# streamlit_app.py

import os
import logging
import base64

import streamlit as st

from hsm.securosys_rest_api import (
    fetchKeysFromHsm,
    getOrCreateSecp256k1Key,
    getAddressAndPublicKey,
    sign_with_hsm,
    fetchKeyAttributeFromHsm,
    HsmKeyNotFoundError
)
from blockstream.blockstream_node import get_utxos, fetch_access_token, broadcast_tx
from hsm.helper import (
    get_compressed_pubkey_from_der,
    hash160_to_bech32_address,
    get_segwit_v0_data_for_hsm_sha256,
)
from btclib.tx.tx import Tx, TxIn, TxOut
from btclib.script.witness import Witness
from btclib.script.script_pub_key import ScriptPubKey, type_and_payload
from btclib.tx.tx_in import OutPoint
from btclib.script.script import serialize as serialize_script_asm
from btclib.utils import bytes_from_octets
from btclib.hashes import hash160

# --- Logger Setup ---
logger = logging.getLogger("streamlit_hsm_app")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

# --- Streamlit Config ---
st.set_page_config(page_title="HSM‐Backed BTC Transaction (Testnet)", layout="centered")
st.title("🔐 HSM‐Backed Bitcoin Transaction (Testnet)")

st.markdown(
    """
This app will:
1. Fetch (or create) a secp256k1 key pair from your HSM via REST API.
2. Display the derived testnet address.
3. Allow you to enter a recipient address (P2WPKH/testnet), amount, and fee.
4. Construct, sign (via HSM), and broadcast a SegWit transaction.
"""
)

# --- Sidebar: Configuration Inputs ---
st.sidebar.header("Configuration")

# HSM / KMS environment
TSB_API_URL = st.sidebar.text_input(
    "HSM REST API URL", value=os.getenv("TSB_API_URL", "")
)
TSB_KEY_LABEL = st.sidebar.text_input(
    "HSM Key Label", value=os.getenv("TSB_KEY_LABEL", "")
)
HSM_ACCESS_TOKEN = st.sidebar.text_input(
    "HSM Access Token", value=os.getenv("HSM_ACCESS_TOKEN", ""), type="password"
)

# Node (Blockstream) environment
NODE_API_URL = st.sidebar.text_input(
    "Blockstream Node API URL", value=os.getenv("NODE_API_URL", "")
)
NODE_CLIENT_ID = st.sidebar.text_input(
    "Node Client ID", value=os.getenv("NODE_CLIENT_ID", "")
)
NODE_CLIENT_SECRET = st.sidebar.text_input(
    "Node Client Secret", value=os.getenv("NODE_CLIENT_SECRET", ""), type="password"
)

# Transaction defaults
DEFAULT_AMOUNT = int(os.getenv("AMOUNT_TO_SEND_SATS", "2000"))
DEFAULT_FEE = int(os.getenv("FEE_SATS", "1000"))

st.sidebar.markdown("---")
st.sidebar.markdown("⚠️ **All addresses must be P2WPKH (Bech32) on testnet.**")

# --- Helper Functions ---
#@st.cache_data(show_spinner=False)
def initialize_hsm_key(tsb_api_url: str, key_label: str, access_token: str):
    """
    Fetch existing secp256k1 key or raise HsmKeyNotFoundError.
    If not found, create one. Returns (bech32_address, compressed_pubkey_bytes, pubkey_hash).
    """
    if not tsb_api_url or not key_label:
        st.error("HSM URL and Key Label are required.")
        return None

    # 1) Try to fetch the key’s attributes. If it doesn’t exist, HsmKeyNotFoundError will be raised.
    try:
        _ = fetchKeyAttributeFromHsm(tsb_api_url, key_label, access_token)
        # Key exists—no need to create
    except HsmKeyNotFoundError:
        # Key not found: create it
        try:
            getOrCreateSecp256k1Key(tsb_api_url, key_label, access_token)
            st.info(f"Created new secp256k1 key with label '{key_label}'.")
        except Exception as e:
            st.error(f"Failed to create key '{key_label}': {e}")
            return None
    except Exception as e:
        # Some other error fetching the key
        st.error(f"Failed to fetch key '{key_label}' from HSM: {e}")
        return None

    # 2) Now that the key is guaranteed to exist, retrieve address & raw DER public key
    try:
        addr_hash_hex, der_pubkey_bytes = getAddressAndPublicKey(
            tsb_api_url, key_label
        )
    except Exception as e:
        st.error(f"Failed to get address/public key: {e}")
        return None

    # 3) Convert DER‐encoded public key to compressed form
    try:
        compressed_pubkey = get_compressed_pubkey_from_der(der_pubkey_bytes)
    except Exception as e:
        st.error(f"Error processing DER public key: {e}")
        return None

    # 4) Compute bech32 address from the hash160 of the public key
    try:
        bech32_address = hash160_to_bech32_address(addr_hash_hex)
    except Exception as e:
        st.error(f"Failed to convert hash160 to bech32: {e}")
        return None

    # 5) Compute the hash160 of the compressed public key bytes
    pubkey_hash_bytes = hash160(compressed_pubkey)

    return (bech32_address, compressed_pubkey, pubkey_hash_bytes)


#@st.cache_data(show_spinner=False)
def fetch_utxo_list(node_api_url: str, client_id: str, client_secret: str, address: str):
    """
    Fetch UTXOs for a given address (testnet) from the blockstream node.
    """
    if not node_api_url or not client_id or not client_secret:
        st.error("Node API URL, Client ID, and Client Secret are required.")
        return None

    try:
        access_token = fetch_access_token(client_id, client_secret)
        utxos = get_utxos(node_api_url, access_token, address)
    except Exception as e:
        st.error(f"Failed to fetch UTXOs: {e}")
        return None

    if not utxos:
        st.warning(
            f"No UTXOs found for address {address}. Fund it first! "
            "https://bitcoinfaucet.uo1.net/send.php"
        )
    return utxos


def build_and_sign_transaction(
    utxo: dict,
    recipient_address: str,
    amount_sats: int,
    fee_sats: int,
    sender_pubkey_hash: bytes,
    compressed_pubkey: bytes,
    key_label: str,
    tsb_api_url: str,
    hsm_access_token: str,
):
    """
    Constructs a SegWit v0 P2WPKH transaction, signs via HSM, and returns (tx_hex, txid, vsize).
    """
    # 1. Validate recipient address
    try:
        r_spk = ScriptPubKey.from_address(recipient_address)
        r_type, r_prog = type_and_payload(r_spk.script)
        if r_type != "p2wpkh" or r_spk.network != "testnet":
            st.error("Recipient address must be P2WPKH (Bech32) on testnet.")
            return None
    except Exception as e:
        st.error(f"Invalid recipient address: {e}")
        return None

    # 2. Build scriptPubKeys
    sender_spk_bytes = serialize_script_asm(["OP_0", sender_pubkey_hash])
    recipient_spk_bytes = serialize_script_asm(["OP_0", r_prog])
    script_code_bytes = serialize_script_asm(
        ["OP_DUP", "OP_HASH160", sender_pubkey_hash, "OP_EQUALVERIFY", "OP_CHECKSIG"]
    )

    # 3. Construct TxIn/TxOut
    outpoint = OutPoint(tx_id=bytes_from_octets(utxo["txid"], 32), vout=utxo["vout"])
    txin = TxIn(prev_out=outpoint, script_sig=b"", sequence=0xFFFFFFFF)
    tx_outs = [TxOut(value=amount_sats, script_pub_key=recipient_spk_bytes)]

    change = utxo["value"] - amount_sats - fee_sats
    if change < 0:
        st.error("🚫 Insufficient funds for the requested amount + fee.")
        return None
    # Add a change output if above dust (546 sats)
    if change > 546:
        tx_outs.append(TxOut(value=change, script_pub_key=sender_spk_bytes))

    tx = Tx(version=2, lock_time=0, vin=[txin], vout=tx_outs)

    # 4. Create sighash payload for HSM
    try:
        tx_raw_payload = get_segwit_v0_data_for_hsm_sha256(
            script_code_bytes, tx, 0, 0x01, utxo["value"]
        )
    except Exception as e:
        st.error(f"Failed to prepare SegWit sighash: {e}")
        return None

    # 5. Ask HSM to sign
    try:
        hsm_signature, signature_b64, tsb_sign_payload = sign_with_hsm(
            tsb_api_url, tx_raw_payload, key_label, hsm_access_token
        )
    except Exception as e:
        st.error(f"HSM signing failed: {e}")
        return None

    # 6. Build witness and finalize
    witness = Witness([hsm_signature + b"\x01", compressed_pubkey])
    tx.vin[0].script_witness = witness

    try:
        tx_hex = tx.serialize(include_witness=True).hex()
    except Exception as e:
        st.error(f"Failed to serialize transaction: {e}")
        return None

    # 7. Broadcast
    try:
        access_token = fetch_access_token(NODE_CLIENT_ID, NODE_CLIENT_SECRET)
        txid = broadcast_tx(NODE_API_URL, access_token, tx_hex)
    except Exception as e:
        st.error(f"Broadcast failed: {e}")
        return None

    return tx_hex, txid, tx.vsize, tsb_sign_payload, signature_b64


# --- Callbacks for Session State Updates ---

def load_hsm_key():
    """Callback to (re-)initialize the HSM key and store results in session_state."""
    res = initialize_hsm_key(TSB_API_URL, TSB_KEY_LABEL, HSM_ACCESS_TOKEN)
    st.session_state["hsm_init"] = res


def load_utxos():
    """Callback to (re-)fetch UTXOs and store in session_state."""
    if "hsm_init" not in st.session_state or st.session_state["hsm_init"] is None:
        st.session_state["utxos"] = None
        return

    sender_address = st.session_state["hsm_init"][0]
    utxos = fetch_utxo_list(
        NODE_API_URL,
        NODE_CLIENT_ID,
        NODE_CLIENT_SECRET,
        sender_address,
    )
    st.session_state["utxos"] = utxos


def prepare_transaction():
    """Callback to build, sign, and broadcast the selected transaction."""
    utxos = st.session_state.get("utxos")
    if not utxos:
        st.session_state["tx_result"] = None
        return

    idx = st.session_state.get("selected_utxo_idx")
    if idx is None or idx < 0 or idx >= len(utxos):
        st.session_state["tx_result"] = None
        return

    selected_utxo = utxos[idx]
    rec_addr = st.session_state.get("recipient_address", "").strip()
    amt = int(st.session_state.get("amount_to_send", DEFAULT_AMOUNT))
    fee = int(st.session_state.get("fee_to_use", DEFAULT_FEE))

    # Extract pubkey hash + compressed pubkey from the HSM‐init tuple
    _, compressed_pubkey, sender_pubkey_hash = st.session_state["hsm_init"]

    result = build_and_sign_transaction(
        utxo=selected_utxo,
        recipient_address=rec_addr,
        amount_sats=amt,
        fee_sats=fee,
        sender_pubkey_hash=sender_pubkey_hash,
        compressed_pubkey=compressed_pubkey,
        key_label=TSB_KEY_LABEL,
        tsb_api_url=TSB_API_URL,
        hsm_access_token=HSM_ACCESS_TOKEN,
    )

    st.session_state["tx_result"] = result


# --- Main App Logic ---

# 1) On first load, run HSM initialization if not already in session_state
if "hsm_init" not in st.session_state:
    load_hsm_key()

# Step 0: “Reload All” button at top
if st.button("🔄 Reload All"):
    # Clear all relevant session_state keys
    for key in ["hsm_init", "utxos", "tx_result", "selected_utxo_idx"]:
        if key in st.session_state:
            del st.session_state[key]
    # Re-run each step
    load_hsm_key()
    load_utxos()
    # We do not call prepare_transaction() until user clicks the build button

st.markdown("---")

# Step 1: Initialize HSM Key
with st.expander("Step 1: Initialize HSM Key", expanded=True):
    if st.button("↻ Reload HSM Key"):
        load_hsm_key()

    init_res = st.session_state.get("hsm_init")
    if init_res is None:
        st.error("⚠️ Failed to initialize HSM key. (Check logs/errors above.)")
        st.stop()

    sender_address, compressed_pubkey, sender_pubkey_hash = init_res
    st.success(f"✅ Loaded HSM key. Derived Testnet Address: **{sender_address}**")

st.markdown("---")

# Step 2: Fetch UTXOs
with st.expander("Step 2: Fetch UTXOs", expanded=True):
    if st.button("↻ Reload UTXOs"):
        load_utxos()

    init_res = st.session_state.get("hsm_init")
    if init_res is None:
        st.warning("🔒 Cannot fetch UTXOs until HSM key is initialized.")
        st.stop()

    sender_address = init_res[0]
    st.write(f"Fetching UTXOs for address: `{sender_address}`")

    utxos = st.session_state.get("utxos")
    if utxos is None:
        # On first opening, automatically fetch UTXOs once
        load_utxos()
        utxos = st.session_state.get("utxos")

    if utxos:
        st.write("### Available UTXOs")
        utxo_rows = []
        for i, u in enumerate(utxos):
            utxo_rows.append(
                {
                    "Index": i,
                    "TxID": u["txid"],
                    "vout": u["vout"],
                    "Value (sats)": u["value"],
                }
            )
        st.table(utxo_rows)
    else:
        st.info("No UTXOs to display.")

st.markdown("---")

# Step 3: Build & Broadcast Transaction
with st.expander("Step 3: Build & Broadcast Transaction", expanded=True):
    utxos = st.session_state.get("utxos")
    if utxos:
        # Initialize selected_utxo_idx if missing
        st.session_state.setdefault("selected_utxo_idx", 0)
        utxo_index = st.selectbox(
            "Select UTXO to spend",
            options=list(range(len(utxos))),
            index=st.session_state["selected_utxo_idx"],
            format_func=lambda x: f"#{x} → {utxos[x]['value']} sats",
            key="selected_utxo_idx",
        )
        selected_utxo = utxos[utxo_index]
    else:
        selected_utxo = None
        st.warning("🔒 No UTXO available to spend.")

    st.text_input(
        "Recipient Address (Bech32 P2WPKH, testnet)",
        value=os.getenv("TO_ADDRESS_NEW", ""),
        key="recipient_address",
    )
    st.number_input(
        "Amount to send (sats)",
        min_value=1,
        value=DEFAULT_AMOUNT,
        step=100,
        key="amount_to_send",
    )
    st.number_input(
        "Transaction Fee (sats)", min_value=1, value=DEFAULT_FEE, step=100, key="fee_to_use"
    )

    if selected_utxo:
        if st.button("▶️ Build, Sign & Broadcast"):
            with st.spinner("Constructing, signing, and broadcasting transaction..."):
                prepare_transaction()

        tx_res = st.session_state.get("tx_result")
        if tx_res is not None:
            tx_hex, txid, vsize, tsb_sign_payload, hsm_signature = tx_res
            st.success("✅ Transaction successfully broadcasted!")
            st.write(f"• **Transaction ID (txid):** `{txid}`")
            st.write(f"Check Signed Transaction here: https://mempool.space/testnet/tx/{txid}")
            st.write(f"• **Virtual Size:** `{vsize}` vbytes")
            st.write("• **Raw Transaction (hex):**")
            st.code(tx_hex, language="text")
            st.write("TSB Signing Payload: /v1/synchronousSign")
            st.json(tsb_sign_payload)
            st.write("HSM Signature Result (DER - Base64):")
            st.code(hsm_signature, language="text")
            st.write("Compressed Public-Key Bytes:")
            st.code(base64.b64encode(compressed_pubkey).decode("utf-8"), language="text")
        elif "tx_result" in st.session_state and st.session_state["tx_result"] is None:
            st.error("❌ Transaction failed; see errors above.")
    else:
        st.info("No UTXO selected—cannot build a transaction.")
