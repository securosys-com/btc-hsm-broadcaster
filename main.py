import os
import logging

from hsm.securosys_rest_api import fetchKeysFromHsm, getOrCreateSecp256k1Key, getAddressAndPublicKey, sign_with_hsm
from blockstream.blockstream_node import get_utxos, fetch_access_token, broadcast_tx
from hsm.helper import get_compressed_pubkey_from_der, hash160_to_bech32_address, get_segwit_v0_data_for_hsm_sha256

from btclib.tx.tx import Tx, TxIn, TxOut
from btclib.script.witness import Witness
from btclib.script.script_pub_key import ScriptPubKey, type_and_payload
from btclib.tx.tx_in import OutPoint
from btclib.script.script import serialize as serialize_script_asm
from btclib.utils import bytes_from_octets
from btclib.network import NETWORKS
from btclib.hashes import hash160
from btclib.script.sig_hash import segwit_v0 as calculate_segwit_v0_sighash

# --- Logger Setup ---
logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

logger.setLevel(logging.INFO)

# --- Configuration ---
NETWORKS["testnet"]  # Required for btclib's testnet address parsing
HSM_TSB_API_URL = os.getenv("TSB_API_URL")
HSM_KEY_LABEL = os.getenv("TSB_KEY_LABEL")
TSB_ACCESS_TOKEN = os.getenv("TSB_ACCESS_TOKEN", "")
RECIPIENT_ADDRESS_STR = os.getenv("TO_ADDRESS_NEW")
NODE_API_URL = os.getenv("NODE_API_URL")
NODE_CLIENT_ID = os.getenv("NODE_CLIENT_ID")
NODE_CLIENT_SECRET = os.getenv("NODE_CLIENT_SECRET")

AMOUNT_TO_SEND_SATS = 2000
FEE_SATS = 1000

# --- HSM Public Key & Address ---
keys = fetchKeysFromHsm(HSM_TSB_API_URL)
if HSM_KEY_LABEL not in keys:
    key_attributes = getOrCreateSecp256k1Key(HSM_TSB_API_URL, HSM_KEY_LABEL)

addr_hash_hex, der_pubkey_bytes = getAddressAndPublicKey(HSM_TSB_API_URL, HSM_KEY_LABEL)
bech32_address = hash160_to_bech32_address(addr_hash_hex)

try:
    compressed_pubkey = get_compressed_pubkey_from_der(der_pubkey_bytes)
except Exception as e:
    logger.error(f"Error processing DER public key: {e}")
    exit()

pubkey_hash = hash160(compressed_pubkey)
logger.info(f"Compressed PubKey: {compressed_pubkey.hex()}")
logger.info(f"Sender Address: {bech32_address}")

# --- Sender Address Verification ---
try:
    sender_spk = ScriptPubKey.from_address(bech32_address)
    stype, sprog = type_and_payload(sender_spk.script)
    if stype != "p2wpkh" or sender_spk.network != "testnet" or sprog != pubkey_hash:
        raise ValueError("Mismatch or invalid sender address configuration.")
    logger.info(f"Sender address {bech32_address} successfully verified.")
except Exception as e:
    logger.error(f"Sender address verification failed: {e}")
    exit()

# --- Recipient Address ---
try:
    recipient_spk = ScriptPubKey.from_address(RECIPIENT_ADDRESS_STR)
    rtype, rprog = type_and_payload(recipient_spk.script)
    if rtype != "p2wpkh" or recipient_spk.network != "testnet":
        raise ValueError("Recipient address is not valid P2WPKH on testnet.")
    logger.info(f"Recipient pubkey hash: {rprog.hex()}")
except Exception as e:
    logger.error(f"Error decoding recipient address: {e}")
    exit()

# --- ScriptPubKey Setup ---
sender_spk_bytes = serialize_script_asm(["OP_0", pubkey_hash])
recipient_spk_bytes = serialize_script_asm(["OP_0", rprog])
script_code_bytes = serialize_script_asm(
    ["OP_DUP", "OP_HASH160", pubkey_hash, "OP_EQUALVERIFY", "OP_CHECKSIG"]
)

# --- Fetch UTXO ---
access_token = fetch_access_token(NODE_CLIENT_ID, NODE_CLIENT_SECRET)
utxos = get_utxos(NODE_API_URL, access_token, bech32_address)
if not utxos:
    logger.error(f"No UTXOs for address, fund your account first: {bech32_address}")
    exit()

utxo = utxos[0]
logger.info(f"Selected UTXO: {utxo}")

# --- Transaction Construction ---
outpoint = OutPoint(tx_id=bytes_from_octets(utxo['txid'], 32), vout=utxo['vout'])
tx_in = TxIn(prev_out=outpoint, script_sig=b"", sequence=0xFFFFFFFF)
tx_outs = [TxOut(value=AMOUNT_TO_SEND_SATS, script_pub_key=recipient_spk_bytes)]

change = utxo["value"] - AMOUNT_TO_SEND_SATS - FEE_SATS
if change < 0:
    logger.error("Insufficient funds.")
    exit()
if change > 546:
    tx_outs.append(TxOut(value=change, script_pub_key=sender_spk_bytes))

tx = Tx(version=2, lock_time=0, vin=[tx_in], vout=tx_outs)

# --- Signature (HSM Hash) ---

tx_raw_payload = get_segwit_v0_data_for_hsm_sha256(script_code_bytes, tx, 0, 0x01, utxo["value"])
try:
    presigned_sig = sign_with_hsm(HSM_TSB_API_URL, tx_raw_payload, HSM_KEY_LABEL, TSB_ACCESS_TOKEN)            
except Exception as e:
    logger.error(f"HSM signing failed: {e}")
    exit()

# --- Witness Assignment ---
witness = Witness([presigned_sig + b"\x01", compressed_pubkey])
tx.vin[0].script_witness = witness

# --- Finalize ---
tx_hex = tx.serialize(include_witness=True).hex()
logger.info(f"Signed Transaction Hex:{tx_hex[:80]}...")
logger.info(f"Full Signed Transaction Hex: {tx_hex}")


fee_paid = utxo["value"] - sum(o.value for o in tx.vout)
logger.info(f"vSize: {tx.vsize} bytes")
logger.info(f"Fee: {fee_paid} sats ({fee_paid / tx.vsize:.2f} sat/vbyte)")

# Uncomment to broadcast the signed transaction
txid = broadcast_tx(NODE_API_URL, access_token, tx_hex)
