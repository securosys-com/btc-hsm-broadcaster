import os
import requests
import logging

# --- Logger Setup ---
logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)

logger.setLevel(logging.INFO)

# --- Environment ---
NODE_AUTH_URL = os.getenv("NODE_AUTH_URL")


def fetch_access_token(client_id: str, client_secret: str) -> str:
    """
    Fetch access token using client credentials flow.
    """
    payload = {
        'client_id': client_id,
        'client_secret': client_secret,
        'grant_type': 'client_credentials',
        'scope': 'openid'
    }
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    try:
        response = requests.post(NODE_AUTH_URL, data=payload, headers=headers)
        response.raise_for_status()
        token = response.json().get('access_token')
        if not token:
            raise ValueError("No access_token in response")
        logger.info("Access token fetched successfully.")
        return token
    except Exception as e:
        logger.error(f"Failed to fetch access token: {e}")
        raise


def check_balance(node_api_url: str, access_token: str, address: str) -> int:
    """
    Check confirmed balance of a Bitcoin address.
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"{node_api_url}/address/{address}"

    response = requests.get(url, headers=headers)
    response.raise_for_status()
    data = response.json()
    
    funded = data["chain_stats"]["funded_txo_sum"]
    spent = data["chain_stats"]["spent_txo_sum"]
    balance = funded - spent

    logger.info(f"Balance for address {address}: {balance} sats")
    return balance


def get_utxos(node_api_url: str, access_token: str, address: str) -> list:
    """
    Retrieve UTXOs for a given address.
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    url = f"{node_api_url}/address/{address}/utxo"

    response = requests.get(url, headers=headers)
    response.raise_for_status()
    utxos = response.json()

    logger.info(f"Fetched {len(utxos)} UTXO(s) for address {address}")
    return utxos


def broadcast_tx(node_api_url: str, access_token: str, signed_tx_hex: str) -> str:
    """
    Broadcast a signed transaction hex to the network.
    """
    headers = {
        "Authorization": f"Bearer {access_token}",
        'Content-Type': 'text/plain'
    }
    url = f"{node_api_url}/tx"

    response = requests.post(url, headers=headers, data=signed_tx_hex)
    response.raise_for_status()
    txid = response.text.strip()

    logger.info(f"Transaction broadcasted. TXID: {txid}")
    return txid
