import os
import base64
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


def sign_with_hsm(tsb_api_url: str, data_to_sign_bytes: bytes, key_label: str, access_token: str = ''):
    """
    Signs the given data using a key stored in the Securosys HSM.

    Args:
        tsb_api_url: The base URL of the TSB API.
        data_to_sign_bytes: The raw bytes of the data to be signed.
        key_label: The label/name of the key in the HSM to use for signing.
        access_token: Optional bearer token for authentication.

    Returns:
        bytes: The DER-encoded signature as raw bytes.

    Raises:
        requests.exceptions.HTTPError: If the API request fails.
        requests.exceptions.RequestException: For other network/request issues.
        KeyError: If the response JSON is not as expected.
    """
    endpoint = tsb_api_url.rstrip('/') + "/synchronousSign"
    headers = {"Content-Type": "application/json"}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"        

    payload_b64 = base64.b64encode(data_to_sign_bytes).decode("utf-8")
    logger.info("sign payload: " + payload_b64)
    # "signatureAlgorithm": "NONE_WITH_ECDSA", # Assuming ECDSA, adjust if key type varies
    payload = {
        "signRequest": {
            "payload": payload_b64,
            "payloadType": "UNSPECIFIED",  # Or HASH if data_to_sign_bytes is already a hash
            "signKeyName": key_label,
            "signatureAlgorithm": "DOUBLE_SHA256_WITH_ECDSA", # Assuming ECDSA, adjust if key type varies      
            "signatureType": "DER"
        }
    }

    logger.info(f"Sending signing request to HSM for key '{key_label}'. Endpoint: {endpoint}")
    logger.debug(f"HSM Sign Payload (first 80 chars of b64 data): {payload_b64[:80]}...")
    logger.debug(f"HSM Sign Full Request Payload: {payload}")


    try:
        resp = requests.post(endpoint, headers=headers, json=payload, timeout=30) # Added timeout
        logger.info(f"HSM Sign Response Status for key '{key_label}': {resp.status_code}")

        if resp.status_code >= 300:
            error_message = f"HSM signing error for key '{key_label}'. Status: {resp.status_code}. Response: {resp.text}"
            logger.error(error_message)
            resp.raise_for_status() # This will raise an HTTPError

        response_json = resp.json()
        signature_b64 = response_json["signature"]
        logger.info(f"Successfully received signature from HSM for key '{key_label}'.")
        logger.info(f"HSM Signature (Base64): {signature_b64[:80]}...")

        return base64.b64decode(signature_b64)

    except requests.exceptions.Timeout:
        logger.error(f"HSM signing request timed out for key '{key_label}' at {endpoint}.")
        raise
    except requests.exceptions.RequestException as e:
        logger.error(f"HSM signing request failed for key '{key_label}' at {endpoint}. Error: {e}")
        raise
    except KeyError:
        logger.error(f"HSM signing response JSON for key '{key_label}' did not contain 'signature' key. Response: {response_json}")
        raise


def getAddressAndPublicKey(tsb_api_url: str, key_label: str, access_token: str = ''):
    """
    Retrieves the public key (Base64 DER) and a truncated address hash from the HSM.

    Args:
        tsb_api_url: The base URL of the TSB API.
        key_label: The label/name of the key in the HSM.
        access_token: Optional bearer token for authentication if required by the endpoint.

    Returns:
        tuple: (address_160_hash_hex, der_public_key_base64_string)
               - address_160_hash_hex (str): Hex string of the (truncated) address.
               - der_public_key_base64_string (str): DER-encoded public key as a Base64 string.

    Raises:
        requests.exceptions.HTTPError: If the API request fails.
        requests.exceptions.RequestException: For other network/request issues.
        KeyError: If the response JSON is not as expected.
    """
    endpoint = tsb_api_url.rstrip('/') + "/key/attributes"
    headers = {"Content-Type": "application/json"}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"            

    payload = {
        "label": key_label
    }

    logger.info(f"Requesting key attributes from HSM for key '{key_label}'. Endpoint: {endpoint}")
    logger.debug(f"HSM GetKeyAttributes Payload: {payload}")

    try:
        resp = requests.post(endpoint, headers=headers, json=payload, timeout=15) # Added timeout
        logger.info(f"HSM GetKeyAttributes Response Status for key '{key_label}': {resp.status_code}")

        if resp.status_code >= 300:
            error_message = f"HSM GetKeyAttributes error for key '{key_label}'. Status: {resp.status_code}. Response: {resp.text}"
            logger.error(error_message)
            resp.raise_for_status()

        response_json = resp.json()
        key_attributes = response_json.get("json", {})

        public_key_b64_der = key_attributes.get("publicKey")
        logger.info(f"DER encoded public-key (base64 from HSM): {public_key_b64_der}")
        public_key_der = base64.b64decode(public_key_b64_der)
        
        address_truncated_value = key_attributes.get("addressTruncated")
        if isinstance(address_truncated_value, dict):
            address_160_hash_hex = address_truncated_value.get("address")
            if not address_160_hash_hex:
                logger.warning(
                    f"HSM GetKeyAttributes: 'json.addressTruncated' is a dictionary "
                    f"but does not contain an 'address' field for key '{key_label}'. "
                    f"addressTruncated content: {address_truncated_value}"
                )
        elif address_truncated_value is None:            
            logger.info(
                f"HSM GetKeyAttributes: 'json.addressTruncated' field is null, the key is not an SKA-Key (Key with Policy) for key '{key_label}'. "
                "Calculate the Address hash by yourself, using the public-key."
            )       

        logger.info(f"Successfully retrieved attributes for key '{key_label}'.")
        logger.debug(f"HSM Public Key (Base64 DER for key '{key_label}', first 80 chars): {public_key_der[:80]}...")
        logger.debug(f"HSM Address Hash (Hex for key '{key_label}'): {address_160_hash_hex}")

        # IMPORTANT: Returning the Base64 encoded string for the public key,
        # as expected by the calling script's variable HSM_DER_PUBKEY_B64.
        return address_160_hash_hex, public_key_der

    except requests.exceptions.Timeout:
        logger.error(f"HSM GetKeyAttributes request timed out for key '{key_label}' at {endpoint}.")
        raise
    except requests.exceptions.RequestException as e:
        logger.error(f"HSM GetKeyAttributes request failed for key '{key_label}' at {endpoint}. Error: {e}")
        raise
    except KeyError as e: # Catch KeyErrors from parsing JSON
        logger.error(f"HSM GetKeyAttributes response JSON for key '{key_label}' was missing an expected key: {e}. Response: {response_json}")
        raise
    except Exception as e: # Catch-all for other unexpected errors during processing
        logger.error(f"An unexpected error occurred while getting attributes for key '{key_label}': {e}")
        raise

def fetchKeysFromHsm(tsb_api_url: str, access_token: str = '') -> dict:
    endpoint = tsb_api_url.rstrip('/') + "/key"
    headers = {"Content-Type": "application/json"}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"

    try:
        resp = requests.get(endpoint, headers=headers, timeout=30)
        response_json = resp.json()
        return response_json
    
    except requests.exceptions.Timeout:
        logger.error(f"Request to list keys at {endpoint} timed out.")
        raise

    except requests.exceptions.RequestException as e:
        logger.error(f"HTTP error during HSM key listing: {e}")
        raise

def getOrCreateSecp256k1Key(tsb_api_url: str, key_label: str, access_token: str = '') -> dict:
    """
    Create or retrieve a secp256k1 key from the HSM.

    Parameters:
    - tsb_api_url: Base URL of the TSB HSM API
    - key_label: Unique label for the key to create or fetch
    - access_token: Optional Bearer token for authentication

    Returns:
    - Dictionary of key attributes from the HSM response
    """
    endpoint = tsb_api_url.rstrip('/') + "/key"
    headers = {"Content-Type": "application/json"}
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"

    payload = {
        "label": key_label,
        "algorithm": "EC",
        "curveOid": "1.3.132.0.10",  # OID for secp256k1
        "addressFormat": {
            "format": "BTC"          # OID for BTC-Address-Generation
        },
        "attributes": {
            "decrypt": False,
            "sign": True,
            "unwrap": False,
            "destroyable": True,     # Use False if in production
            "modifiable": True,
            "derive": True,
            "bip32": True
        },
        "policy": {
            "ruleUse": None,
            "ruleBlock": None,
            "ruleUnblock": None,
            "ruleModify": None,
            "keyStatus": {
                "blocked": False
            }
        }
    }

    try:
        resp = requests.post(endpoint, headers=headers, json=payload, timeout=30)
        logger.info(f"HSM key creation/fetch response for '{key_label}': {resp.status_code}")
        
        if resp.status_code >= 300:
            return getAddressAndPublicKey(tsb_api_url, key_label, access_token)

        return getAddressAndPublicKey(tsb_api_url, key_label, access_token)

    except requests.exceptions.Timeout:
        logger.error(f"Request to create/fetch key '{key_label}' at {endpoint} timed out.")
        raise

    except requests.exceptions.RequestException as e:
        logger.error(f"HTTP error during HSM key creation for '{key_label}': {e}")
        raise


# --- Example Usage (for testing this module directly) ---
if __name__ == "__main__":
    # To see DEBUG logs, uncomment the line below or set it in your application
    # logger.setLevel(logging.DEBUG)

    # --- Configuration for direct testing ---
    # You MUST set these environment variables or hardcode values for testing
    HSM_TSB_API_URL_TEST = os.getenv("TSB_API_URL_TEST", "YOUR_HSM_API_URL_HERE")
    HSM_KEY_LABEL_TEST = os.getenv("TSB_KEY_LABEL_TEST", "YOUR_HSM_KEY_LABEL_HERE")
    HSM_ACCESS_TOKEN_TEST = os.getenv("HSM_ACCESS_TOKEN_TEST", "") # Optional, depends on HSM config

    print("--- Testing securosys_rest_api.py ---")

    if "YOUR_HSM_API_URL_HERE" in HSM_TSB_API_URL_TEST or "YOUR_HSM_KEY_LABEL_HERE" in HSM_KEY_LABEL_TEST:
        logger.warning("Skipping direct test calls as HSM_TSB_API_URL_TEST or HSM_KEY_LABEL_TEST are not properly set.")
    else:
        logger.info(f"Using HSM API URL: {HSM_TSB_API_URL_TEST}")
        logger.info(f"Using HSM Key Label: {HSM_KEY_LABEL_TEST}")
        if HSM_ACCESS_TOKEN_TEST:
            logger.info("Using HSM Access Token.")
        else:
            logger.info("No HSM Access Token provided for testing.")

        try:
            logger.info("\n--- Testing getAddressAndPublicKey ---")
            addr_hash, pubkey_b64 = getAddressAndPublicKey(
                HSM_TSB_API_URL_TEST,
                HSM_KEY_LABEL_TEST,
                HSM_ACCESS_TOKEN_TEST
            )
            logger.info(f"getAddressAndPublicKey Result: Address Hash = {addr_hash}, PubKey (b64 DER) = {pubkey_b64[:60]}...")

            logger.info("\n--- Testing sign_with_hsm ---")
            # Create some dummy data to sign (e.g., a 32-byte hash)
            dummy_data_to_sign = os.urandom(32)
            logger.info(f"Dummy data to sign (hex): {dummy_data_to_sign.hex()}")

            signature = sign_with_hsm(
                HSM_TSB_API_URL_TEST,
                dummy_data_to_sign,
                HSM_KEY_LABEL_TEST,
                HSM_ACCESS_TOKEN_TEST
            )
            logger.info(f"sign_with_hsm Result: Signature (hex) = {signature.hex()}")
            logger.info(f"Signature length: {len(signature)} bytes")

        except requests.exceptions.HTTPError as http_err:
            logger.error(f"HTTP error during testing: {http_err} - Response: {http_err.response.text if http_err.response else 'No response object'}")
        except requests.exceptions.RequestException as req_err:
            logger.error(f"Request error during testing: {req_err}")
        except KeyError as key_err:
            logger.error(f"Key error during testing (likely unexpected API response structure): {key_err}")
        except Exception as e:
            logger.error(f"An unexpected error occurred during testing: {e}", exc_info=True)

    print("\n--- securosys_rest_api.py testing finished ---")