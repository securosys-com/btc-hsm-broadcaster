import bech32
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from asn1crypto import core as asn1_core

def hash160_to_bech32_address(hash160_hex: str, network: str = 'testnet') -> str:
    """
    Convert a HASH160 hex string into a Bech32 address.
    """
    hrp = 'tb' if network == 'testnet' else 'bc'  # Human-readable prefix
    hash160_bytes = bytes.fromhex(hash160_hex)
    # Convert to 5-bit words as required by Bech32
    converted = bech32.convertbits(hash160_bytes, 8, 5)
    return bech32.bech32_encode(hrp, [0] + converted)

def get_compressed_pubkey_from_der(der_bytes: bytes) -> bytes:
    """
    Convert a DER-encoded EC public key to compressed SEC format (33 bytes).
    Accepts bytes or hex string.
    """
    if isinstance(der_bytes, str):  # Handle hex string input
        der_bytes = bytes.fromhex(der_bytes)
    
    pubkey_obj = load_der_public_key(der_bytes, backend=default_backend())
    if not isinstance(pubkey_obj, ec.EllipticCurvePublicKey):
        raise ValueError("DER key is not an Elliptic Curve Public Key")
    
    numbers = pubkey_obj.public_numbers()
    x = numbers.x
    y = numbers.y

    # Determine prefix based on parity of y
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    x_bytes = x.to_bytes(32, byteorder='big')
    return prefix + x_bytes

def der_to_raw_signature(der_sig_bytes: bytes) -> bytes:
    """
    Convert a DER-encoded ECDSA signature to a raw 64-byte (r||s) format.
    
    Bitcoin's witness stack for P2WPKH expects (signature + sighash_type),
    where signature is 64 bytes (32 bytes r + 32 bytes s).
    
    This is a simplified ASN.1 parser using asn1crypto. Ensure r and s are padded to 32 bytes.
    """
    # Basic DER parsing for ECDSA signature: SEQUENCE of two INTEGERs r and s
    seq = asn1_core.Sequence.load(der_sig_bytes)
    r = seq[0].native.to_bytes(32, 'big').lstrip(b'\x00')
    s = seq[1].native.to_bytes(32, 'big').lstrip(b'\x00')
    
    # Pad to ensure 32 bytes if needed (e.g., if r or s is < 32 bytes)
    r = b'\x00' * (32 - len(r)) + r
    s = b'\x00' * (32 - len(s)) + s
    return r + s