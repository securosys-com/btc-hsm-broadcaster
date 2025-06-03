import bech32
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from asn1crypto import core as asn1_core
from btclib.hashes import hash256, sha256 # Ensure sha256 is imported
from btclib.utils import bytes_from_octets
from btclib.alias import Octets
from btclib.tx import Tx
from btclib import var_bytes



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

DEFAULT = 0
ALL = 1
NONE = 2
SINGLE = 3
ANYONECANPAY = 0b10000000

def get_segwit_v0_data_for_hsm_sha256(
    script_code: Octets,
    tx: Tx,
    vin_i: int,
    hash_type: int,
    amount: int,
) -> bytes:
    script_code = bytes_from_octets(script_code)

    hash_prev_outs = b"\x00" * 32
    if not hash_type & ANYONECANPAY:
        hash_prev_outs = b"".join(
            [vin.prev_out.serialize(check_validity=False) for vin in tx.vin]
        )
        hash_prev_outs = hash256(hash_prev_outs) # Still hash256 for intermediate

    hash_seqs = b"\x00" * 32
    if (
        not (hash_type & ANYONECANPAY)
        and (hash_type & 0x1F) != SINGLE
        and (hash_type & 0x1F) != NONE
    ):
        hash_seqs = b"".join(
            [
                vin.sequence.to_bytes(4, byteorder="little", signed=False)
                for vin in tx.vin
            ]
        )
        hash_seqs = hash256(hash_seqs) # Still hash256 for intermediate

    hash_outputs = b"\x00" * 32
    if hash_type & 0x1F not in (SINGLE, NONE):
        hash_outputs = b"".join(
            [vout.serialize(check_validity=False) for vout in tx.vout]
        )
        hash_outputs = hash256(hash_outputs) # Still hash256 for intermediate
    elif (hash_type & 0x1F) == SINGLE and vin_i < len(tx.vout):
        hash_outputs = hash256(tx.vout[vin_i].serialize(check_validity=False)) # Still hash256

    preimage = b"".join(
        [
            tx.version.to_bytes(4, byteorder="little", signed=False),
            hash_prev_outs,
            hash_seqs,
            tx.vin[vin_i].prev_out.serialize(check_validity=False),
            var_bytes.serialize(script_code),
            amount.to_bytes(8, byteorder="little", signed=False),  # value
            tx.vin[vin_i].sequence.to_bytes(4, byteorder="little", signed=False),
            hash_outputs,
            tx.lock_time.to_bytes(4, byteorder="little", signed=False),
            hash_type.to_bytes(4, byteorder="little", signed=False),
        ]
    )
    
    # THIS IS THE KEY CHANGE:
    # Instead of hash256(preimage), we return sha256(preimage)
    # The HSM will perform the second SHA256
    return preimage