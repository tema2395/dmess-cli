import os
from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519


def derive_shared_key(
    private_key: x25519.X25519PrivateKey, peer_public_key: x25519.X25519PublicKey
) -> bytes:
    shared = private_key.exchange(peer_public_key)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"dmess-local-chat",
    )
    return hkdf.derive(shared)


def encrypt_message(plaintext: str, key: bytes) -> Tuple[bytes, bytes]:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce, ciphertext


def decrypt_message(nonce: bytes, ciphertext: bytes, key: bytes) -> str:
    aes = AESGCM(key)
    plaintext = aes.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")
