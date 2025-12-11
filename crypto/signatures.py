from cryptography.hazmat.primitives.asymmetric import ed25519


def sign_message(message: bytes, private_key: ed25519.Ed25519PrivateKey) -> bytes:
    return private_key.sign(message)


def verify_message(message: bytes, signature: bytes, public_key: ed25519.Ed25519PublicKey) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except Exception:
        return False
