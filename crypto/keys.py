import base64
import hashlib
import os
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)

DEFAULT_KEYS_DIR = "keys"


@dataclass
class Identity:
    private_key: x25519.X25519PrivateKey
    public_key: x25519.X25519PublicKey
    fingerprint: str
    display_name: Optional[str] = None


def _ensure_keys_dir(keys_dir: str = DEFAULT_KEYS_DIR) -> None:
    os.makedirs(keys_dir, exist_ok=True)


def _private_key_path(keys_dir: str) -> str:
    return os.path.join(keys_dir, "id_private.pem")


def _public_key_path(keys_dir: str) -> str:
    return os.path.join(keys_dir, "id_public.pem")


def _fingerprint(public_key: x25519.X25519PublicKey) -> str:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def public_key_to_b64(public_key: x25519.X25519PublicKey) -> str:
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def public_key_from_b64(value: str) -> x25519.X25519PublicKey:
    raw = base64.b64decode(value.encode("ascii"))
    return x25519.X25519PublicKey.from_public_bytes(raw)


def save_identity(identity: Identity, keys_dir: str = DEFAULT_KEYS_DIR) -> None:
    _ensure_keys_dir(keys_dir)
    priv_path = _private_key_path(keys_dir)
    pub_path = _public_key_path(keys_dir)
    with open(priv_path, "wb") as f:
        f.write(
            identity.private_key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
        )
    with open(pub_path, "wb") as f:
        f.write(
            identity.public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        )


def load_identity(display_name: Optional[str] = None, keys_dir: str = DEFAULT_KEYS_DIR) -> Identity:
    _ensure_keys_dir(keys_dir)
    priv_path = _private_key_path(keys_dir)
    pub_path = _public_key_path(keys_dir)
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path, "rb") as f:
            priv = load_pem_private_key(f.read(), password=None)
        with open(pub_path, "rb") as f:
            pub = load_pem_public_key(f.read())
        return Identity(priv, pub, _fingerprint(pub), display_name=display_name)

    identity = generate_identity(display_name=display_name, keys_dir=keys_dir)
    return identity


def generate_identity(display_name: Optional[str] = None, keys_dir: str = DEFAULT_KEYS_DIR) -> Identity:
    _ensure_keys_dir(keys_dir)
    priv = x25519.X25519PrivateKey.generate()
    pub = priv.public_key()
    identity = Identity(priv, pub, _fingerprint(pub), display_name=display_name)
    save_identity(identity, keys_dir=keys_dir)
    return identity
