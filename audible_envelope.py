"""Stage an approved audible bundle without putting plaintext in a public repository."""

import argparse
import base64
from hashlib import sha256
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


DOMAIN = b"taqdeersa/approved-content-queue-2026-11:audible:bundle:v1"
HEADER = b"SNAUD1"
MAX_BUNDLE_BYTES = 48 * 1024 * 1024
OVERHEAD = len(HEADER) + 32 + 12 + 16


def derive_key(material, purpose):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=DOMAIN + purpose).derive(material)


def runner_receiver(seal_secret):
    key = base64.b64decode(seal_secret, validate=True)
    if len(key) != 32:
        raise ValueError("bad seal key size")
    return X25519PrivateKey.from_private_bytes(derive_key(key, b":receiver"))


def public_bytes(private):
    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def seal(plaintext, receiver_public):
    if not 0 < len(plaintext) <= MAX_BUNDLE_BYTES:
        raise ValueError("bundle size invalid")
    sender = X25519PrivateKey.generate()
    sender_public = public_bytes(sender)
    receiver = X25519PublicKey.from_public_bytes(receiver_public)
    key = derive_key(sender.exchange(receiver), b":payload:" + sender_public + receiver_public)
    nonce = os.urandom(12)
    return HEADER + sender_public + nonce + AESGCM(key).encrypt(nonce, plaintext, DOMAIN)


def open_in_runner(envelope, receiver):
    if (not OVERHEAD < len(envelope) <= MAX_BUNDLE_BYTES + OVERHEAD
            or not envelope.startswith(HEADER)):
        raise ValueError("sealed bundle size or format invalid")
    start = len(HEADER)
    sender_public = envelope[start:start + 32]
    nonce = envelope[start + 32:start + 44]
    sender = X25519PublicKey.from_public_bytes(sender_public)
    key = derive_key(receiver.exchange(sender), b":payload:" + sender_public + public_bytes(receiver))
    return AESGCM(key).decrypt(nonce, envelope[start + 44:], DOMAIN)


def main():
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("receiver-public")
    pack = subcommands.add_parser("seal")
    pack.add_argument("--public-key", type=Path, required=True)
    pack.add_argument("--bundle", type=Path, required=True)
    pack.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "receiver-public":
        receiver = runner_receiver(os.environ["SNAP_QUEUE_SEAL_KEY"])
        print("AUDIBLE_RECEIVER_PUBLIC_V1=" + base64.b64encode(public_bytes(receiver)).decode("ascii"))
        return

    if not 0 < args.bundle.stat().st_size <= MAX_BUNDLE_BYTES:
        raise ValueError("bundle size invalid")
    receiver_public = base64.b64decode(args.public_key.read_text(encoding="ascii").strip(), validate=True)
    envelope = seal(args.bundle.read_bytes(), receiver_public)
    with args.output.open("xb") as destination:
        destination.write(envelope)
    print("ciphertext_sha256=" + sha256(envelope).hexdigest())


if __name__ == "__main__":
    main()
