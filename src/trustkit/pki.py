"""Throw-away test PKI, built with `cryptography` to stay independent of pyHanko.

Keys are created at run time in a temporary directory outside the repository and
must never be committed. Certificates carry no AIA, OCSP or CRL URL, so no
validator has anywhere to call.
"""

import datetime as dt
import os
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

from trustkit.oracle import ROOT

ORG = "Example Test Org"
ROOT_CN = "TEST ONLY Root CA - Not For Production"
LEAF_CN = "TEST ONLY Signer - Not For Production"
OTHER_ROOT_CN = "TEST ONLY Untrusted Root CA - Not For Production"
OTHER_LEAF_CN = "TEST ONLY Untrusted Signer - Not For Production"
SECOND_LEAF_CN = "TEST ONLY Second Signer - Not For Production"
EXPIRED_LEAF_CN = "TEST ONLY Expired Signer - Not For Production"

# Fixed and far apart, so fixtures do not expire. See docs/decisions.md.
NOT_BEFORE = dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
NOT_AFTER = dt.datetime(2046, 12, 31, tzinfo=dt.timezone.utc)
EXPIRED_NOT_AFTER = dt.datetime(2020, 12, 31, tzinfo=dt.timezone.utc)
# RFC 9608 noRevAvail, whose value is an ASN.1 NULL. The leaves have no revocation source,
# and this states it. The default DSS policy needs it to accept such a leaf. See docs/decisions.md.
NO_REV_AVAIL = ObjectIdentifier("2.5.29.56")
ASN1_NULL = b"\x05\x00"


@dataclass(frozen=True)
class Identity:
    cert: x509.Certificate
    cert_path: Path
    key_path: Path


@dataclass(frozen=True)
class TestPki:
    # Tells pytest that this is not a test class.
    __test__ = False

    root: Identity
    leaf: Identity
    other_root: Identity
    other_leaf: Identity
    second_leaf: Identity
    expired_leaf: Identity


def _name(common_name: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )


def _key_usage(*, signer: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=signer,
        # pyHanko requires non_repudiation on signers by default.
        content_commitment=signer,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=not signer,
        crl_sign=not signer,
        encipher_only=False,
        decipher_only=False,
    )


def _store(
    cert: x509.Certificate, key: rsa.RSAPrivateKey, certs_dir: Path, keys_dir: Path, stem: str
) -> Identity:
    cert_path = certs_dir / f"{stem}.crt"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path = keys_dir / f"{stem}.key"
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    return Identity(cert, cert_path, key_path)


def _make_root(common_name: str, certs_dir: Path, keys_dir: Path, stem: str) -> Identity:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = _name(common_name)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(_key_usage(signer=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return _store(cert, key, certs_dir, keys_dir, stem)


def _make_leaf(
    common_name: str,
    issuer: Identity,
    certs_dir: Path,
    keys_dir: Path,
    stem: str,
    not_after: dt.datetime = NOT_AFTER,
) -> Identity:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer_key = serialization.load_pem_private_key(issuer.key_path.read_bytes(), password=None)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(issuer.cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(_key_usage(signer=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer.cert.public_key()),
            critical=False,
        )
        .add_extension(x509.UnrecognizedExtension(NO_REV_AVAIL, ASN1_NULL), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )
    return _store(cert, key, certs_dir, keys_dir, stem)


def assert_outside_repository(path: Path) -> None:
    resolved = path.resolve()
    if resolved == ROOT or ROOT in resolved.parents:
        raise ValueError(f"key directory must be outside the repository: {resolved}")


def generate(certs_dir: Path, keys_dir: Path) -> TestPki:
    """Create the test PKI. Certificates go to certs_dir and keys to keys_dir."""
    assert_outside_repository(keys_dir)
    certs_dir.mkdir(parents=True, exist_ok=True)
    keys_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(keys_dir, 0o700)
    root = _make_root(ROOT_CN, certs_dir, keys_dir, "test-root")
    leaf = _make_leaf(LEAF_CN, root, certs_dir, keys_dir, "test-leaf")
    other_root = _make_root(OTHER_ROOT_CN, certs_dir, keys_dir, "other-root")
    other_leaf = _make_leaf(OTHER_LEAF_CN, other_root, certs_dir, keys_dir, "other-leaf")
    second_leaf = _make_leaf(SECOND_LEAF_CN, root, certs_dir, keys_dir, "second-leaf")
    expired_leaf = _make_leaf(
        EXPIRED_LEAF_CN, root, certs_dir, keys_dir, "expired-leaf", not_after=EXPIRED_NOT_AFTER
    )
    return TestPki(root, leaf, other_root, other_leaf, second_leaf, expired_leaf)
