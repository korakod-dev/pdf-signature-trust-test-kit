"""Reads signature structure from raw bytes for fixture property tests.

Uses no validator. Anything proven here does not depend on pyHanko's verdicts.
"""

import hashlib
import re
from dataclasses import dataclass

from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

BYTE_RANGE = re.compile(rb"/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]")


@dataclass(frozen=True)
class SignedRegion:
    start1: int
    length1: int
    start2: int
    length2: int

    def covers(self, position: int) -> bool:
        return (
            self.start1 <= position < self.start1 + self.length1
            or self.start2 <= position < self.start2 + self.length2
        )

    def signed_bytes(self, data: bytes) -> bytes:
        return (
            data[self.start1 : self.start1 + self.length1]
            + data[self.start2 : self.start2 + self.length2]
        )


def signed_region(data: bytes) -> SignedRegion:
    matches = BYTE_RANGE.findall(data)
    if len(matches) != 1:
        raise ValueError(f"expected one ByteRange, found {len(matches)}")
    return SignedRegion(*(int(n) for n in matches[0]))


def _signed_data(data: bytes) -> cms.SignedData:
    region = signed_region(data)
    gap = data[region.start1 + region.length1 : region.start2]
    if not (gap.startswith(b"<") and gap.endswith(b">")):
        raise ValueError("the ByteRange gap is not exactly the /Contents hex string")
    content_info = cms.ContentInfo.load(bytes.fromhex(gap[1:-1].decode("ascii")))
    return content_info["content"]


def embedded_certificates(data: bytes) -> list[x509.Certificate]:
    return [
        x509.load_der_x509_certificate(choice.chosen.dump())
        for choice in _signed_data(data)["certificates"]
    ]


def digest_matches(data: bytes) -> bool:
    """Compare a SHA-256 of the signed bytes with the CMS messageDigest attribute."""
    signer_info = _signed_data(data)["signer_infos"][0]
    for attribute in signer_info["signed_attrs"]:
        if attribute["type"].native == "message_digest":
            claimed = attribute["values"][0].native
            actual = hashlib.sha256(signed_region(data).signed_bytes(data)).digest()
            return claimed == actual
    raise ValueError("no messageDigest attribute")


def verify_signed_attributes(data: bytes, signer_cert: x509.Certificate) -> None:
    """Verify the RSA signature over the signed attributes. Raises when it fails."""
    signer_info = _signed_data(data)["signer_infos"][0]
    # Signed over the SET OF encoding, not the [0] IMPLICIT tag used in the file.
    encoded = b"\x31" + signer_info["signed_attrs"].dump()[1:]
    signer_cert.public_key().verify(
        signer_info["signature"].native, encoded, padding.PKCS1v15(), hashes.SHA256()
    )
