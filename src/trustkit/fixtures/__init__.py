"""Fixture recipes. One function per case id."""

import io
from dataclasses import dataclass
from pathlib import Path

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers
from reportlab.pdfgen import canvas

from trustkit.pki import Identity, TestPki

AMOUNT_TEXT = b"Amount: 1000.00"
# A2 turns the first digit of the amount into a 9.
AMOUNT_TAMPER_OFFSET = len(b"Amount: ")
AMOUNT_TAMPER_BYTE = ord("9")


@dataclass(frozen=True)
class Fixture:
    case_id: str
    path: Path
    # The only certificate a validator may trust for this case.
    trust_anchor: Identity


def base_pdf() -> bytes:
    """A one-page PDF with uncompressed page content, so byte edits are controlled."""
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pageCompression=0, invariant=1)
    pdf.setTitle("TEST ONLY synthetic document")
    pdf.setAuthor("Example Test Org")
    pdf.drawString(72, 750, "TEST ONLY - synthetic document - Not For Production")
    pdf.drawString(72, 720, "Example Test Org")
    pdf.drawString(72, 690, AMOUNT_TEXT.decode("ascii"))
    pdf.showPage()
    pdf.save()
    return buffer.getvalue()


def sign(data: bytes, signer_identity: Identity, issuer: Identity) -> bytes:
    """Sign with the issuer embedded, so B1 also tests that a root in the file is not trusted."""
    signer = signers.SimpleSigner.load(
        key_file=str(signer_identity.key_path),
        cert_file=str(signer_identity.cert_path),
        ca_chain_files=[str(issuer.cert_path)],
    )
    if signer is None:
        raise RuntimeError("pyHanko could not load the test signer")
    writer = IncrementalPdfFileWriter(io.BytesIO(data))
    meta = signers.PdfSignatureMetadata(
        field_name="Signature1",
        md_algorithm="sha256",
        subfilter=fields.SigSeedSubFilter.PADES,
    )
    return signers.sign_pdf(writer, meta, signer=signer).getvalue()


def tamper_amount(signed: bytes) -> bytes:
    """Change exactly one byte of the amount, keeping file length and xref offsets."""
    if signed.count(AMOUNT_TEXT) != 1:
        raise ValueError("expected the amount text exactly once in the page content")
    position = signed.index(AMOUNT_TEXT) + AMOUNT_TAMPER_OFFSET
    tampered = bytearray(signed)
    tampered[position] = AMOUNT_TAMPER_BYTE
    return bytes(tampered)


def build_m1(out_dir: Path, pki: TestPki) -> dict[str, Fixture]:
    out_dir.mkdir(parents=True, exist_ok=True)
    base = base_pdf()
    a1 = sign(base, pki.leaf, pki.root)
    contents = {
        "A1": (a1, pki.root),
        "A2": (tamper_amount(a1), pki.root),
        # Trust anchor is the first root, so the second one stays untrusted.
        "B1": (sign(base, pki.other_leaf, pki.other_root), pki.root),
    }
    fixtures = {}
    for case_id, (data, anchor) in contents.items():
        path = out_dir / f"{case_id}.pdf"
        path.write_bytes(data)
        fixtures[case_id] = Fixture(case_id, path, anchor)
    return fixtures
