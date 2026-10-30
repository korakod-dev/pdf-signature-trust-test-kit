"""Fixture recipes. One function per case id."""

import datetime as dt
import io
from dataclasses import dataclass
from pathlib import Path

from asn1crypto import cms
from asn1crypto import crl as asn1_crl
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from pyhanko.keys import load_cert_from_pemder, load_certs_from_pemder, load_private_key_from_pemder
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.writer import PageObject, PdfFileWriter
from pyhanko.sign import fields, signers
from pyhanko.sign.timestamps.dummy_client import DummyTimeStamper
from pyhanko.sign.validation.dss import DocumentSecurityStore
from reportlab.pdfgen import canvas

from trustkit.fixtures import inspect, pdfa
from trustkit.pki import Identity, TestPki

AMOUNT_TEXT = b"Amount: 1000.00"
# A2 turns the first digit of the amount into a 9.
AMOUNT_TAMPER_OFFSET = len(b"Amount: ")
AMOUNT_TAMPER_BYTE = ord("9")
# C4 and C5 change the visible amount to this.
CHANGED_AMOUNT_TEXT = b"Amount: 9000.00"
FORM_FIELD_NAME = "TestField"
FORM_FIELD_VALUE = "TEST ONLY filled value"
# D1 shows this on the page. The certificate subject says something else.
OTHER_NAME_TEXT = "Signed by: Example Other Person"
# A3 puts this in the part of the ByteRange gap after /Contents.
UNSIGNED_MARKER = b"% TEST ONLY content outside the signature"
# B3: inside the window of the expired leaf, which ended in 2020.
PAST_TIME = dt.datetime(2020, 6, 15, 12, 0, tzinfo=dt.timezone.utc)


@dataclass(frozen=True)
class Fixture:
    case_id: str
    path: Path
    # The only certificate a validator may trust for this case.
    trust_anchor: Identity
    # For cases with a later update: the exact bytes the first signature covers.
    signed_revision: bytes | None = None


def base_pdf(extra_line: str | None = None) -> bytes:
    """A one-page PDF with uncompressed page content, so byte edits are controlled."""
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pageCompression=0, invariant=1)
    pdf.setTitle("TEST ONLY synthetic document")
    pdf.setAuthor("Example Test Org")
    pdf.drawString(72, 750, "TEST ONLY - synthetic document - Not For Production")
    pdf.drawString(72, 720, "Example Test Org")
    pdf.drawString(72, 690, AMOUNT_TEXT.decode("ascii"))
    if extra_line:
        pdf.drawString(72, 660, extra_line)
    pdf.showPage()
    pdf.save()
    return buffer.getvalue()


def form_pdf() -> bytes:
    """The base document with one empty text field, for C2."""
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pageCompression=0, invariant=1)
    pdf.setTitle("TEST ONLY synthetic form")
    pdf.setAuthor("Example Test Org")
    pdf.drawString(72, 750, "TEST ONLY - synthetic form - Not For Production")
    pdf.acroForm.textfield(name=FORM_FIELD_NAME, x=72, y=680, width=300, height=20, value="")
    pdf.showPage()
    pdf.save()
    return buffer.getvalue()


def layered_pdf() -> bytes:
    """Two page content streams for C5. The second one paints over the changed amount.

    At signing time a reader sees 1000.00. The changed amount is in the signed bytes,
    underneath an opaque rectangle. Written from the published Hide description, with
    no third-party file involved. See docs/related-work.md.
    """
    writer = PdfFileWriter()
    font = generic.DictionaryObject(
        {
            generic.pdf_name("/Type"): generic.pdf_name("/Font"),
            generic.pdf_name("/Subtype"): generic.pdf_name("/Type1"),
            generic.pdf_name("/BaseFont"): generic.pdf_name("/Helvetica"),
        }
    )
    underneath = writer.add_object(
        generic.StreamObject(
            stream_data=(
                b"BT /F1 12 Tf 72 750 Td (TEST ONLY - synthetic document) Tj ET\n"
                b"BT /F1 12 Tf 72 690 Td (" + CHANGED_AMOUNT_TEXT + b") Tj ET\n"
            )
        )
    )
    overlay = writer.add_object(
        generic.StreamObject(
            stream_data=(
                b"q 1 1 1 rg 60 680 400 30 re f Q\n"
                b"BT /F1 12 Tf 72 690 Td (" + AMOUNT_TEXT + b") Tj ET\n"
            )
        )
    )
    page = PageObject(
        contents=generic.ArrayObject([underneath, overlay]),
        media_box=(0, 0, 612, 792),
        resources=generic.DictionaryObject(
            {
                generic.pdf_name("/Font"): generic.DictionaryObject(
                    {generic.pdf_name("/F1"): font}
                )
            }
        ),
    )
    writer.insert_page(page)
    buffer = io.BytesIO()
    writer.write(buffer)
    return buffer.getvalue()


class _BackdatingSigner(signers.PdfSigner):
    """pyHanko exposes no signing time, so B3 sets it on the signing session."""

    def __init__(self, *args, signing_time: dt.datetime, **kwargs):
        super().__init__(*args, **kwargs)
        self._signing_time = signing_time

    def init_signing_session(self, *args, **kwargs):
        session = super().init_signing_session(*args, **kwargs)
        session.system_time = self._signing_time
        return session


def timestamper(tsa: Identity, issuer: Identity, at: dt.datetime | None = None) -> DummyTimeStamper:
    """A TSA in this process, so no timestamp request leaves it. See docs/decisions.md."""
    return DummyTimeStamper(
        tsa_cert=load_cert_from_pemder(str(tsa.cert_path)),
        tsa_key=load_private_key_from_pemder(str(tsa.key_path), passphrase=None),
        certs_to_embed=list(load_certs_from_pemder([str(issuer.cert_path)])),
        fixed_dt=at,
    )


def sign(
    data: bytes,
    signer_identity: Identity,
    issuer: Identity,
    field_name: str = "Signature1",
    docmdp: fields.MDPPerm | None = None,
    tsa: DummyTimeStamper | None = None,
    signing_time: dt.datetime | None = None,
    preserve_xmp: bool = False,
) -> bytes:
    """Sign with the issuer embedded, so B1 also tests that a root in the file is not trusted.

    Passing docmdp makes this a certification signature.
    """
    signer = signers.SimpleSigner.load(
        key_file=str(signer_identity.key_path),
        cert_file=str(signer_identity.cert_path),
        ca_chain_files=[str(issuer.cert_path)],
    )
    if signer is None:
        raise RuntimeError("pyHanko could not load the test signer")
    writer = IncrementalPdfFileWriter(io.BytesIO(data))
    if preserve_xmp:
        pdfa.keep_xmp(writer)
    meta = signers.PdfSignatureMetadata(
        field_name=field_name,
        md_algorithm="sha256",
        subfilter=fields.SigSeedSubFilter.PADES,
        certify=docmdp is not None,
        docmdp_permissions=docmdp or fields.MDPPerm.FILL_FORMS,
    )
    if signing_time is None:
        return signers.sign_pdf(writer, meta, signer=signer, timestamper=tsa).getvalue()
    pdf_signer = _BackdatingSigner(meta, signer, timestamper=tsa, signing_time=signing_time)
    return pdf_signer.sign_pdf(writer).getvalue()


def tamper_amount(signed: bytes) -> bytes:
    """Change exactly one byte of the amount, keeping file length and xref offsets."""
    if signed.count(AMOUNT_TEXT) != 1:
        raise ValueError("expected the amount text exactly once in the page content")
    position = signed.index(AMOUNT_TEXT) + AMOUNT_TAMPER_OFFSET
    tampered = bytearray(signed)
    tampered[position] = AMOUNT_TAMPER_BYTE
    return bytes(tampered)


def _update(data: bytes, change) -> bytes:
    """Append one incremental update. The earlier bytes stay exactly as they were."""
    writer = IncrementalPdfFileWriter(io.BytesIO(data))
    change(writer)
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def _first_page(writer: IncrementalPdfFileWriter) -> generic.DictionaryObject:
    return writer.root["/Pages"]["/Kids"][0]


def fill_field(signed: bytes) -> bytes:
    """C2: set the value and appearance of the form field, and nothing else."""

    def change(writer: IncrementalPdfFileWriter) -> None:
        field = writer.root["/AcroForm"]["/Fields"][0]
        if field["/T"] != FORM_FIELD_NAME:
            raise ValueError("expected the test form field first")
        old = field["/AP"]["/N"]
        font = next(iter(old["/Resources"]["/Font"]))
        # Same dictionary as the empty appearance, so only the shown value differs.
        appearance = generic.StreamObject(
            {key: old.raw_get(key) for key in old if key != "/Length"},
            stream_data=(
                b"/Tx BMC BT " + font.encode("ascii") + b" 12 Tf 2 5 Td ("
                + FORM_FIELD_VALUE.encode("ascii") + b") Tj ET EMC\n"
            ),
        )
        field[generic.pdf_name("/V")] = generic.TextStringObject(FORM_FIELD_VALUE)
        field[generic.pdf_name("/AP")] = generic.DictionaryObject(
            {generic.pdf_name("/N"): writer.add_object(appearance)}
        )
        writer.update_container(field)

    return _update(signed, change)


def add_annotation(signed: bytes) -> bytes:
    """C3: add one text annotation. DocMDP 1 forbids it, and DocMDP 3 would allow it."""

    def change(writer: IncrementalPdfFileWriter) -> None:
        page = _first_page(writer)
        annotation = generic.DictionaryObject(
            {
                generic.pdf_name("/Type"): generic.pdf_name("/Annot"),
                generic.pdf_name("/Subtype"): generic.pdf_name("/Text"),
                generic.pdf_name("/Rect"): generic.ArrayObject(
                    [generic.NumberObject(n) for n in (72, 600, 92, 620)]
                ),
                generic.pdf_name("/Contents"): generic.TextStringObject("TEST ONLY annotation"),
            }
        )
        annotations = generic.ArrayObject(page.get("/Annots", generic.ArrayObject()))
        annotations.append(writer.add_object(annotation))
        page[generic.pdf_name("/Annots")] = annotations
        writer.update_container(page)

    return _update(signed, change)


def replace_page_content(signed: bytes) -> bytes:
    """C4: point the page at a new content stream showing a changed amount."""

    def change(writer: IncrementalPdfFileWriter) -> None:
        page = _first_page(writer)
        original = page["/Contents"].data
        if original.count(AMOUNT_TEXT) != 1:
            raise ValueError("expected the amount text exactly once in the page content")
        changed = generic.StreamObject(
            stream_data=original.replace(AMOUNT_TEXT, CHANGED_AMOUNT_TEXT)
        )
        page[generic.pdf_name("/Contents")] = writer.add_object(changed)
        writer.update_container(page)

    return _update(signed, change)


def remove_overlay(signed: bytes) -> bytes:
    """C5: a new Page object with every object of the old one, except the overlay."""

    def change(writer: IncrementalPdfFileWriter) -> None:
        pages = writer.root["/Pages"]
        old_page = pages["/Kids"][0]
        new_page = generic.DictionaryObject(
            {key: old_page.raw_get(key) for key in old_page if key != "/Contents"}
        )
        new_page[generic.pdf_name("/Contents")] = old_page["/Contents"].raw_get(0)
        pages[generic.pdf_name("/Kids")] = generic.ArrayObject([writer.add_object(new_page)])
        writer.update_container(pages)

    return _update(signed, change)


def widen_byte_range_gap(signed: bytes) -> bytes:
    """A3: end /Contents early, and put bytes in the rest of the gap.

    The signed bytes and the ByteRange do not change, so the signature still verifies.
    """
    region = inspect.signed_region(signed)
    start, end = region.start1 + region.length1, region.start2
    hex_digits = signed[start + 1 : end - 1]
    cms_length = len(cms.ContentInfo.load(bytes.fromhex(hex_digits.decode("ascii"))).dump())
    contents = b"<" + hex_digits[: 2 * cms_length] + b">\n" + UNSIGNED_MARKER
    return signed[:start] + contents.ljust(end - start - 1) + b"\n" + signed[end:]


def past_crl(root: Identity) -> bytes:
    """B3: a CRL from inside the leaf's validity window, which lists nothing."""
    key = serialization.load_pem_private_key(root.key_path.read_bytes(), password=None)
    return (
        x509.CertificateRevocationListBuilder()
        .issuer_name(root.cert.subject)
        .last_update(PAST_TIME + dt.timedelta(days=1))
        .next_update(PAST_TIME + dt.timedelta(days=180))
        .sign(key, hashes.SHA256())
        .public_bytes(serialization.Encoding.DER)
    )


def embed_revocation_data(signed: bytes, root: Identity, crl: bytes) -> bytes:
    """B3: add a document security store with the CRL, in an incremental update."""

    def change(writer: IncrementalPdfFileWriter) -> None:
        DocumentSecurityStore.supply_dss_in_writer(
            writer,
            None,
            certs=[load_cert_from_pemder(str(root.cert_path))],
            crls=[asn1_crl.CertificateList.load(crl)],
        )

    return _update(signed, change)


def replace_attachment(signed: bytes, xml: bytes) -> bytes:
    """F2: point the attachment at new XML. No page object changes."""
    writer = IncrementalPdfFileWriter(io.BytesIO(signed))
    pdfa.keep_xmp(writer)
    spec = writer.root["/Names"]["/EmbeddedFiles"]["/Names"][1]
    spec["/EF"][generic.pdf_name("/F")] = writer.add_object(pdfa.embedded_file(writer, xml))
    spec["/EF"][generic.pdf_name("/UF")] = spec["/EF"].raw_get("/F")
    writer.update_container(spec)
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def _write(out_dir: Path, contents: dict[str, tuple]) -> dict[str, Fixture]:
    out_dir.mkdir(parents=True, exist_ok=True)
    built = {}
    for case_id, (data, anchor, *revision) in contents.items():
        path = out_dir / f"{case_id}.pdf"
        path.write_bytes(data)
        built[case_id] = Fixture(case_id, path, anchor, revision[0] if revision else None)
    return built


def build_m1(out_dir: Path, pki: TestPki) -> dict[str, Fixture]:
    base = base_pdf()
    a1 = sign(base, pki.leaf, pki.root)
    return _write(
        out_dir,
        {
            "A1": (a1, pki.root),
            "A2": (tamper_amount(a1), pki.root),
            # Trust anchor is the first root, so the second one stays untrusted.
            "B1": (sign(base, pki.other_leaf, pki.other_root), pki.root),
        },
    )


def build_m2(out_dir: Path, pki: TestPki) -> dict[str, Fixture]:
    base = base_pdf()
    plain = sign(base, pki.leaf, pki.root)
    certified_form = sign(form_pdf(), pki.leaf, pki.root, docmdp=fields.MDPPerm.FILL_FORMS)
    certified = sign(base, pki.leaf, pki.root, docmdp=fields.MDPPerm.NO_CHANGES)
    layered = sign(layered_pdf(), pki.leaf, pki.root)
    return {
        **build_m1(out_dir, pki),
        **_write(
            out_dir,
            {
                "N1": (base, pki.root),
                "B2": (sign(base, pki.expired_leaf, pki.root), pki.root),
                "C1": (
                    sign(plain, pki.second_leaf, pki.root, field_name="Signature2"),
                    pki.root,
                    plain,
                ),
                "C2": (fill_field(certified_form), pki.root, certified_form),
                "C3": (add_annotation(certified), pki.root, certified),
                "C4": (replace_page_content(plain), pki.root, plain),
                "C5": (remove_overlay(layered), pki.root, layered),
            },
        ),
    }


def build_m3(out_dir: Path, pki: TestPki) -> dict[str, Fixture]:
    base = base_pdf()
    plain = sign(base, pki.leaf, pki.root)
    # Trust anchor is the first root, so the second TSA stays untrusted in E2.
    past = sign(
        base,
        pki.past_leaf,
        pki.root,
        tsa=timestamper(pki.tsa, pki.root, at=PAST_TIME),
        signing_time=PAST_TIME,
    )
    return {
        **build_m2(out_dir, pki),
        **_write(
            out_dir,
            {
                "A3": (widen_byte_range_gap(plain), pki.root),
                "B3": (embed_revocation_data(past, pki.root, past_crl(pki.root)), pki.root, past),
                "B4": (
                    sign(base, pki.revoked_leaf, pki.root, tsa=timestamper(pki.tsa, pki.root)),
                    pki.root,
                ),
                "B5": (sign(base, pki.unreachable_leaf, pki.root), pki.root),
                "D1": (sign(base_pdf(OTHER_NAME_TEXT), pki.leaf, pki.root), pki.root),
                "E1": (sign(base, pki.leaf, pki.root, tsa=timestamper(pki.tsa, pki.root)), pki.root),
                "E2": (
                    sign(
                        base,
                        pki.leaf,
                        pki.root,
                        tsa=timestamper(pki.other_tsa, pki.other_root),
                    ),
                    pki.root,
                ),
            },
        ),
    }


def build_m4(out_dir: Path, pki: TestPki) -> dict[str, Fixture]:
    matching = pdfa.pdfa_with_xml(pdfa.synthetic_xml(pdfa.PAGE_AMOUNT))
    disagreeing = pdfa.pdfa_with_xml(pdfa.synthetic_xml(pdfa.OTHER_AMOUNT))
    f1 = sign(matching, pki.leaf, pki.root, preserve_xmp=True)
    f3 = sign(disagreeing, pki.leaf, pki.root, preserve_xmp=True)
    # The unsigned files exist for the veraPDF check before signing. See PDFA_CHECKS.
    unsigned_dir = out_dir / "unsigned"
    unsigned_dir.mkdir(parents=True, exist_ok=True)
    (unsigned_dir / "F1.pdf").write_bytes(matching)
    (unsigned_dir / "F3.pdf").write_bytes(disagreeing)
    return {
        **build_m3(out_dir, pki),
        **_write(
            out_dir,
            {
                "F1": (f1, pki.root),
                "F2": (
                    replace_attachment(f1, pdfa.synthetic_xml(pdfa.OTHER_AMOUNT)),
                    pki.root,
                    f1,
                ),
                "F3": (f3, pki.root),
            },
        ),
    }


# Files that are labeled PDF/A-3b, relative to the fixture directory. gates.check_pdfa
# requires all of them to pass veraPDF.
PDFA_CHECKS = {
    "F1 before signing": "unsigned/F1.pdf",
    "F1 after signing": "F1.pdf",
    "F3 before signing": "unsigned/F3.pdf",
    "F3 after signing": "F3.pdf",
}

BUILDERS = {"M1": build_m1, "M2": build_m2, "M3": build_m3, "M4": build_m4}
