# Decisions and corrections to the project brief

Checked on 2026-10-30 against installed tools. "Sample" below always means an
unrelated throw-away PDF and throw-away PKI, created outside the repository only
to learn output formats. Sample PDFs and keys are not in the repository. Only
their tool output is, under `tests/data/raw_outputs/`.

## Corrections to the brief

### pdfsig: `-no-ocsp` breaks trust checking on poppler 24.02

The brief says to pass `-no-ocsp` until M3. On Ubuntu 24.04 (poppler
24.02.0-1ubuntu9.11, NSS 2:3.98-1ubuntu0.3) a good chain then reports:

    Certificate Validation: Unknown issue with Certificate or corrupted data.

The same PDF and the same NSS database report `Certificate is Trusted.` without
the flag. `vfychain` also accepts the chain, for both RSA and ECDSA, with or
without key identifiers, and with or without the root embedded in the CMS. So the
flag is the cause, not the certificate profile. Homebrew poppler 26.04.0 reports
`Certificate is Trusted.` with and without the flag, so this looks specific to the
older version. The cause inside poppler or NSS was not investigated further.

Decision: do not pass `-no-ocsp`. This is also the tool's default configuration,
which is what the reference policy asks for. No outbound call follows from this:

- test certificates carry no AIA, OCSP or CRL URL;
- no default OCSP responder is configured in the temporary NSS database;
- CI runs validators in a network namespace with no route.

Options considered:

1. Keep `-no-ocsp`: every trusted case on pdfsig becomes `TOOL_ERROR`. Rejected.
2. Build a newer poppler from source: drifts from what Ubuntu 24.04 users run.
   Rejected for M1.
3. Drop the flag and isolate the network instead. Chosen.

M3 needs this reopened, because it adds revocation URLs.

### pdfsig: messages and exit codes on 24.02.0

Confirmed by observation: `Signature is Valid.`, `Digest Mismatch.`,
`Certificate is Trusted.`, `Certificate issuer isn't Trusted.`,
`Certificate issuer is unknown.`, `Total document signed`,
`Not total document signed`. Exit 0 with an invalid signature, exit 1 on an
unreadable or missing file, exit 2 with no signature.

Added to what the brief knew: `Unknown issue with Certificate or corrupted data.`
It stays unmapped on purpose.

Still not observed on 24.02.0: `Signature is Invalid.`,
`Certificate has been Revoked.`, `Certificate has Expired`. Their tests use
synthetic lines and say so.

An unsigned file prints `File '...' does not contain any signatures`, with exit 2.
`Document isn't signed or corrupted data.` was not seen.

### pdfsig: which "unknown issuer" message appears depends on the file

With the signer's root embedded in the CMS, the message is
`Certificate issuer isn't Trusted.`. Without it, the message is
`Certificate issuer is unknown.`. Both map to `INDETERMINATE`.

The kit embeds the root in fixtures. B1 then also checks that a root that merely
travels inside the file is not treated as a trust anchor.

### pdfsig options differ between versions

24.02.0 lacks `-no-appearance`, `-assert-signer` and `-enable-pgp`, which exist in
26.04.0. The kit only uses `-nssdir`.

### pyHanko

- `pyHanko` 0.38.0, `pyhanko-cli` 0.6.0 and their licenses are confirmed on PyPI.
  PyPI says Python >=3.10. The kit uses 3.12.
- `--trust-replace` is marked deprecated in the CLI help. The kit uses the API.
- `valid` and `intact` are separate. In the sample with one changed byte, the
  status was `intact=False, valid=True, trusted=False`. The rule that catches
  this is `intact` false, so `valid` alone would not be enough.
- `NONSTANDARD_COVERAGE` is a token from `summary_fields()`, not a value of the
  `coverage` field, whose values are `SignatureCoverageLevel` names. The adapter
  exposes it as the derived signal `coverage_summary`.
- `ValidationContext(allow_fetching=False)` is the default, confirmed in source.

### pdfsig: `Certificate has Expired` is now observed

Seen on 24.02.0 on a throw-away PDF during M2, with exit 0. It is no longer synthetic.

### DSS

Checked on DSS 6.5.1 with throw-away PDFs.

- The report writes `TOTAL_PASSED` and `TOTAL_FAILED`, with an underscore.
- The default policy is named "QES AES/QC AES TL based". It is used unmodified.
- `dss-cms-object` must be on the class path. `dss-policy-jaxb` supplies the default
  policy.
- Modification categories are in the diagnostic data, under `PDFRevision`,
  `ModificationDetection` and `ObjectModifications`. Names are confirmed in
  `DiagnosticData.xsd`.
- The documentation shows a validation time only for `RevocationDataVerifierFactory`.
  A setter on the document validator is not confirmed, and M2 does not need one.

## Certificates declare that no revocation data exists

**The default DSS policy rejects a signer with no revocation data.** A sample with
a good chain, and no revocation source, came back `INDETERMINATE` /
`CERTIFICATE_CHAIN_GENERAL_FAILURE`. Under that result every case except the
hash-failure and no-chain ones looks the same, so no modification result can be
observed, and no `TOTAL_PASSED` rule can be proven.

Options considered:

1. Keep the certificates as they were and report `INDETERMINATE` throughout. Honest,
   but it says nothing about the C group. Rejected.
2. Relax the DSS policy. The brief allows only stricter policies as separately
   labeled configurations, so the main results would stop being default. Rejected.
3. Put the RFC 9608 `noRevAvail` extension on every leaf. Chosen. The default policy
   lists this extension as a reason to skip the revocation check. It is also true
   of these leaves, which have no revocation source.

This changes the M1 leaf certificates. It changes no expected value. pyHanko and
pdfsig reported the same verdicts on samples with the extension, and gate 4 checks
this against the M1 verdicts. Case B5 in M3 must leave the extension off, because it
tests a revocation source that cannot be reached.

## How far the M2 samples go

Before the first real M2 run, pyHanko, pdfsig and DSS ran on throw-away PDFs built
with a separate PKI. Some were built with the same recipe functions as the C group,
because the report format of a modified file cannot be learned otherwise. The kit's
own fixtures were not run. This means the C-group behavior was largely visible
before the first run. `cases.yaml` was not changed after seeing it. Two things were
changed:

- The DSS mapping was written, following the brief's three `TOTAL_PASSED` rules.
- The C2 form fill first replaced the appearance dictionary, which DSS reported as
  undefined changes. That was a defect in the fixture, because a viewer filling a
  form keeps the dictionary, so the recipe now keeps it.

A form fill that changes the page still produces a DSS visual difference warning.
Under the brief's rule ("only signature or form-fill modifications") that is an
other warning, so the mapping gives `VALID_WITH_UNCLASSIFIED_CHANGES`. The rule was
not loosened to fit case C2.

## M3

### `-no-ocsp` stays off

M3 reopened this, as planned. Without the flag, pdfsig contacts the OCSP URL in a
certificate, and B4 then reports `Certificate has been Revoked.`. With the flag on
poppler 24.02 no good chain can be trusted at all. So the harness still does not pass it.

### Validators may fetch, and only loopback answers

To see revocation, pyHanko runs with `allow_fetching=True`, which is not its default,
and DSS has `OnlineCRLSource`, `OnlineOCSPSource` and `DefaultAIASource`. Both are
listed in the results. Only certificates with URLs fetch, and a test requires every
URL in the kit's certificates to be on `127.0.0.1`. In CI the run is in a network
namespace where only the loopback interface is up, with no route. Each observation
records the requests the local service saw.

### TSA, CRL and OCSP

- **CRL and OCSP:** `trustkit.services`, a small HTTP service on `127.0.0.1:18765`,
  started for the length of a run. Port 18766 is never bound, for B5.
- **TSA:** pyHanko's `DummyTimeStamper`, called in the same process when a fixture is
  built. No timestamp request reaches any network, which is stricter than loopback.
- **Certomancer is not used.** `DummyTimeStamper` takes a fixed time, so B3 is
  feasible without it. pyHanko exposes no signing time, so a small subclass sets it on
  the signing session.

### The default DSS policy requires revocation data for a TSA

The policy has no `noRevAvail` exemption for timestamp certificates. A sample with a
`noRevAvail` TSA gave a timestamp of `INDETERMINATE`, which DSS then ignored without
changing the signature's result. That made E1 look fine while its timestamp had failed,
and made B3 impossible. So both TSA certificates, and the B3 leaf, have a CRL URL on
loopback instead. Results now record each timestamp's own indication.

B3 has its CRL in a document security store, as its recipe says, and its leaf also has
a CRL URL. DSS and pyHanko fetched from that URL in the samples, so these results do
not show that a tool can rely on the embedded CRL alone.

### pdfsig: `Unknown issue with Certificate or corrupted data.`

On B5 pdfsig prints this, with an unreachable OCSP URL. It was unmapped on purpose, but
gate 3 then fails on every run.

1. Map it to `INDETERMINATE`, which would agree with the oracle for B5. The string
   does not say the cause, so this would claim more than the tool does. Rejected.
2. Map it to an explicit `TOOL_ERROR`, and record that in the baseline, as gate 2
   allows. Chosen. This scores `ERROR`.

### DSS: `ExtensionChange` counts as no modification

DSS gives no warning for it, and the brief's rule for `VALID` is "no modification
warnings". The pyHanko rules treat `LTA_UPDATES` the same way. This affects only B3,
and it was decided after seeing B3 in a sample, so it is listed here on purpose.

### How far the M3 samples go

As in M2, the tools ran on samples before the first real run, this time with the same
recipe functions and a fresh PKI for each sample, and in a container set up like CI. So
the M3 behavior was visible before the first real run. Besides the mapping, the samples
changed the TSA and B3 certificates, as described above. `cases.yaml` did not change.

## M4

### veraPDF

Version 1.28.2, the newest `org.verapdf.apps:greenfield-apps` on Maven Central. The
installer on the veraPDF site has no version in its URL, so it cannot be pinned. A
pom with no code of ours packages the command line, and the jar is built in CI. Only
the pom is in this repository. veraPDF is a precondition for group F, not a validator
under test, and gate 1 fails when a labeled file does not pass.

### Building PDF/A-3b

Group F has its own base document, because the base PDF of earlier cases has a font
that is not embedded. It uses Bitstream Vera as shipped with ReportLab, and an sRGB
profile generated by Pillow. Neither file is stored here.

Two pyHanko behaviors needed handling, both found through veraPDF:

- `/AFRelationship` raises the output version to 2.0, while PDF/A-3 needs a 1.x
  header. The builder sets it back to 1.7.
- pyHanko replaces a `/Metadata` stream it did not write on every write, which drops
  the PDF/A identification. Writers of these files turn that off through a private
  attribute, `_update_meta`, which is safe only because pyHanko is pinned.

### Which files are labeled PDF/A-3b

F1 and F3, before and after signing. F2 is F1 with a later update, and is not labeled,
so it is not part of the gate.

### How far the M4 samples go

As in M2 and M3, the tools ran on samples from the same recipes before the first real
run, in a container set up like CI. The mapping did not change for M4, and `cases.yaml`
did not change.

## Changes to `oracle/mapping.yaml` before the first real run

Version 1 is the brief's mapping, committed before any sampling. Version 2 follows
sampling:

1. pyHanko `VALID` now needs `coverage = ENTIRE_FILE` or `LTA_UPDATES`. Version 1
   allowed any `modification_level = NONE`, but the sample with trailing bytes
   (`EXTENDED_WITH_NONE`) has that level and the file is not wholly covered. The
   brief says "whole file covered or LTA_UPDATES only". That state is now unmapped.
2. pdfsig has an explicit list of informational lines, so that any other line is
   unmapped. The brief's "any other string" needs this to be enforceable.
3. The catch-all exit code entry was removed. An exit code not listed is unmapped.

Version 3 replaces the placeholder DSS section with the real one, before DSS has run
on any fixture.

Version 4 adds the two M3 entries above, before the first real M3 run.

No expected value in `cases.yaml` changed.

## Other decisions

- **Signature type:** `ETSI.CAdES.detached`, because M3 builds on PAdES. pdfsig and
  pyHanko accepted `adbe.pkcs7.detached` equally in the sample.
- **Key type:** RSA-2048, as the most widely supported choice for later validators.
- **Certificate validity:** roots and valid leaves run 2020-01-01 to 2046-12-31.
  Expired leaves, from M2, will end by 2021.
- **Trust flags:** NSS `CT,C,C`.
- **All 20 cases are pre-registered now.** Only the milestone's cases are run, but
  committing every expected value early is the stronger claim.
- **The first real run happens in GitHub Actions.** The run's timestamp and commit
  come from outside this machine, which is better evidence than a local log. That
  run is red by design, because gate 4 has no baseline yet.
- **Apt packages are pinned to exact versions.** When Ubuntu replaces one, the
  install step goes red and someone must update the pin. A silent tool upgrade in
  a regression kit is worse.
- **Actions are pinned by commit SHA.**
- **Network isolation:** `unshare --net` under `sudo` in CI, then back to the runner
  user. `results.json` records whether the routing table was empty. Locally on
  macOS there is no namespace, so local runs report `network_isolated: false`.
