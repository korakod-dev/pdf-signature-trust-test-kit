# Limitations

- **pyHanko is both generator and validator.** It signs the fixtures and is also
  one of the validators under test. A pyHanko signing bug could be hidden by its
  own validator. Mitigations: pdfsig reads the same files, and the fixture property
  tests recompute the digest and verify the RSA signature with `cryptography`
  alone. pyHanko is never the oracle.
- **pyHanko describes incremental update analysis as "(very) experimental"** and
  does not validate PAdES profile structure. Later cases that depend on these must
  be read with that in mind.
- **pdfsig runs in default OCSP mode, not with `-no-ocsp`.** See `decisions.md`.
  Isolation depends on every URL in the test certificates being on loopback, and on
  the network namespace in CI.
- **Local runs on macOS have no network namespace**, and `network_isolated` is false
  in their results. Certificate URLs in the kit are on loopback, but only CI enforces
  isolation.
- **pyHanko and DSS do not run with their out-of-the-box revocation settings.** Both
  are allowed to fetch, so that they can see revocation at all. Without this, B4
  could not show anything on either tool. pyHanko keeps its default soft-fail mode.
- **pyHanko uses `validate_pdf_signature`**, not `validate_pdf_ltv_signature`. B3
  measures the first. The second may give another result, and has not been run.
- **B3 does not show reliance on the embedded CRL alone**, because its leaf also has
  a CRL URL that answers.
- **The TSA is pyHanko's `DummyTimeStamper`,** a test class, so the timestamps do not
  come from a separate TSA program.
- **M1 pdfsig results apply to poppler 24.02.0 with NSS 3.98 on Ubuntu 24.04.** On
  Homebrew poppler 26.04.0, `-no-ocsp` behaved differently, so results cannot be
  assumed to carry across versions.
- **Fixtures use one signature type** (`ETSI.CAdES.detached`) and one key type
  (RSA-2048).
- **`spec_ref` is `TODO` on every `spec` case.** ISO 32000-2, ETSI EN 319 102-1 and
  ETSI EN 319 142 have not been read for this project, so those verdicts rest on
  general understanding of the standards until the clauses are confirmed.
- **One pdfsig string is only tested with a synthetic line:** `Signature is Invalid.`.
- **DSS accepts the leaves only because they declare `noRevAvail`.** Without it,
  every signature with a good chain is `INDETERMINATE` under the default policy. See
  `decisions.md`.
- **B2 has no claimed signing time inside the validity window.** pyHanko stamps the
  current time, so the claim is also after expiry. A claimed time inside the window
  is not tested.
- **C5 covers one Hide variant**, the one that writes a new Page object without the
  overlay. The Xref variant is not covered.
- **C3 uses an annotation as the later change**, so it tests DocMDP level 1 rather
  than page changes, which C4 covers.
- **DSS runs on Java 21 in CI**, with DSS 6.5.1 and its default policy.
- **Fixture bytes differ on every run**, because keys and signing times differ. The
  baseline compares verdicts and scores, not hashes. Each run records its own
  fixture SHA-256.
