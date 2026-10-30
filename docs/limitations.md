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
  Isolation depends on the test certificates having no URLs and on the network
  namespace in CI.
- **Local runs on macOS have no network namespace**, and `network_isolated` is false
  in their results. The kit's test certificates have no URLs, and pyHanko runs with
  fetching off, but only CI enforces isolation.
- **M1 pdfsig results apply to poppler 24.02.0 with NSS 3.98 on Ubuntu 24.04.** On
  Homebrew poppler 26.04.0, `-no-ocsp` behaved differently, so results cannot be
  assumed to carry across versions.
- **Fixtures use one signature type** (`ETSI.CAdES.detached`) and one key type
  (RSA-2048).
- **`spec_ref` is `TODO` on every `spec` case.** ISO 32000-2, ETSI EN 319 102-1 and
  ETSI EN 319 142 have not been read for this project, so those verdicts rest on
  general understanding of the standards until the clauses are confirmed.
- **Three pdfsig strings are only tested with synthetic lines:**
  `Signature is Invalid.`, `Certificate has been Revoked.`, `Certificate has Expired`.
- **Fixture bytes differ on every run**, because keys and signing times differ. The
  baseline compares verdicts and scores, not hashes. Each run records its own
  fixture SHA-256.
- **Not investigated yet:** how DSS exposes modification warnings, and whether
  Certomancer can issue backdated timestamps for B3.
