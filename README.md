# PDF Signature Trust Test Kit

"The signature verifies" and "this document can be trusted" are different
questions. This kit generates synthetic signed PDFs, commits the expected verdict
for each one before any tool runs on it, runs independent validators in CI, maps
their output to one verdict model, and records which tool produced which verdict.

It is not new vulnerability research, not a legal or compliance verdict, not an
e-Tax conformance test, and not a ranking of tools. It reports behavior per case,
tool version and configuration.

**Status:** milestone M4 (20 cases, on pyHanko, pdfsig and EU DSS, with veraPDF
checking the files labeled PDF/A-3b). Group F is a simulated scenario, not a
conformance test.

**License:** to be decided before public release.

## Evidence of ordering

The expected verdicts were committed before any tool ran on any fixture. See
[Commit order](#commit-order) for the commits.

## Run

Requires Python 3.12, [uv](https://docs.astral.sh/uv/), `poppler-utils` and
`libnss3-tools` (or any `pdfsig` and `certutil`), Java 21 and Maven.

```bash
uv sync --locked
mvn -B -q -f adapters/dss-runner/pom.xml package
mvn -B -q -f adapters/verapdf-runner/pom.xml package
uv run pytest
uv run trustkit run --milestone M4 --out out
uv run trustkit check --results out/results.json
uv run trustkit scan
```

`trustkit run` writes `out/results.md`, `out/results.json`, `out/raw/`,
`out/fixtures/` and `out/certs/`. Test keys exist only in a temporary directory
outside the repository, and are deleted when the run ends.

Results on a machine other than Ubuntu 24.04 with the pinned packages can differ
from the baseline, and gate 4 then fails. That is expected.

## CI gates

CI is red when any of these holds:

1. a fixture property test fails, or a file labeled PDF/A-3b fails veraPDF;
2. a tool is missing, a case was not run, or a `TOOL_ERROR` is not recorded in the
   baseline;
3. any output is unmapped;
4. results differ from `baselines/baseline.json`, better or worse;
5. a tracked file looks like key material.

CI is not red merely because a tool disagrees with the oracle. That is a recorded
result.

## Where things are

- `oracle/`: expected verdicts, reference policy, verdict model, mapping, review
  labels for findings, and the log of changes to expected values.
- `adapters/dss-runner/`: thin Java command line around EU DSS.
- `adapters/verapdf-runner/`: packages the veraPDF command line at a pinned version.
- `src/trustkit/`: PKI, fixtures, local revocation service, adapters, scoring, gates,
  report, CLI.
- `baselines/baseline.json`: the committed expected scored results.
- `tests/data/raw_outputs/`: captured output of an unrelated throw-away PDF.
- `docs/decisions.md`: corrections to the original brief and the choices made.
- `docs/limitations.md`: what these results do not show.
- `docs/related-work.md`: related projects and research.

## Commit order

1. Oracle: [`79b32c8`](https://github.com/korakod-dev/pdf-signature-trust-test-kit/commit/79b32c8)
   pre-registers the expected verdicts, and
   [`2ee992a`](https://github.com/korakod-dev/pdf-signature-trust-test-kit/commit/2ee992a)
   confirms the mapping against output from an unrelated throw-away PDF.
2. Generator, adapters and tests:
   [`ce6b4b4`](https://github.com/korakod-dev/pdf-signature-trust-test-kit/commit/ce6b4b4).
3. First real run:
   [CI run 41084416912](https://github.com/korakod-dev/pdf-signature-trust-test-kit/actions/runs/41084416912)
   on `ce6b4b4`, red at gate 4 because no baseline existed yet.
4. Baseline:
   [`1b241bc`](https://github.com/korakod-dev/pdf-signature-trust-test-kit/commit/1b241bc),
   which adds [`baselines/baseline.json`](baselines/baseline.json) and nothing else.

The first three commits reached GitHub in one push, so their relative order rests
on self-reported commit dates and on git ancestry. The first externally timestamped
event is the CI run on `ce6b4b4`.

### M2

The expected verdicts for N1, B2 and C1 to C5 are in `79b32c8`, and have not changed
since. Before step 3, the tools ran on throw-away PDFs that were built with the same
recipes and a separate PKI, so the kit's own fixtures were new to them but the
behavior was largely visible. See "How far the M2 samples go" in
[`docs/decisions.md`](docs/decisions.md).

1. DSS mapping: [`c0d9c36`](https://github.com/korakod-dev/pdf-signature-trust-test-kit/commit/c0d9c36).
2. Fixtures, DSS adapter and tests:
   [`03dc0b7`](https://github.com/korakod-dev/pdf-signature-trust-test-kit/commit/03dc0b7).
3. First real run:
   [CI run 41087912319](https://github.com/korakod-dev/pdf-signature-trust-test-kit/actions/runs/41087912319)
   on `03dc0b7`, red at gate 4 because the baseline was still for M1.
4. Review labels:
   [`68328dd`](https://github.com/korakod-dev/pdf-signature-trust-test-kit/commit/68328dd).
   Baseline:
   [`3809954`](https://github.com/korakod-dev/pdf-signature-trust-test-kit/commit/3809954),
   which changes [`baselines/baseline.json`](baselines/baseline.json) and nothing else.

### M3

The expected verdicts for A3, B3, B4, B5, D1, E1 and E2 are also in `79b32c8`, and have
not changed since. As in M2, the tools first ran on samples from the same recipes. See
"How far the M3 samples go" in [`docs/decisions.md`](docs/decisions.md).

1. Mapping: [`e745386`](https://github.com/korakod-dev/pdf-signature-trust-test-kit/commit/e745386).
2. Fixtures, revocation service and tests:
   [`7cc2844`](https://github.com/korakod-dev/pdf-signature-trust-test-kit/commit/7cc2844).
3. First real run:
   [CI run 41140005501](https://github.com/korakod-dev/pdf-signature-trust-test-kit/actions/runs/41140005501)
   on `7cc2844`, red at gate 2 (B5 on pdfsig not yet recorded) and gate 4 (baseline still
   for M2).
4. Review labels:
   [`8663307`](https://github.com/korakod-dev/pdf-signature-trust-test-kit/commit/8663307).
   Baseline:
   [`badf75a`](https://github.com/korakod-dev/pdf-signature-trust-test-kit/commit/badf75a),
   which changes [`baselines/baseline.json`](baselines/baseline.json) and nothing else.

### M4

The expected verdicts for F1, F2 and F3 are also in `79b32c8`, and have not changed since.
The mapping did not change for M4. As in M2 and M3, the tools first ran on samples from
the same recipes. See "How far the M4 samples go" in [`docs/decisions.md`](docs/decisions.md).

1. Fixtures, veraPDF check and tests:
   [`f8267eb`](https://github.com/korakod-dev/pdf-signature-trust-test-kit/commit/f8267eb).
2. First real run:
   [CI run 41142561948](https://github.com/korakod-dev/pdf-signature-trust-test-kit/actions/runs/41142561948)
   on `f8267eb`, red at gate 4 because the baseline was still for M3.
3. Review labels:
   [`abb96cf`](https://github.com/korakod-dev/pdf-signature-trust-test-kit/commit/abb96cf).
   Baseline:
   [`408785a`](https://github.com/korakod-dev/pdf-signature-trust-test-kit/commit/408785a),
   which changes [`baselines/baseline.json`](baselines/baseline.json) and nothing else.
