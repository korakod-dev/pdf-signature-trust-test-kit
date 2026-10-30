# PDF Signature Trust Test Kit

"The signature verifies" and "this document can be trusted" are different
questions. This kit generates synthetic signed PDFs, commits the expected verdict
for each one before any tool runs on it, runs independent validators in CI, maps
their output to one verdict model, and records which tool produced which verdict.

It is not new vulnerability research, not a legal or compliance verdict, not an
e-Tax conformance test, and not a ranking of tools. It reports behavior per case,
tool version and configuration.

**Status:** milestone M1 (cases A1, A2 and B1, on pyHanko and pdfsig).

**License:** to be decided before public release.

## Evidence of ordering

The expected verdicts were committed before any tool ran on any fixture. See
[Commit order](#commit-order) for the commits.

## Run

Requires Python 3.12, [uv](https://docs.astral.sh/uv/), `poppler-utils` and
`libnss3-tools` (or any `pdfsig` and `certutil`).

```bash
uv sync --locked
uv run pytest
uv run trustkit run --milestone M1 --out out
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

1. a fixture property test fails;
2. a tool is missing, a case was not run, or a `TOOL_ERROR` is not recorded in the
   baseline;
3. any output is unmapped;
4. results differ from `baselines/baseline.json`, better or worse;
5. a tracked file looks like key material.

CI is not red merely because a tool disagrees with the oracle. That is a recorded
result.

## Where things are

- `oracle/`: expected verdicts, reference policy, verdict model, mapping, and the
  log of changes to expected values.
- `src/trustkit/`: PKI, fixtures, adapters, scoring, gates, report, CLI.
- `baselines/baseline.json`: the committed expected scored results.
- `tests/data/raw_outputs/`: captured output of an unrelated throw-away PDF.
- `docs/decisions.md`: corrections to the original brief and the choices made.
- `docs/limitations.md`: what these results do not show.
- `docs/related-work.md`: related projects and research.

## Commit order

Filled in once the baseline exists.
