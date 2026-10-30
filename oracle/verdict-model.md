# Verdict model

"The signature verifies" and "this document can be trusted" are different
questions. The verdicts below keep them apart.

## Common verdicts

| Verdict | Meaning |
|---|---|
| `VALID` | Signature valid, trusted, no change after signing. |
| `VALID_WITH_ALLOWED_CHANGES` | Valid, with changes the tool classifies as permitted. |
| `VALID_WITH_UNCLASSIFIED_CHANGES` | Signature passes and the tool reports later changes or partial coverage, but does not judge them. |
| `INVALID` | Broken signature, disallowed change, or revoked certificate. |
| `INDETERMINATE` | Cryptographic check not failed, but evidence is insufficient (unknown root, expired with no proof of time, unavailable revocation). |
| `NO_SIGNATURE` | No signature in the file. |
| `UNSUPPORTED` | The tool does not assess this aspect. |
| `TOOL_ERROR` | Crash, unparseable output, or any output not in the mapping table. |

Unmapped output never defaults to another verdict. It is `TOOL_ERROR` and turns
CI red (gate 3) until the mapping is reviewed.

## Observation record

Each observation stores: raw output, exit code, tool version, command or API
options, fixture SHA-256, and signals (coverage, modification level, warnings,
sub-indication, signer subject shown or not).

## Scoring

Accept class = {`VALID`, `VALID_WITH_ALLOWED_CHANGES`}.
Reject class = {`INVALID`, `INDETERMINATE`}.

Rules apply in this order, first match wins:

1. Case marked informational -> `INFO` (reported, never counted).
2. `TOOL_ERROR` -> `ERROR`.
3. `UNSUPPORTED` -> `NOT_ASSESSED`.
4. Observed equals expected or is in `acceptable` -> `AGREE`.
5. Observed is `VALID_WITH_UNCLASSIFIED_CHANGES` -> `PARTIAL`.
6. Expected reject class, observed accept class -> `MISSED`.
7. Expected accept class, observed reject class -> `OVER_REJECTED`.
8. Both reject class but different -> `REJECTED_DIFFERENTLY`.
9. Both accept class but different -> `PARTIAL`.
10. Anything else -> `MISMATCH`.

## Review labels

A `MISSED` or `PARTIAL` result is a finding, not automatically a bug. Each one
is reviewed and labeled `documented_behavior`, `possible_bug`,
`oracle_disputed`, or `not_reviewed`.

Repository text does not call any result a vulnerability. A result that looks
like one stops work on that finding and goes privately to the owner.
