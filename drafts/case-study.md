# Case study: PDF Signature Trust Test Kit

> **DRAFT. Not published and not approved for publication.** Open items are marked
> `TODO`. Numbers come from CI run 41160827326 on commit `d86dbb8`, dated 2026-10-31.

## Problem

"The signature verifies" and "this document can be trusted" are different questions.
A validator can answer the first correctly and still leave the second open. A later
change can sit beside a passing signature, and a signed document can say something
false from the moment it is signed.

The kit is a regression test for how validators report these situations. For each
synthetic signed PDF, it records what each tool said, at which version, and under
which configuration.

It is not new vulnerability research, not a legal or compliance verdict, not an e-Tax
conformance test, and not a ranking of tools.

## Requirements

- Synthetic data and throw-away test keys only, with keys generated at run time and
  kept out of the repository.
- The expected verdict for each case is committed before any tool runs on that case's
  fixture.
- Several independent validators, whose output maps to one common verdict model.
- No live validation service and no public timestamp authority. TSA, CRL and OCSP run
  locally, and CI runs validators in a network namespace with no route.
- Every result states the tool version, the options, and the test date.

## Pre-set acceptance criteria

CI is red when any of these holds:

1. a fixture property test fails, or a file labeled PDF/A-3b fails veraPDF;
2. a tool is missing, a case was not run, or a `TOOL_ERROR` is not in the baseline;
3. any output is unmapped;
4. results differ from the committed baseline, better or worse;
5. a tracked file looks like key material.

CI is deliberately not red when a tool disagrees with the oracle. That is a result to
record, not a failure to fix.

## Test plan

| Group | Shown here | What it exercises |
|---|---|---|
| A | A1 to A3 | Signature integrity and coverage |
| B | B1 to B5 | Trust, expiry, revocation, and proof of time |
| N | N1 | Harness control with no signature |
| C | C1 to C5 | Changes after signing |
| D | D1 | Name on the page differs from the certificate subject |
| E | E1, E2 | Signature timestamps |
| F | F1, F3 | Simulated PDF/A-3b scenario with embedded synthetic XML |

Twenty cases were pre-registered and nineteen are shown. **One case is withheld from
public results.**

Validators under test: EU DSS 6.5.1 (Java 21.0.13, default policy), pdfsig (poppler
24.02.0, NSS 3.98), and pyHanko 0.38.0. veraPDF 1.28.2 is a precondition for files
labeled PDF/A-3b, not a validator under test. pyHanko also generates the fixtures, so
it is never the oracle.

**How strong the ordering is.** Expected verdicts were committed first and have not
changed. However, from M2 onward the tools ran on throw-away samples built with the
same recipes before the first real run, because a report format cannot be learned any
other way. That behavior was therefore largely visible when the mapping was written.
The mapping and some fixtures changed as a result, and the expected verdicts did not.

`TODO`: the evidence links for this ordering depend on how the repository is released.

## Defects found

These are defects and wrong assumptions in the kit, found by running it.

- **C2 fixture:** the form fill replaced the appearance dictionary, which a viewer
  filling a form would keep. The recipe was fixed.
- **DSS mapping too broad:** `ExtensionChange` counted as no modification, but the DSS
  sources show it also holds `/Metadata` and `/StructTreeRoot`. It now applies only
  under `/Catalog /DSS`. No result changed, and the other paths are covered by a unit
  test on an edited report, not by a fixture.
- **PDF/A output:** `/AFRelationship` raised the output version to 2.0, while PDF/A-3
  needs a 1.x header. pyHanko also replaced the `/Metadata` stream, which dropped the
  PDF/A identification. veraPDF found both.
- **`-no-ocsp` on poppler 24.02:** the brief said to pass this flag, but it stopped any
  good chain from being trusted. The flag is off, and isolation comes from the network
  namespace.
- **Default DSS policy:** without revocation data, every good chain was `INDETERMINATE`,
  which hid the results of later cases. Leaves now declare RFC 9608 `noRevAvail`, and a
  TSA without revocation data let E1 look fine while its timestamp had failed.

## Results

57 observations on 19 cases.

| Score | Count | Meaning |
|---|---:|---|
| `AGREE` | 35 | Matches the expected verdict |
| `PARTIAL` | 10 | Tool passes the signature and does not judge the change, or classifies it differently |
| `INFO` | 6 | Informational case, never counted as agreement or disagreement |
| `MISSED` | 3 | Expected rejection, tool accepted |
| `OVER_REJECTED` | 2 | Expected acceptance, tool rejected |
| `ERROR` | 1 | Output the mapping maps to `TOOL_ERROR` |

These counts describe the cases as a set, and they do not rank tools. A tool with more
`PARTIAL` results may simply have an output with no field for that judgment.

Results worth reading closely:

- **C4 and C5, visible content changed after signing.** DSS and pdfsig both report a
  passing signature. DSS adds visual difference and undefined change warnings under its
  default policy, and pdfsig reports `Not total document signed`. pyHanko reports
  `INVALID`. The information is there in all three, in very different places.
- **D1 and F3, misleading from the start.** The name on the page differs from the
  certificate subject in D1, and the XML disagrees with the visible page in F3. All three
  tools report `VALID`, and all three show the signer subject. The signature is correct,
  because it never made a claim about either.
- **B3, expired certificate with a trusted timestamp.** DSS reports `VALID`, while pdfsig
  and pyHanko report `INDETERMINATE`. pyHanko was run through `validate_pdf_signature`,
  not its LTV function, which may give another result.
- **B5, unreachable revocation source.** DSS reports `INDETERMINATE`. pyHanko reports
  `VALID` under its default soft-fail mode, which the kit keeps. pdfsig prints a generic
  message that the kit maps to `TOOL_ERROR`, because the message does not state the cause.
- **E2, untrusted timestamp.** The DSS result is labeled `oracle_disputed`: it reports
  the timestamp separately as `INDETERMINATE` and does not use it as proof of time. Our
  expected verdict may be the wrong one, so it stays visible.

## Takeaways

1. **A top-level result is not enough.** On C4 and C5, the useful information is in the
   warnings and coverage lines, not in the headline.
2. **No validator answers whether the document is honest.** D1 and F3 pass everywhere,
   and that is correct behavior for a signature check.
3. **Configuration is part of the result.** Revocation outcomes depend on fetch and
   soft-fail settings, so a result without its options says little.
4. **Pre-registering exposes the oracle too.** E2 shows that a disagreement can mean the
   expected value is arguable, which is why such a label stays public.
5. **Baselines should fail on improvements as well.** A silent change in either direction
   means that the tool or the kit changed.

## Limitations

- `TODO`: `spec_ref` is unset on every `spec` case. ISO 32000-2, ETSI EN 319 102-1 and
  ETSI EN 319 142 have not been read for this project, so these verdicts rest on a general
  understanding of the standards.
- Results apply to the listed versions on Ubuntu 24.04, and may not carry across versions.
- pyHanko is both the generator and a validator under test. pdfsig reads the same files,
  and property tests verify the signatures with `cryptography` alone.
- DSS accepts the leaves only because they declare `noRevAvail`.
- pyHanko and DSS run with fetching enabled, which is not their out-of-the-box setting.
- The TSA is pyHanko's `DummyTimeStamper`, a test class, not a separate TSA program.
- Fixtures use one signature type and one key type. C5 covers one Hide variant.
- Group F is a simulated scenario with an invented XML format, not an e-Tax conformance
  test. No Thai Revenue Department standard was read for this project.
- Files were not opened in a viewer, and commercial viewers are out of scope.

## Credits and links

- C5 is written from the published description of the Hide class in "Shadow Attacks:
  Hiding and Replacing Content in Signed PDFs" (NDSS 2021), and pdf-insecurity.org. Their
  exploit files are not used. `TODO`: add the authors' names from the paper.
- `TODO`: repository link, results page link, and license, once decided.
