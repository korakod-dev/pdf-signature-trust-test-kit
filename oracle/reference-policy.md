# Reference policy

Every expected verdict in `cases.yaml` assumes this policy. It is the kit's own
test policy. It is not a legal or compliance verdict and not an e-Tax
conformance test.

## Trust anchor

Only the test root named by the case. Never the OS trust store.

## Acceptance

A document is acceptable only if all of these hold:

1. the signature is cryptographically valid;
2. the certificate chains to the trust anchor;
3. the certificate was valid at a time that can be proven: a trusted timestamp
   if present, otherwise the validation time;
4. the certificate is not revoked;
5. no disallowed change exists after signing.

## Oracle basis

Each case records one basis:

- `crypto`: provable by computation.
- `spec`: should follow a public standard. `spec_ref` names the clause once the
  text has been read, and stays `TODO` until then. No clause number is cited
  from memory.
- `policy`: our own judgment. The reasoning is written in `rationale`.

## Tool configuration

Tools run in their default configuration unless the case says otherwise. Any
non-default option is listed in the results. The options the harness always
needs in order to isolate trust and network access are listed per tool in
`mapping.yaml` and recorded on every observation.

## Independence

pyHanko generates the signed fixtures and also validates them, and its own
documentation says incremental update analysis is experimental. pyHanko is
therefore never the oracle. Fixture properties are asserted by tests that do
not call any validator.

## Changing an expected value

After the first real run, an expected value never changes silently. Every
change gets an entry in `changes.md`. A change to a `crypto` or `spec` case also
needs the owner's approval.
