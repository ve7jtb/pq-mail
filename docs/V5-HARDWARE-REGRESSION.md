# Optional Level 3 v5 interoperability — 2026-11-21

A staged PQ Mail development codec and the GnuPG PIV connector passed v5
signing and hybrid encryption/decryption with an existing Level 3 YubiKey 6 PIV
identity. The test used the existing PKCS#11 backend and a local v5 certificate
created from the already-provisioned keys. No hardware key generation, card
certificate replacement, bundle write, policy change or email send occurred.

## Observed results

| Operation | Confirmed result |
| --- | --- |
| GnuPG creates a local v5 certificate from existing component keys | PASS; self-certifications, public component bindings and the full v5 fingerprint were validated before message operations. |
| GnuPG v5 Ed25519/SHA-512 detached signature | PASS; independently verified by stock GnuPG and PQ Mail. |
| PQ Mail v5 Ed25519/SHA-512 detached signature, slot 88 | PASS; independently verified by stock GnuPG. The signing adapter was called once with one PIN prompt. |
| GnuPG decrypts PQ Mail's hybrid ciphertext | PASS; `DECRYPTION_OKAY`, `GOODMDC` and the exact 48-byte synthetic plaintext. |
| PQ Mail decrypts stock GnuPG's hybrid ciphertext | PASS; LibrePGP tag-20 OCB authentication and exact synthetic plaintext. One ML-KEM-768 call in 9d and one X25519 call in 85 shared one operation-scoped PIN prompt. |

The encrypted fixtures contain unsigned literal data. Detached signatures were
verified separately; this is not an inline-signed message or a live PGP/MIME
exchange. The signing algorithm is **classical Ed25519**, even though encryption
is **hybrid ML-KEM-768/X25519**.

The original run completed local certificate creation and GnuPG signing. The
corrected signing driver then produced the PQ Mail signature, and a final
resume completed both decryptions. Each resume rechecked the original public
fixtures, signature provenance, component bindings and fresh card snapshots;
it did not repeat completed signing operations. The final run publicly
reverified both signatures and passed both decryptions. No automatic private
operation retry occurs after an error.

## Format and application scope

This explicit compatibility codec supports a v5 Ed25519 certification/signing
primary and a bound LibrePGP algorithm-8 ML-KEM-768/X25519 encryption subkey.
It validates self-certifications and current key policy before use. Its v5
fingerprint framing, detached-signature hashing and KMAC-based combiner differ
from RFC 9580/9980 v6; it never interprets algorithm 8 as RFC 9980 algorithm 35.

Outgoing test ciphertext uses SEIPD v1 with MDC. Incoming stock-GnuPG ciphertext
uses LibrePGP tag 20 with AES-256/OCB and a final authentication tag. The
receiver consumes and authenticates the complete encrypted stream before
returning plaintext. Public recipient/framing errors fail before either
private component is requested.

**v6 remains the default identity profile.** This publication adds the optional
codec and reusable interoperability drivers. The physical result used an
explicitly selected staged development app jar; it does not mean that a new
Mac application was installed or released. Persistent v5 identity creation and
selection in the desktop interface, v5 inline signatures, and routing encrypted
v5 PGP/MIME through the normal inbox are not established by this test. Existing
v4/v6 regressions remain required.

The GnuPG core implementation and PIV adapter are separate components. The
adapter routes existing key components and does not add packet/algorithm
support to an otherwise incompatible stock GnuPG release. Stock GnuPG served
as an independent sender and signature verifier; the adapted development
GnuPG handled card-backed decryption.

## Key and policy preservation

All **24 ordinary PIV slots** matched the original audited baseline and the
final before/after snapshots: ten occupied slots (9c, 9d and 82–89), fourteen
empty slots. Comparison covered presence, full public-key SPKI SHA-256,
algorithm, origin, PIN policy and touch policy. The selected application jar,
Python adapters, native helpers, PKCS#11 provider and module also retained their
recorded hashes. This is evidence for those PIV keys/policies, not a comparison
of every object in other card applications.

Raw certificates, fingerprints, device serials, account identifiers, snapshots,
PINs and local result paths are excluded from this public report. Only the
sanitized result and reusable code are published.

## Reproduce with existing keys

Build the development app and the separate compatible GnuPG core/PIV adapter.
Use the [GnuPG v5 driver](https://github.com/ve7jtb/gnupg/blob/development/yubikey6-piv/pqmail/v5_test.py)
through its [hardware harness and setup instructions](https://github.com/ve7jtb/gnupg/blob/development/yubikey6-piv/README.PQMAIL.md).
Select an explicit device serial, backend path and fresh output directory;
the driver expects existing Ed25519 signing in 88, ML-KEM-768 in 9d and X25519
in 85. It does not create missing keys.

Compile the public Java drivers against the selected app's jar using the
patched Java runtime required by this repository:

```sh
export JAVA_HOME=/path/to/patched-jdk
APP_DIR="/path/to/development-app/Contents/app"
CLASSES="$PWD/build/tests/v5-interop"
./tests/hardware/build-v5-interop.sh "$APP_DIR" "$CLASSES" --self-test
```

Compilation and `--self-test` access no card and request no real PIN. The
subprocess regression verifies that signing results are decoded from Base64
while KEM results remain raw bytes; malformed/incorrect-length signatures are
rejected. Driver classes remain outside the selected app and do not replace
its classes. The receiver checks its executing codec jar and local signed-bundle
bindings before requesting a private operation.

Run the GnuPG harness's `--preflight-only` mode first. The full v5 run has five
logical PIN operations: local certificate creation, GnuPG signing, PQ Mail
signing and two decryptions. Enter PINs only in the hidden local Terminal
prompts and touch only when required by the existing key policy. Keep the
before/after reports. Stop on any failure and inspect the results and PIN retry
counter before retrying; do not reset or reprovision the card.

## Software regressions

The codec tests cover stock GnuPG certificate/signature parsing, exact plaintext
round trips, incoming tag-20 authentication, MDC/OCB corruption, a missing final
OCB tag, malformed key material and PKESKs, wrong recipients, and signature
tampering. Invalid public framing is checked before a private backend call.
Existing v4 compressed-signature and v4/v6 profile/policy regressions also pass.

The new codec and legacy-parser integration also compile against the existing
Android classes and API-37 SDK with Java 17 targeting. The Android shared-source
list now includes `LibreOpenPgp`. A wider three-class check including the current
`OpenPgp` fails against the cached Android classes on desktop-companion references
and older `Identity`/`ExternalMu` APIs; the pre-v5 baseline produces the same 13
diagnostics. This limited comparison does not establish the outcome of a fresh
full Android build. No full Gradle build, APK rebuild or Android v5 hardware/UI
test was performed for this publication.

`build-v5-interop.sh` also compiles `V5SoftwareFixture`, a test-only software
component that creates fresh Ed25519/X25519/ML-KEM-768 keys. It has no hardware,
account or production PKCS#11 path. The PKCS#12 aliases are `84` (Ed25519), `85`
(X25519) and `9d` (ML-KEM-768), with the deliberately **public test-only** password
`synthetic-fixture-password`. Never use these keys for real identities.

The [GnuPG fixture generator](https://github.com/ve7jtb/gnupg/blob/development/yubikey6-piv/pqmail/tests/generate_v5_fixture.py)
uses that software component and the prepared experimental GnuPG core to
create an explicit v5 certificate and detached signature. An independent stock
GnuPG verifies the signature and creates the tag-20 encrypted fixture. It selects a
short, isolated agent home, requests no interactive PIN and never uses the
normal GnuPG home. The prepared core requires the existing explicit v5
batch-version and raw Ed25519 component hooks; unmodified GnuPG may ignore the
batch version fields or use a different signing-component input. These are the
same core prerequisites as the hardware harness, not new changes made by the
fixture generator. Set explicit paths to that build, a stock peer with v5 and
algorithm-8 support, libgcrypt, the GnuPG connector checkout and the app/helper
paths compiled above:

```sh
FIXTURE="$PWD/build/tests/v5-fixture"
python3 "$GNUPG_CONNECTOR/pqmail/tests/generate_v5_fixture.py" \
  --out "$FIXTURE" \
  --gpg "$GPG_BUILD/g10/gpg" \
  --gpg-agent "$GPG_BUILD/agent/gpg-agent" \
  --gpg-connect-agent "$GPG_BUILD/tools/gpg-connect-agent" \
  --stock-gpg "$STOCK_GPG" \
  --libgcrypt /path/to/libgcrypt \
  --java "$JAVA_HOME/bin/java" \
  --helper-classes "$CLASSES" --app-dir "$APP_DIR"
"$JAVA_HOME/bin/java" -Djava.awt.headless=true -cp "$APP_DIR/*" \
  dev.hybridmail.LibreOpenPgpTest "$FIXTURE" "$FIXTURE/identity.p12" \
  "$PWD/build/tests/v5-codec-results"
```

Generation refuses an existing output directory. The fixture contains
`public-v5.pgp`, `detached.pgp`, `plain.txt`, `stock-encrypted.pgp` and the matching
disposable PKCS#12, plus public provenance and test logs. Keep generated private
fixtures out of source control. The hardware-driver `--self-test` above is
independent and needs neither stock GnuPG nor those fixture files.
