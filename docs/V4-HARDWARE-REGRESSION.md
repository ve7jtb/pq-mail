# Level 3 v4 hardware regression — 2026-11-21

The installed PQ Mail Mac build and GnuPG PIV connector passed the five-operation
follow-up to the [seven-fix review](REVIEW-FIXES-20261121.md). The test reused an
existing Level 3 YubiKey 6 PIV identity and the installed PKCS#11 backend. It did
not generate keys, change PIN/touch policies, replace certificates, write the
on-key bundle or send email.

## Observed results

| Operation | Result |
| --- | --- |
| v4 Ed25519/SHA-512 detached signature, slot 88 | PASS; stock GnuPG and installed PQ Mail independently verified it. |
| GnuPG decrypts PQ Mail ML-KEM-768/X25519 ciphertext | PASS; integrity check and exact 67-byte synthetic plaintext. |
| GnuPG decrypts fixed-GnuPG ML-KEM-768/X25519 ciphertext | PASS; integrity check and exact synthetic plaintext. |
| v4 Ed25519/SHA-256 detached signature, slot 88 | PASS; stock GnuPG and installed PQ Mail independently verified it, exercising the component, Python adapter and native helper's SHA-256 input handling. |
| Installed PQ Mail decrypts fixed-GnuPG ciphertext | PASS; v6 PKESK addressed to the full v4 recipient fingerprint, with SEIPD v1 integrity and exact plaintext. One ML-KEM-768 call in 9d and one X25519 call in 85 shared one PIN prompt. |

The encrypted fixtures contain no inline signature. Detached signatures were
verified separately; this run does not demonstrate an inline-signed PGP/MIME
message or a live mail exchange. The signing algorithm is classical Ed25519;
the encryption algorithm is hybrid ML-KEM-768/X25519.

The fixed sender includes the separately tracked [v4 fingerprint serialization
correction](https://github.com/ve7jtb/gnupg/tree/fix/v6-pkesk-v4-fingerprint-length).
The development GnuPG core and the PIV adapter are separate components; the
adapter does not itself add missing packet or algorithm support to stock GnuPG.
Stock GnuPG was used as an independent signature verifier.

## Key and policy preservation

The before, standard-harness after, and extended-harness after snapshots matched
for all **24 ordinary PIV slots**. Ten were occupied (9c, 9d and 82–89), and
fourteen were empty. Comparison covered slot presence, full public-key SPKI
SHA-256, algorithm, origin, PIN policy and touch policy. This confirms the
observed keys and policies were unchanged throughout the run. It is not a claim
about every object in the card's other applications.

Hashes of the installed application jar, Python adapters, native helper,
PKCS#11 provider and module matched the preflight, saved run and installed app.
The local evidence includes individual verification/decryption status, exact
plaintext comparisons, snapshots and backend hashes. Device serials, account
certificates, raw snapshots and private result directories are not published.

## Reproduce using an already-provisioned test identity

Use the [GnuPG five-test driver](https://github.com/ve7jtb/gnupg/blob/development/yubikey6-piv/pqmail/review_v4_test.py)
and its [setup instructions](https://github.com/ve7jtb/gnupg/blob/development/yubikey6-piv/README.PQMAIL.md).
It requires an explicit serial and output directory, a built compatible GnuPG
core/adapter, Sequoia's public-bundle restore and snapshot tools, and a selected
installed PQ Mail build. Review the selected paths and serial before starting.

Compile the two public Java drivers against that installed app, with the same
patched Java runtime required by the repository:

```sh
export JAVA_HOME=/path/to/patched-jdk
APP_DIR="/path/to/PQ Mail.app/Contents/app"
CLASSES="$PWD/build/tests/v4-interop"
./tests/hardware/build-v4-interop.sh "$APP_DIR" "$CLASSES" --self-test
```

Compilation and `--self-test` use disposable software fixtures, access no card
and request no PIN. The drivers are outside the application source tree and do
not replace application classes. The receive driver checks it is executing the
selected installed jar before a private operation. Its `--preflight` mode checks
local public files without signing or decryption.

Run the public GnuPG driver's preflight with your integration workspace and
already-provisioned card, then remove `--preflight-only` for the five-operation
run. Enter PINs only at the local hidden Terminal prompts and touch only if the
key's existing policy requires it. Never include PINs on the command line or in
saved logs. Stop on a failure and inspect the saved evidence before retrying.

The driver takes a fresh baseline, bounds helper execution, records backend
hashes before/after and takes a final key/policy snapshot even on a test failure.
It refuses an occupied result directory. Results are written locally; the
harness does not upload them or send mail. A failed or incomplete final snapshot
cannot establish that key policies were preserved.
