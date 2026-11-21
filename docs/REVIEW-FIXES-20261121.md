# Review fixes — 2026-11-21

The source review produced seven concrete corrections. This is a targeted review
with software regressions, not a complete security audit of every platform or dependency.

| Issue | Change and regression |
| --- | --- |
| PQ Mail rejects a valid v6 PKESK with a v4 recipient fingerprint | Match the complete v4 fingerprint and select the correct session-key semantics. Reject wrong fingerprint, length, padding and payload integrity before returning plaintext; malformed recipient framing is rejected before invoking a private-key backend. Synthetic signed/encrypted tests cover Level 3 and Level 5, v3, v6-to-v4 and native v6. |
| Frontend treats every raw User ID as a trustable email | Required Sequoia public-policy inspection checks live self-certifications, primary expiry, and UID/certificate revocation. Preview, selection and persisted trust use validated email claims. Receive paths recheck the selected cached email/fingerprint. An email self-certification is still not independent evidence of mailbox ownership. |
| GnuPG rejects Ed25519/SHA-256 input | Accept a 32-byte classical signing digest consistently in the component, Python signing adapter and C helper. Keep profile-specific ML-DSA hash and 64-byte external-μ requirements. |
| Sequoia helper timeout misses blocked stdin or descendant-held pipes | One nonblocking supervisor covers input, both outputs, child exit and cleanup. Tests cover blocked input, retained pipes, output limits and descendant termination. |
| Failed Level 5 companion authentication leaves tentative plaintext unwiped | Allocate the AES-GCM output inside a Zeroizing owner before update/finalize so failure paths are covered as well as success. |
| GnuPG patch failure partially edits source | Validate all exact anchors before writing; stage replacements and backups, then roll back ordinary replacement failures. This is not power-loss atomicity across multiple files. |
| GnuPG captures unbounded child output | Live per-stream limits and bounded input/output/exit waits replace unbounded capture. Bridge and component use the same nonblocking supervisor; nested helper cleanup is tested. Python secret wiping remains best-effort. |

The shared adapter opt-in `PQMAIL_SUPERVISED_PROCESS_GROUP=1` is set by trusted
Sequoia/GnuPG supervisors. It keeps native helpers inside their already-isolated
POSIX process group so deadline cleanup reaches the whole chain. Standalone
adapter calls retain their own-session behavior. No persistent PIN cache is added.

## Validation and reproduction

On macOS, the installed jar passed these eight targeted suites:
`V4RecipientPacketTest`, `Rfc9980Test`, `Level5CompatibilityTest`, `OpenPgpTest`,
`VerifiedMimeTest`, `FormattedComposeTest`, `SafeMailHtmlTest` and `ChatBundleTest`.
The complete Java source tree compiled with the required Java 25.0.5.1 runtime.
To build and run the repository's full software suite with built dependencies:

```sh
./build.sh test
```

The targeted shared-adapter checks can also run separately:

```sh
python3 -m unittest discover -s tests -p 'test_pkcs11_mu.py' -v
python3 -m unittest discover -s tests -p 'test_supervised_process_group.py' -v
bash scripts/build-pkcs11-signer.sh
```

The shared signing suite ran 20 tests with one optional skip; the broader existing
PKCS#11 suite passed 29 with one skip. Three supervised-group tests passed. Native
software checks passed 45 signature-verification assertions, seven input-length
checks, PIN-callback tests and five KEM profiles. These suite counts overlap and
must not be summed as independent tests. The new native signer is bundled with
the Mac update; the existing cryptographic provider/module is retained.

The standalone project passed four native policy/identity tests and 39 Python
mail/Chat/browser tests; JavaScript syntax checks passed. Sequoia passed 31 tests
and rebuilt all seven adapter CLIs. GnuPG passed 24 connector tests and seven tests
against the mirrored software bridge. Patch preflight also passed on clean
GnuPG 2.5.23 and 2.5.24 trees. Each connector README documents its commands and
separate core/adapter dependencies.

No physical key was accessed during these fixes or regressions. Tests use
disposable software keys, fake backends/storage and mocked Google transports.
No keys, certificates, PIN/touch policies or account data were modified. The Mac
update was installed and reopened after deep/strict code-signature verification;
the provisioned Keychain helper was preserved byte-for-byte.

## Limits

Connector process supervision is implemented and tested on macOS/POSIX;
unsupported non-POSIX execution fails before launching a private operation.
This work did not create new Windows/Linux installers, install Android/iOS builds,
upgrade crypto/runtime dependencies or rerun hardware/mail interoperability.
GnuPG protocol/core extensions and its PIV adapter remain separate workstreams;
the adapter alone does not add unsupported OpenPGP algorithms to stock GnuPG.
Public source and synthetic test fixtures are published; machine-specific paths,
credentials, identity bundles and raw live-test artifacts are not.
