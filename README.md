# PQ Mail

<img src="assets/pq-mail.png" alt="PQ Mail: PQ shield, lime envelope and YubiKey on a dark teal background" width="160" />

PQ Mail is an experimental post-quantum mail application supporting **S/MIME and OpenPGP on macOS, Windows, Linux, Android and iOS**. Desktop and Android use **Jakarta Mail, Eclipse Angus Mail, and Bouncy Castle**; the SwiftUI iOS preview uses **OpenSSL**. Desktop token operations use bundled **PKCS#11** adapters; Android uses **YubiKit 3.3.0** directly. It supports software identities and keys generated and used on a PQC Ready YubiKey. Formerly **Hybrid Mail**, the project now lives at [ve7jtb/pq-mail](https://github.com/ve7jtb/pq-mail).

New on-key certificate backups use lossless compression on desktop, Android and iOS. Existing uncompressed banks are read only for migration; signatures and fingerprints are unchanged. See [compressed storage and platform limits](docs/ON-KEY-CERTIFICATES.md#compressed-on-key-storage).

The desktop/Sequoia development build also supports a **Level 5 encrypted software companion**: new Ed448/X448 components are wrapped through the existing P-384 slot 82 while ML-DSA-87 and ML-KEM-1024 remain on the YubiKey. A physical test on November 21, 2026 passed fresh compressed restore, signing and decryption in both implementations, preserving all existing keys and touch policies. Lossless compression reduced the companion from 46,412 to 39,163 bytes and increased actual free card storage from 18.0 to 25.8 KiB. Software components are exposed in host memory during use; this is not native hardware custody. See [format, tests and security tradeoffs](docs/LEVEL5-COMPANION.md). This companion path is not yet an Android/iOS feature; an optional **ultra-compact** mode now stores authenticated certificate templates and reconstructs self-signatures once on a new host, then verifies and caches only the public certificate. Full storage remains the default. Ultra-compact conversion, interrupted-write recovery and Java/Sequoia interoperability are tested in software; its physical-card conversion test is still pending. Third-party certifications and unsupported certificate structures require full storage.


The [Independent Submission draft](docs/internet-drafts/draft-bradley-pqmail-certificate-bundle-00.md) specifies the current single-bank public bundle and encrypted companion formats, with [rendered HTML](https://ve7jtb.github.io/pq-mail/spec/draft-bradley-pqmail-certificate-bundle-00.html) and an [xml2rfc/idnits validation report](docs/internet-drafts/validation-report.md). Its proposed future slot layout is separate from the implemented mapping; other smart cards need their own supported mapping and storage binding.

The desktop/Sequoia development build also implements a [Level 3 software-PQ companion](docs/LEVEL3-POLYFILL.md) for classical-only cards: hardware Ed25519 certification/signing in 82/9c and X25519 decryption in 9d require PIN and touch; dedicated P-384 wrapping in 83 requires PIN without touch. The encrypted, empty-password .p12 holds separate ML-DSA-65 certification/signing seeds and an ML-KEM-768 seed. Normal operations need one hardware touch. Desktop creation/recovery/restore and PGP/MIME tests pass. Physical tests on YubiKey 5.8 **40814807** on November 21, 2026 passed hybrid signing/decryption in both implementations, verification in both directions and byte-identical on-key restore. The companion occupies **34,630 bytes**, and all keys and PIN/touch policies were unchanged during the successful test run. This v6 OpenPGP-only profile provides classical protection at rest and exposes software PQ keys in host memory during use. It does not create S/MIME/v4 identities or change the existing Level 3 hardware profile.

## Review fixes and regression results — 2026-11-21

A coordinated review corrected seven issues across PQ Mail, the standalone
[gws–Sequoia frontend](https://github.com/ve7jtb/gws-sequoia-chat), the
[Sequoia PIV connector](https://github.com/ve7jtb/sequoia/tree/development/yubikey6-piv/piv-adapter)
and the [GnuPG connector](https://github.com/ve7jtb/gnupg/tree/development/yubikey6-piv/pqmail).

- PQ Mail now accepts a v6 PKESK addressed to a v4 hybrid recipient, checking the
  complete fingerprint and packet framing before private operations. Level 3 and
  Level 5 regressions preserve existing v3 and native-v6 behavior.
- The standalone frontend offers only current, policy-validated self-certified
  email addresses for trust and rechecks cached contact bindings before opening
  Chat or mail messages.
- Ed25519/SHA-256 works through the GnuPG component, shared Python adapter and
  native signing helper. ML-DSA external-μ requirements remain unchanged.
- Sequoia and GnuPG enforce bounded input/output and deadlines across the helper
  chain; nested PKCS#11 helpers remain in the supervisor's cleanup group.
- Failed Level 5 companion authentication wipes tentative plaintext. GnuPG patch
  application preflights all source anchors and rolls back ordinary write failures.

Validation used disposable software keys and mocked transports: **eight packaged
PQ Mail Java suites**, **four frontend Rust tests**, **39 frontend Python tests**,
**31 Sequoia tests**, **24 GnuPG connector tests** and **seven mirrored bridge
tests** passed. Shared-adapter and native signing/KEM regressions also passed,
with one optional Python test skipped. Suite counts overlap. The installed Mac
update passed deep/strict code-signature verification; its provisioned Keychain
helper was retained unchanged. These checks performed no hardware or live-account
operations and changed no keys, certificates or touch policies. See the
[seven-fix report and test commands](docs/REVIEW-FIXES-20261121.md) for scope,
platform limitations and reproducible checks.

## Experimental Google Chat

The desktop app can connect to Google Chat, browse conversations, and send or open signed and optionally encrypted OpenPGP bundles. Enable **Experimental Google Chat** in Settings → Mail accounts, select the separate Desktop OAuth client bundled with your build, then use **Google Chat → Sign in or reconnect**. The feature remains off by default. A dedicated development Google Cloud project keeps Chat consent separate from Gmail; it requests `chat.spaces.readonly`, `chat.messages.readonly` and `chat.messages.create`, plus basic account email identification.

For your own source build, download the Desktop client JSON from your separate Chat project and set `PQ_MAIL_CHAT_CLIENT_JSON=/absolute/path/to/client.json` when running `./build.sh`. The build script packages only client registration metadata, never user tokens. No Chat client JSON is committed; entering only a client ID in Settings does not replace the bundled configuration.

Chat OAuth refresh tokens are stored exclusively in the **PRF-encrypted vault**, bound to the account and client. Unlock the vault to connect; access tokens stay in memory and are cleared on lock. There is no plaintext or Keychain fallback for Chat. Pin a hybrid v6 OpenPGP identity whose certified email matches the Chat account. Recipient selection shows saved certificates and trust bound to the email and full primary fingerprint; encryption requires a trusted hybrid v6 recipient or the pinned self identity.

In **Google Chat → Send bundle**, the subject has its own full-width field labeled **Subject (inside encrypted bundle)**. It is inside the protected payload, not the visible Chat caption. Turning encryption off changes the label to **Subject (inside signed bundle)** and explains that the subject is readable.

Each bundle uses two linked Chat messages: one public `pq-mail-sender-key.pgp` certificate, followed by one `message.pgp` payload referencing it. Google rejects multiple non-media attachments in a single message. The receiver checks that the certificate reference stays in the same conversation and has the same Google sender, then verifies the OpenPGP signature separately. Receiving a certificate never automatically saves or trusts it. Google and conversation members can see the public certificate and transport metadata; signed From, To, Subject, body and files are inside the bundle and encrypted when encryption is selected. Verified HTML is rendered locally without remote images or active content.

### Successful two-way encrypted Google Chat test — 2026-11-20

A live test exchanged synthetic messages between a personal Gmail account in the installed Mac app and a separate Workspace account using the independent [gws + Sequoia CLI](https://github.com/ve7jtb/gws-sequoia-chat). PQ Mail used a YubiKey 6 PIV Level 3 identity through PKCS#11; the standalone side used password-encrypted software OpenPGP keys and separate Google authorization.

| Direction | Confirmed result |
| --- | --- |
| Standalone gws + Sequoia → PQ Mail | YubiKey decryption succeeded; the hybrid signature verified against the trusted sender certificate; the formatted HTML body displayed correctly. |
| PQ Mail → standalone gws + Sequoia | The encrypted bundle and linked public certificate downloaded successfully; Sequoia decrypted and verified the expected signer. Signed sender, recipient, subject and recovered body matched. |

Both directions used **ML-DSA-65 + Ed25519 signatures** and **ML-KEM-768 + X25519 encryption**. The return certificate matched an independently selected local certificate. These tests reused existing keys and policies. This is evidence for these accounts and this Level 3 setup, not universal personal-Gmail eligibility, Level 5 hardware Chat, or a group encryption test. Account identifiers, message IDs, certificates, private keys, OAuth configuration and raw test artifacts remain local.

The portable core also passed earlier **software-only Level 3 and Level 5 Sequoia tests** for signed/encrypted ZIP/ZLIB bundles, text/HTML alternatives and binary attachments. See [format, limits and reproducible tests](docs/CHAT-BUNDLES.md). Android has the portable bundle core; the live Chat connector and UI described here are desktop features.

## Desktop mail workflow

The desktop app opens on **Connect your email**, using the same teal, lime and pale background as Android. Choose **Sign in or reconnect** for Gmail, Hotmail / Outlook, or another IMAP provider. A saved OAuth session is restored when available; first-time users sign in. If reconnection fails, the app offers an explicit sign-in option instead of automatically reopening the browser. The loading indicator explains when access to the Google/Microsoft OAuth refresh token or saved IMAP settings needs passkey-vault or authenticated Mac Keychain approval. Startup does not automatically unlock a software identity or restore a mail session.

A successful connection opens **Inbox**. The sidebar provides **Compose**, **Inbox**, **Read message**, **Switch account** and **Lock vault**. **Settings** contains mail accounts and advanced OAuth configuration, Keys/passkey vault, Certificates/trust and OpenPGP. Offline identity management remains available before connecting.

The inbox toolbar has **Search**, **Clear search**, **Refresh**, **Newer / Older** and a page indicator:

- **Gmail:** server-side search within INBOX, including operators such as `from:` and `subject:`; 50 messages per page. The **Signed or encrypted only** filter covers S/MIME and OpenPGP and inspects the current page's MIME headers, so a filtered page may be empty while Older remains available.
- **Hotmail / Outlook:** server-side subject search within the inbox; 50 messages per page.
- **IMAP:** server-side sender-or-subject search and 10-message pages. If the mailbox changes while paging, refresh to establish a new page sequence.

Headers and search results remain in memory; message bodies are fetched only when opened. Opening continues through PQ Mail's existing decryption and signature-verification flow. Search does not mark messages trusted or send mail. Automated checks cover all three provider searches, paging/clear/empty results, query escaping, header-only reads and navigation with synthetic data; this update does not claim a fresh live-account test.

The desktop shows a large animated teal-and-lime spinner over the mail area
while connecting, refreshing, searching, or paging. Its text identifies the
current operation, including credential unlock when needed, and it clears on
success or failure. PIN and passkey prompts remain separate dialogs.

### Safe HTML reading and simple formatting

Desktop **Read message** offers **Formatted HTML** and **Plain text**. It renders a small local subset (headings, emphasis, lists, tables, quotes and links). Signature verification uses the original MIME bytes before display processing. The app's verification, trust and sender information stays in a separate panel above the message body. Unsigned mail remains explicitly unverified.

The viewer removes sender CSS, JavaScript, forms, frames and other active content. It loads no images, including remote tracking images and embedded `cid:` images, and no external styles or fonts. Images become placeholders; complex layouts may simplify. Clicking an HTTP/HTTPS link shows the actual destination and requires confirmation before opening the external browser. Oversized HTML falls back to plain text. Rendering does not save message content to disk.

In **Compose**, enable **Use formatting** for bold, italic, underline, headings, bulleted/numbered lists and website links. Clipboard content is pasted as text. Formatted S/MIME and PGP/MIME messages include both UTF-8 plain text and HTML inside the signed MIME entity, and inside encryption when enabled. Switching back to plain text asks before discarding formatting. Outgoing file attachments remain S/MIME-only.

Regression tests cover local rendering with zero resource requests, unsafe links/active markup, document clearing, original-MIME tamper rejection, and signed/encrypted round trips retaining both MIME alternatives and S/MIME attachments. These are synthetic software tests, not a new live Gmail/Proton interoperability result.

### Gmail OpenPGP interoperability

A two-way live Gmail test on November 20, 2026 passed between PQ Mail's Level 3
YubiKey identity and the standalone [gws + Sequoia app](https://github.com/ve7jtb/gws-sequoia-chat)
using an existing software identity. Both sides decrypted and verified hybrid
ML-DSA-65 + Ed25519 signatures with ML-KEM-768 + X25519 encryption. Existing keys
and touch policies were unchanged.

Gmail rewrote the outbound `multipart/encrypted` envelope into `multipart/mixed`
while retaining the ciphertext. The reader now recognizes only the observed
unambiguous two-part structure: a PGP version-control part and a single armored
ciphertext part. Additional parts, surrounding text and multiple armor blocks
are rejected. Only decrypted, signature-verified inner content is displayed;
outer mail headers remain unauthenticated. The metadata-only inbox filter cannot
identify this rewritten format, and Gmail classified the synthetic test as Spam;
the diagnostic read it by exact Message-ID without moving it or changing labels.


## Demonstration videos

[Watch the Google OAuth and post-quantum S/MIME demonstration](https://youtu.be/RGiaAeGTCmc) (3:20). The desktop demo shows Gmail read/send consent, a YubiKey-signed message, and a signed-and-encrypted message decrypted locally with the YubiKey. It uses ML-DSA-87 + ECDSA P-384 signatures and ML-KEM-1024 + ECDH P-384 encryption. PIN prompts are included with their fields masked; unrelated inbox content and pauses are removed. Recorded November 17, 2026 using synthetic messages sent to the same account. The video is unlisted on YouTube and accessible through this link.

[Watch the Android Google OAuth and S/MIME demonstration](https://youtube.com/shorts/NPNeXnc8ozU) (1:30). Recorded on a Pixel 10 on November 19, 2026, this companion video shows Gmail read/send consent, sending a synthetic signed-and-encrypted message to the same account, and reading it with successful local YubiKey decryption and hybrid signature verification. Pauses are trimmed and unrelated inbox rows are covered with opaque masks. PIN/password screens are capture-protected and appear black. Both demonstration videos are unlisted and accessible through their links.

## On-key certificates and migration

Use **Keys → Back up certificate bundle to YubiKey…** to carry the pure/hybrid S/MIME
certificates, existing OpenPGP public identity and serial/slot mappings with the
key. **Restore certificate bundle from YubiKey…** verifies the bundle and actual public
keys, then asks for review; it does not grant trust. Android and iOS expose the
same backup/restore actions in their identity screens.

New provisioning uses ECDSA slot **83**, leaving 9a available for authentication.
The migration action has been removed from the interfaces now that the test keys
have been migrated. Saved slot mappings and bundle recovery remain supported.
Public storage
contains no PINs, private keys, passwords or Google OAuth refresh tokens.

See [on-key format, workflows and recovery](docs/ON-KEY-CERTIFICATES.md).
**Hardware validation (November 18, 2026):** A YubiKey 6.0.0 Beta0 passed the following tests:

- **On-key bundle:** macOS saved a 24,434-byte signed bundle containing the existing Level 3 pure/hybrid signing and encryption certificates and serial/slot mappings. Read-back through a new PC/SC connection, clean-profile import, restart and duplicate import passed. No private keys were imported and no certificate trust was granted automatically.
- **Slot migration:** the existing P-384 signing key moved from **9a to empty 83**, retaining its public key and PIN Always / Touch Never policies. Slot 9a became empty. Before/after snapshots confirmed all PIV certificates and other keys' public metadata were unchanged. Desktop mappings were updated, and hybrid signing verified the refreshed bundle using slot 83.
- **Android NFC import:** Pixel 10 read the refreshed bundle directly from the key and updated both existing Level 3 identities to **9c / 83 / 9d / 82** (ML-DSA signing / ECDSA signing / ML-KEM decryption / ECDH decryption).
- **NFC S/MIME round trips:** Pixel 10 passed pure **ML-DSA-65 / ML-KEM-768** and hybrid **MLDSA65-ECDSA-P384-SHA512 / MLKEM768-ECDH-P384-SHA3-256** signing and decryption with the imported certificates. Hybrid signing used the saved slot 83 mapping and its composite signature verified. No email was sent.

One pre-PIN NFC retry occurred during hybrid decryption: the public-metadata read
`F7 P2=9C` failed with an IOException after 305 ms; a fresh tap recovered and the
round trip passed. The same trace successfully read slot 83 (`SW=9000`, 28 ms).
These successful tests do not establish that the Pixel 10's intermittent NFC
transport issue is resolved. No saved OpenPGP identity was present in this bundle,
so this hardware run did not validate OpenPGP bundle transfer. Physical iOS bundle
testing remains pending.

Use **Keys → Forget YubiKey identity…** to remove one local YubiKey profile, its certificates, slot mappings and saved OpenPGP identity. Other profiles and contact trust remain unchanged. This does not connect to or erase the YubiKey; on-key bundles remain available for reimport.

## Android preview

**Level 5 software OpenPGP:** The Android PRF-vault preview creates RFC 9980 v6 ML-DSA-87 + Ed448 certification/signing keys and ML-KEM-1024 + X448 encryption, plus P-521-signed v4 compatibility certificates with ML-KEM-768 + X25519 preferred encryption and P-521 classical fallback. Private keys and exact certificates travel in the vault-protected `.p12`; portable exports use a separate user password. See [software profiles and upgrade flow](android/README.md#level-5-software-openpgp). YubiKey profiles are unchanged.

**Mail-first Android interface:** Start by selecting Gmail, Hotmail/Outlook.com, or another IMAP/SMTP provider and signing in or reconnecting. The inbox has sender/subject cards, Search, Newer/Older paging, Refresh and Compose. Identities, certificates, account options and file tools are under **Settings**. Dark teal headers and lime controls match the app icon; a fixed loading banner stays visible during connection, search, refresh and paging. Compose guides users to identity selection when needed, then offers review and confirmed sending; exporting an `.eml` is optional.

**Live Pixel 10 inbox checks (November 19, 2026):** Gmail and Hotmail both passed reconnect, subject search with matching and empty results, opening a signed synthetic message through its inbox card, visible signature verification and sender/certificate matching, and clearing search back to page 1. Gmail verified **ML-DSA-87 + ECDSA P-384**; Hotmail verified **ML-DSA-65**. Older/Newer passed for both: Gmail used a diagnostic-only two-message page because the inbox fit on one normal page, then restored the normal size; Hotmail used normal 50-message pages. No messages were sent, trust changed, or message contents/OAuth tokens written to the test reports. These checks validate signed-message reading, not a new encrypted-send hardware test.

Gmail supports Gmail search syntax and an optional S/MIME-only filter. Hotmail uses Microsoft Graph with subject-text search; its PRF-vault preview uses AppAuth browser authorization and encrypted refresh-token restoration. Manual IMAP uses 20-message pages and sender/subject search. Ordinary unsigned text/HTML mail is shown as text with an unverified-sender label; remote HTML resources are not loaded. Mail headers and opened bodies remain in memory unless explicitly exported.

**Android-to-desktop Gmail interoperability (November 19, 2026):** On a Pixel 10, PQ Mail signed a synthetic message with a Level 5 YubiKey identity (ML-DSA-87 + ECDSA P-384), encrypted it for ML-KEM-1024 + ECDH P-384, and sent it to the same account through the Gmail API. Desktop PQ Mail received it through Gmail, decrypted it using the matching YubiKey, and displayed **SIGNATURE VALID** with the synthetic body. The signer fingerprint matched the Android certificate and the outer From address matched its email. The signer remained untrusted: cryptographic verification did not grant trust. No keys or touch policies were changed. This validates this S/MIME path; it is not an OpenPGP or all-transport hardware claim.


An [Android version](android/README.md) uses **YubiKit 3.3.0 directly over USB and NFC**, with the same three software `.p12`, pure PQ, and hybrid profiles. It includes local S/MIME, Gmail API and Microsoft Graph read/send with OAuth, IMAPS/SMTP for other hosts, and public-only YubiKey identities. See the Android guide for build instructions, hardware testing, and preview limitations; token provisioning remains a desktop feature.

## iOS development preview

The [native SwiftUI iOS preview](ios/README.md) uses **OpenSSL 3.5 LTS (patched 3.5.10-dev snapshot)** for Level 2/3/5 pure and hybrid S/MIME, persistent password-protected `.p12` identities, and public YubiKey credential bundles. **OpenPGP is an alternative for Level 3 hybrid identities**, using draft-05 ML-DSA-65 + P-384 / ML-KEM-768 + P-384 profiles, separate OpenPGP public identities and PGP/MIME. Both formats share software primitives and the YubiKit NFC/USB-C raw PIV backend. Tests cover published OpenPGP vectors, simulator round trips, simulated hardware operations, and desktop S/MIME/PKCS#12 interoperability. **Physical iPhone YubiKey testing remains pending.** This local-file preview has no mail accounts/sending or attachments yet; see the iOS README for supported formats and limitations.

## OpenPGP profiles

Select **OpenPGP** in Compose with a supported hybrid identity:

| Selected identity | OpenPGP signing / encryption | Platforms |
|---|---|---|
| Level 3 hybrid | ML-DSA-65 + P-384 / ML-KEM-768 + P-384 (experimental draft-05) | Desktop, Android, iOS |
| Level 3 + extra YubiKey keys | ML-DSA-65 + Ed25519 / ML-KEM-768 + X25519 (RFC 9980) | Desktop and Android |
| Existing Level 5 classical OpenPGP | Receive/verify/decrypt only; outgoing signing disabled | Desktop and Android |
| Imported v4 classical certificate | Verify incoming signatures; encrypt to a valid recipient subkey | Desktop and Android |

Existing Level 5 OpenPGP reuses the classical keys in slots **83/82** for new YubiKey identities; its pure/hybrid S/MIME profiles remain unchanged. Pure-only and Level 2 identities do not support OpenPGP. Public OpenPGP identities have separate fingerprints from X.509 certificates. Create/import the same `.asc` identity on other installations, or restore it through a supported on-key bundle, to preserve those fingerprints.

Desktop outgoing OpenPGP uses v6 hybrid signatures by default. For a selected v4 recipient only, the RFC 9980 YubiKey identity uses Ed25519 compatibility signing after confirmation; it attaches both v4 and v6 public certificates. New Level 3 identities use the dedicated Ed25519/X25519 compatibility keys in slots 88/89; slots 84/85 remain exclusive hybrid components. Android retains hybrid-only outgoing signing. In desktop **Compose**, selecting OpenPGP looks up the complete **To** email address on **keys.openpgp.org** after a short typing delay. Android Compose provides the same lookup and recipient-key selection. Imported keys remain usable without a keyserver lookup. Encryption is enabled only for a matching, usable recipient certificate; its encryption choices come from that certificate, not the sender’s S/MIME profile. Changing To clears the selected recipient and turns encryption off. Lookup results never confer trust; review the fingerprint.

V4 compatibility verifies RSA (2048+), ECDSA and legacy Ed25519 signatures with SHA-2, validates self-certifications and signing-subkey cross-certifications, and rejects revoked/expired keys and unsupported critical metadata. Encryption uses a current bound RSA/ECDH subkey, AES and integrity-protected v1 SEIPD with v3 PKESK. Desktop v4 compatibility messages use Ed25519 signatures, which are classical. V4 encryption can be hybrid when a valid algorithm-35 subkey is present; otherwise it is classical and requires confirmation. SHA-1 is used only for the mandated v4 fingerprint/MDC formats, not accepted for document or certification signatures.

Signed and optionally encrypted PGP/MIME is supported. The desktop reader verifies signatures before extracting plain text or HTML from multipart bodies; desktop HTML is rendered through a restricted local formatting subset without loading remote content. Outgoing desktop OpenPGP supports plain text or signed plain-text/HTML alternatives; compatibility messages include the full v4, classical-only v4, and v6 public-key attachments automatically. User-added file attachments remain S/MIME-only. New supported YubiKey credentials default to creating an OpenPGP identity, with an opt-out. See the [OpenPGP guide](docs/OPENPGP.md) for setup, profile distinctions and validation limits.


### Sequoia OpenPGP v6 interoperability

Local tests against **Sequoia sq 1.5.0 / sequoia-openpgp 2.4.1** passed detached-signature verification and signed/encrypted payload exchange **in both directions**, using ML-DSA-65 + Ed25519 signing and ML-KEM-768 + X25519 encryption. These tests used disposable software keys; they were not a new YubiKey hardware or mail-delivery test.

PQ Mail now accepts the tested Sequoia v6 certificate structure: multiple certified email addresses, a certification-only primary, a separate cross-certified signing subkey, an authentication subkey, and an encryption subkey. It supports default encrypted-message padding and the RFC 9580 implicit AES-128/OCB preference. Tests reject modified content, unbound subkeys and revoked primary keys. Importing still does not grant trust. Existing PQ Mail v6 certificates remain compatible; no regeneration or fingerprint change is required. See [OpenPGP details](docs/OPENPGP.md) and the public fixtures in `tests/fixtures/sequoia`.

### Proton Mail PGP/MIME interoperability — November 18, 2026

The desktop reader successfully displayed and verified a real message sent from
Proton Mail using a **classical OpenPGP v4 signature**. Multipart/HTML content is
shown as text in that test, without fetching remote images or executing HTML. The message was
**not encrypted**; the classical, non-post-quantum warning remained visible.

A second test used the installed desktop reader with **empty temporary contacts,
no selected signer and no local identity**. It discovered Proton's attached public
certificate, verified the signature and displayed the message as **NOT TRUSTED**.
Both the in-memory and reloaded contact stores remained empty, and no trust was
granted. Existing user contacts were unchanged; message MIME stayed in memory.

Attached certificates are verification candidates, not proof of sender identity.
**Save sender OpenPGP certificate…** explicitly saves a contact without granting
trust. **Trust signer fingerprint…** is a separate review that scopes trust to
selected certified email addresses and the full primary-key fingerprint. Invalid
certificate bindings and altered signatures are rejected. Certificates contained
inside encrypted payloads still require an available sender key before opening.

**Hybrid interoperability did not pass:** Proton Mail web version **5.0.142.3**
rejected our RFC 9980 v6 contact certificate with “Version 6 keys are currently not
supported.” Consequently, Proton verification of our hybrid signatures and Proton
encryption to our hybrid KEM remain untested. The successful inbound v4 test does
not establish v6 or post-quantum interoperability.

## Platform capabilities

| Capability | Desktop (macOS / Windows / Linux) | Android preview | iOS preview |
|---|---|---|---|
| Software `.p12`, Level 2/3/5 pure/hybrid S/MIME | Yes | Yes | Yes |
| Level 3 hybrid OpenPGP | Yes | Yes | Yes |
| Level 5 classical P-384 OpenPGP | Yes | Yes | Not yet |
| Forget a local YubiKey identity | Yes | Yes | Not yet |
| YubiKey private-key backend | Bundled PKCS#11 | YubiKit USB/NFC | YubiKit raw PIV NFC/USB-C; physical testing pending |
| Generate four keys on an empty YubiKey | Yes | Use existing keys | Use existing keys |
| Local signed/encrypted `.eml` files | Yes | Yes | Yes |
| S/MIME attachments | Yes | Yes | Not yet |
| Conventional RSA/ECDSA S/MIME | Yes | Yes | Not yet |
| IMAPS inbox / SMTP | Yes | Yes | Not yet |
| Gmail API / Google OAuth | Yes | Yes | Not yet |
| Microsoft Graph / Hotmail OAuth | Yes | Yes | Not yet |
| Persistent certificate trust | Yes | Yes | Verification only; no automatic trust |

Level 3 OpenPGP validation includes published draft vectors, desktop/Android adapter tests, Swift tests and bidirectional Java/OpenSSL message exchange. Level 5 classical validation includes software/simulated-token round trips, Android instrumentation, and independent Bouncy Castle signature verification and bidirectional ECDH/v2-SEIPD exchange. A Level 3 hybrid OpenPGP USB round trip was reported successful by the tester; unlike the saved S/MIME tests, that manual flow did not persist a hardware report. Physical OpenPGP NFC and Windows runtime testing remain pending. Existing S/MIME hardware test results do not constitute OpenPGP hardware validation.

## Desktop features

- Compose signed messages with attachments, optionally encrypt them, and save/open `.eml` files.
- For other hosts, send through SMTP with STARTTLS and show the **10 most recent inbox messages** through read-only IMAP over TLS. Gmail uses its API with 50-message pages and an optional S/MIME-only filter.
- Sign in to Gmail with Google Desktop OAuth, including PKCE and a loopback callback, requesting only Gmail API read-only and send scopes. Protect persistent account secrets with the **PRF passkey vault**, or retain authenticated **macOS Keychain** protection for the Google OAuth refresh token.
- Select the outgoing signing identity and recipient encryption certificate independently.
- Manage signing and encryption certificates, inspect SHA-256 fingerprints, export PEM/DER, and explicitly mark certificates trusted. Successfully verified incoming signers can be added to the trust store.
- Keep **software identities in password-protected `.p12` files** separate from **YubiKey identities**, whose private keys stay on the device.
- Remember the serial and slots for each YubiKey identity, prompt for the correct device, and show the algorithm in PIN/operation dialogs.
- Update YubiKey certificate email addresses using the existing keys, including up to four additional email SANs.
- Export certificates with suggested `.pem` filenames or select DER `.cer`; identity and message save dialogs default to `.p12` and `.eml`. Missing extensions are added automatically.

This is an experimental interoperability application. Generated certificates are local test certificates; composite formats and OIDs follow the pinned Bouncy Castle implementation. It is not a production mail client or a claim of interoperability with every S/MIME implementation.

## S/MIME cryptographic profiles

| Profile | Signing | Encryption / KEM |
|---|---|---|
| Level 2 pure | ML-DSA-44 | ML-KEM-768 |
| Level 2 hybrid | MLDSA44-ECDSA-P256-SHA256 | MLKEM768-ECDH-P256-SHA3-256 |
| Level 3 pure | ML-DSA-65 | ML-KEM-768 |
| Level 3 hybrid | MLDSA65-ECDSA-P384-SHA512 | MLKEM768-ECDH-P384-SHA3-256 |
| Level 5 pure | ML-DSA-87 | ML-KEM-1024 |
| Level 5 hybrid | MLDSA87-ECDSA-P384-SHA512 | MLKEM1024-ECDH-P384-SHA3-256 |

Software creation offers the same Level 2, 3 and 5 choices as YubiKey creation. Each creates four software keys and stores both pure and hybrid identities in one password-protected `.p12` bundle; the PQ components are shared between the two views. Importing that bundle restores both selections. The empty-device provisioning flow offers levels 2, 3 and 5. Every option saves both pure and hybrid S/MIME identities for selection when sending. Desktop initial provisioning creates four keys at Level 2, ten at Level 3 (including the complete OpenPGP layout), and eight at Level 5. Level labels refer to the ML-DSA NIST category; ML-KEM-768 is category 3 in both levels 2 and 3. These labels do not claim FIPS validation of the device or application.

Software and YubiKey creation accept up to four additional comma-separated email addresses. All signing and encryption certificates, pure and hybrid, include the primary address plus these `rfc822Name` Subject Alternative Names. The subject CN remains the primary email. Duplicate or invalid addresses are rejected. Pending YubiKey setup metadata preserves the additional addresses for certificate issuance retries.

Outgoing S/MIME messages use opaque CMS SignedData, optionally wrapped in AuthEnvelopedData. PQ encryption uses KEMRecipientInfo, HKDF-SHA256, AES-256 key wrap and AES-256-GCM. Encryption is performed on the host with the recipient's public key; the recipient's YubiKey performs private-key decapsulation and ECDH during decryption. The host combines hybrid secrets.

Bouncy Castle computes ML-DSA external μ, including composite domain separation, and assembles composite signatures. The app's OpenSSL/PKCS#11 adapter uses the provider's external-μ support from [PR #818](https://github.com/openssl-projects/pkcs11-provider/pull/818). Returned signatures are verified before use. A composite operation shares one entered PIN between its two components and clears the cache when the operation finishes; PINs are never persisted.

## Getting started on desktop

1. In **Keys**, select or create a software identity, or select a saved YubiKey identity. Software creation requires a new `.p12` file and a password of at least 12 characters.
2. In **Certificates**, import the recipient's encryption certificate. Check its fingerprint through a trusted channel. Signing-certificate trust is an explicit, separate action.
3. In **Compose**, choose **Sign with**, enter matching sender/recipient addresses, and optionally enable **Also encrypt for recipient** and select **Encrypt to**.
4. Save the message locally or send it with SMTP. Use **Read & verify** for a local message or open a message from **Inbox**.

**Microsoft Graph live test (November 19, 2026):** Desktop Hotmail OAuth sign-in loaded a 50-message inbox page. A separate test process restored the Microsoft OAuth refresh token from Keychain, sent one synthetic self-addressed ML-DSA-65 S/MIME message, retrieved its MIME, and verified its signature and exact body. Opening the delivered message in the installed desktop app displayed **SIGNATURE VALID**, with the signer correctly remaining untrusted. The hybrid hardware test below additionally validates encrypted delivery through Hotmail.

For personal Hotmail/Outlook.com accounts, choose **Inbox → Sign in with Microsoft**, then **Connect Hotmail/Outlook**. The desktop app includes PQ Mail's shared public-client registration and uses Microsoft Graph with delegated `Mail.Read`, `Mail.Send`, `User.Read` and `offline_access`. Sign-in uses PKCE and a localhost callback; no client secret is needed. The inbox has 50-message pages and downloads MIME only when opened, without caching messages to disk. Choose **Hotmail / Outlook** when sending. The Microsoft OAuth refresh token is stored separately in the OS credential store; on macOS it uses the login Keychain (the Google Touch ID option does not apply). **Microsoft advanced settings** allows an alternative public client ID. Microsoft support is available on desktop and Android; its inbox currently has no S/MIME-only filter.

**Hotmail hybrid S/MIME validation (November 19, 2026):** A synthetic self-addressed message was signed using an existing Level 5 YubiKey, encrypted, sent and received through Microsoft Graph, then opened using the updated installed macOS app's mail code. MLDSA87-ECDSA-P384-SHA512 signature verification and ML-KEM-1024 + ECDH P-384 authenticated decryption passed; the sender email and exact synthetic body matched. Signing used slots 9c/83 and decryption used 9d/82. All nine public keys and PIN/touch policies matched their pre-test snapshots; 9c and 9d retained PIN Always and Touch Always. No keys or on-key certificates were changed.

Hotmail returned the encrypted CMS object as a `smime.p7m` attachment in `multipart/mixed`, without `smime-type`. The reader now recognizes a single direct S/MIME attachment and determines its type from CMS ContentInfo. It excludes unsigned wrapper text from verified content, rejects ambiguous multiple S/MIME attachments, and still authenticates decryption and verifies the inner signature. This tests PQ Mail interoperability through Hotmail, not native Outlook support for PQ certificates.

For Gmail, the desktop app includes a shared **PQ Mail** Google OAuth registration; new installations do not need their own client ID. Choose **Sign in with Google**, then **Connect Gmail**. The shared project is **In production**, so accounts do not need to be added as named test users. Google verification is pending; the unverified-app warning and Google's unverified-user limit still apply. The shared client loads directly from the app without a credential-store read. Older custom registrations can be reselected by importing their JSON in Advanced settings; choose **Inbox → Advanced settings… → Use PQ Mail Google client** to switch, then sign in again. Developers can still import their own Desktop client JSON or use **Advanced settings… → Enter Google client credentials…**. Google connections use the Gmail API with only `gmail.readonly` and `gmail.send`; other hosts retain IMAP/SMTP. Gmail shows 50 header-only messages per page with **Newer/Older** controls for the entire inbox. Message MIME is fetched when opened and is not cached to disk. Refresh tokens restore access after restart; sign-out removes the saved token. Server passwords and YubiKey PINs are not saved. See the [desktop and Gmail guide](docs/DESKTOP.md).

### Android hardware testing

Install the development APK built from `android/`, then open **Identities & certificates**. Import a software bundle, import an existing YubiKey signing/encryption certificate pair, or issue local certificates for an already-provisioned YubiKey. The app stores public token certificates and their serial binding; it does not copy private keys from the device.

To test a saved YubiKey identity:

1. Open **Identities & certificates** and tap the saved pure or hybrid identity. Selection returns to Home.
2. Open **Identities & certificates** again and scroll below the certificate export buttons.
3. Choose **Test selected YubiKey identity — no email**. This button appears only after selecting a YubiKey identity.
4. Connect over USB or follow the fresh-tap prompt and hold the key at the NFC antenna through each operation. Enter the PIN first, then follow the fresh-tap prompt. A round trip normally asks for one signing PIN and one decryption PIN; each composite operation reuses its PIN for both components.

**Android NFC comparison (November 17, 2026):** With the same APK and Level 3 Beta0 YubiKey, Pixel 9 / Android 17 completed **five NFC S/MIME round trips: three hybrid and two pure**, with no recorded pre-PIN retries. Pixel 10 / Android 17 completed one of four hybrid runs in its comparison batch, with three failures and seven recorded pre-PIN setup failures. The Pixel 10 honored the new 240-byte public-metadata response requests, but transport errors persisted. This points toward a phone-dependent NFC interaction, not a proven root cause or universal reliability claim. Earlier Pixel 10 Level 5 pure/hybrid NFC and Level 3 pure/hybrid USB tests also passed. **22 focused emulator tests passed.** See the [YubiKit integration and phone-comparison report](docs/ANDROID-NFC-YUBIKIT.md) for exact scope and limitations.

## YubiKey identities

**Create identity on empty YubiKey…** checks every user PIV slot before asking for provisioning credentials and checks again under an exclusive device connection before generation. Any occupied or unreadable slot stops the operation. The factory attestation slot is excluded. The flow does not reset a device or replace existing keys.

| Slot | Level 2 | Level 3 | Level 5 |
|---|---|---|---|
| `9c` signing | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
| `83` signing (new identities) | ECDSA P-256 / SHA-256 | ECDSA P-384 / SHA-384 | ECDSA P-384 / SHA-384 |
| `9d` decryption | ML-KEM-768 | ML-KEM-768 | ML-KEM-1024 |
| `82` decryption | ECDH P-256 | ECDH P-384 | ECDH P-384 |
| `84` OpenPGP hybrid component | — | Ed25519 signing | ML-KEM-768 encryption |
| `85` OpenPGP hybrid encryption component | — | X25519 | X25519 |
| `86` OpenPGP certification component | — | ML-DSA-65 | — |
| `87` OpenPGP certification component | — | Ed25519 | — |
| `88` OpenPGP classical signing | — | Ed25519 | ECDSA P-384 |
| `89` OpenPGP classical encryption | — | X25519 | ECDH P-384 |

Composite KEM identifiers follow [draft-ietf-lamps-cms-composite-kem-04](https://datatracker.ietf.org/doc/html/draft-ietf-lamps-cms-composite-kem-04), including MLKEM768-ECDH-P384-SHA3-256. ML-DSA categories are defined in [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final); ML-KEM parameters in [FIPS 203](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.203.pdf).

Desktop provisioning generates all keys on-device with PIN policy **Always**. Touch is **Always** in 9c/9d, plus 86/88/89 at Level 3 and 84/88/89 at Level 5; the other provisioned slots use **Never**. Existing keys and their policies are unchanged. Local records contain public certificates, serial and slot bindings, not token private keys.

**Resume interrupted setup…**, with adjacent **ⓘ** help, replaces **Finish pending certificates…**. Choose `setup.properties` under the app's `token-setups` directory (the error dialog gives its full path). New setup records are saved before generation. Recovery checks serial, public keys, algorithms and policies; it reuses completed certificates and their fingerprints. If key generation was interrupted, explicit provisioning authorization permits generating only unrecorded keys in confirmed empty slots. An occupied slot without a saved matching public key, a changed policy/key or an unreadable slot stops recovery for inspection. It never resets or overwrites a slot. Older certificate-only setup journals remain readable.

**Update YubiKey certificate email…** issues new local signing and encryption certificates for saved token profiles using their existing keys. Enter the primary email and up to four additional comma-separated email SANs; duplicates and invalid addresses are rejected. Old identities are preserved, PIN prompts authorize certificate signing, and no email is sent. This changes certificate identity information, not your Google account.

Desktop provisioning reads the device’s actual beta firmware version through YubiKey Management before opening PIV, allowing Beta0 devices to pass detection while preserving the empty-slot checks.

The packaged provisioning helper uses Yubico's Rust yubikit directly. **ykman is not required for this flow or for PKCS#11 signing/decryption.** The older optional `ykman-mu.py` adapter and Terminal setup scripts still require the Beta0 ykman CLI. See [PKCS#11 signing](docs/PKCS11.md), [KEM decryption](docs/PKCS11-KEM.md), and [external-μ protocol](docs/EXTERNAL-MU.txt).

## Build from source

Use **JDK 25.0.5.1 or newer within the Java 25 GA release line**, **Maven 3.9.9**, Python 3, Git and Bash on macOS/Linux. Initial dependency builds require network access and several GB of disk space. macOS native helpers also require Xcode Command Line Tools and a current Rust toolchain.

```sh
git clone https://github.com/ve7jtb/pq-mail.git
cd pq-mail
# Set JAVA_HOME and PATH for your JDK and Maven.
./scripts/build-dependencies.sh
./build.sh test
./run.sh
```

Dependencies are pinned to these public source revisions:

| Repository | Revision |
|---|---|
| [mail-api](https://github.com/ve7jtb/mail-api) | `09b27cf52b4b382c55cc8736858456f3aa43b369` |
| [angus-mail](https://github.com/ve7jtb/angus-mail) | `d33de7563efdf5a3cb0691994500d6cad8aecafd` |
| [bc-java](https://github.com/ve7jtb/bc-java) | `fad147c4440df867930bd9d8c14e85fbaca1c377` |

Activation uses `jakarta.activation-api:2.2.0-M2` and `angus-activation:2.1.0-M1`. The dependency script keeps checkouts, caches and logs under `.deps/`, validates existing checkouts, and writes runtime jars to `lib/`. Set `HYBRID_DEPS_DIR` to change the cache location. Upstream dependency test suites are skipped; app tests run with `build.sh test`. Subsequent app-only builds use the local jars. Builds are not claimed to be byte-for-byte reproducible.

### macOS app

```sh
./scripts/build-pkcs11.sh
./package.sh
```

This creates **`dist/PQ Mail.app`**, bundling Java, OpenSSL, PKCS#11 modules, and native provisioning/Keychain helpers. Python 3 must be installed on the Mac; its path is configurable. `HYBRID_OPENSSL_ROOT` selects OpenSSL (default `/opt/homebrew/opt/openssl@3`); `HYBRID_MAIL_PACKAGE_DIR` selects the output directory. Existing app images are not overwritten. The development app is ad-hoc signed, not notarized.

### Windows x64 and ARM64

The [Windows installer workflow](https://github.com/ve7jtb/pq-mail/actions/workflows/windows-installers.yml) builds on separate x64 and ARM64 runners and packages Java, Python, OpenSSL, the PKCS#11 provider/module and native helpers. Successful runs publish architecture-specific `PQ-Mail-Windows-*` installer artifacts. These are development installers, not Authenticode-signed releases. See [Windows build instructions and validation status](docs/WINDOWS.md). A configured workflow alone is not evidence of a successful installer or hardware test; check the run result and artifacts.

### Android APK

After building the pinned shared dependencies above, set `ANDROID_HOME` to an SDK with platform **37.0** installed:

```sh
cd android
./gradlew :app:assembleDebug
# app/build/outputs/apk/debug/app-debug.apk
```

The build pins AGP 9.3.3, Gradle 9.9.1 and YubiKit 3.3.0. The APK supports API 26 and later; testing so far used a Pixel 10 running Android 17. This is a debug-signed preview. Android uses Activation 2.1.3 / Angus Activation 2.0.2 for runtime compatibility. See the [Android guide](android/README.md) for installation, device tests, storage behavior and limitations.

### Compatibility with existing installations

The display name and repository changed to PQ Mail. Existing settings, identity references, trust records and OAuth credential-store identifiers remain compatible. The application deliberately retains the legacy **`Hybrid Mail`** data directory (`~/Library/Application Support/Hybrid Mail` on macOS and `%LOCALAPPDATA%\Hybrid Mail` on Windows), Java package names, helper filenames and `HYBRID_*` environment variables. No key regeneration or credential migration is needed for the rename.

## S/MIME attachments

In desktop Compose, use **Add attachments…** and **Remove selected**. Files and the text body are signed together. Enable **Also encrypt for recipient** to encrypt the complete signed message, including attachment filenames and contents, using the selected PQ, hybrid, or conventional recipient certificate. Gmail API and SMTP use the same protected message. Outer email headers remain unprotected.

For signed mail, signature verification must succeed before attachments are available. Decrypted-only mail is explicitly labeled unsigned, and its attachments carry no signer assurance. Decrypted attachments remain in memory until you explicitly save one. Desktop saving refuses to overwrite existing files; Android uses the system save dialog. The composer supports up to 20 attachments and a combined body/file payload of 10 MiB, subject to the final 20 MiB encoded-message limit. Android also supports attachment selection and saving through the system document picker.

## Conventional S/MIME interoperability

RSA and ECDSA signatures can be received and explicitly trusted by certificate fingerprint. Recipient encryption certificates support RSA (2048 bits or larger) and ECDH P-256/P-384 alongside PQ KEM profiles. Key usage and emailProtection extended key usage are checked when present; an ECDH certificate requires keyAgreement when key usage is present. Trust for signing and encryption is separate and does not imply CA-chain validation.

Import a recipient certificate or use **Trust signer for encryption** on verified mail if the signer certificate also permits encryption. A separate encryption certificate must be imported when the signing certificate is signing-only. Conventional software `.p12` files with one unambiguous signing key and at most one encryption key can be imported, including arbitrary aliases. Classical decryption requires the matching software private key; PQ YubiKey profiles remain unchanged.

The reader accepts signed messages inside AuthEnvelopedData or conventional EnvelopedData (including AES-CBC), and plain-text content in common mixed/alternative/related MIME layouts. Desktop HTML uses the safe local viewer described above. Encrypted messages without a signature are shown explicitly as unsigned and cannot be used to establish signer trust. Encryption to a conventional recipient does not provide post-quantum confidentiality, even when the message carries a PQ signature.


## Share certificates between instances

Select a saved **YubiKey identity**, then choose **Share certificates…** (Mac: **Keys**; Android: **Identities & certificates**). PQ Mail gathers the saved pure/hybrid profiles for the same device and PQ key pair and shows the email addresses, algorithms, fingerprints, serial and all four PIV slots before sharing. A normal pure/hybrid pair contains four public certificates. If only one profile is saved, only that profile can be shared; no new certificates or keys are generated.

The versioned `.pqcert` bundle contains public signing/encryption certificates and YubiKey serial/slot mappings. It contains **no private keys, PINs, passwords, OAuth credentials or trust decisions**. The Mac opens its native sharing picker, including AirDrop when available, and also offers **Save bundle…**. Android opens its system share sheet, including Quick Share when available. Transport availability depends on the OS/device; this feature does not implement AirDrop itself.

On the receiving Mac, open the `.pqcert` file with PQ Mail or use **Import certificate bundle from file…**. On Android, share/open it with PQ Mail when offered, or select it with **Import certificate bundle from file…**. Review all fingerprints and device mappings, then choose:

- **Use with my YubiKey / My YubiKey**: save public-only identities for that device. Select the imported pure or hybrid identity afterward. The existing signing/decryption backend checks serial and public keys when the key is used; imported metadata alone does not prove possession.
- **Add contact certificates / Contact certificates**: save certificates for another person's mailbox. Mark fingerprints trusted separately after confirming them with the owner.

Existing trust decisions are preserved, but imports never grant new trust. Repeated identity imports are idempotent; conflicting existing bindings are rejected. No YubiKey slots are written or provisioned. ML-DSA signing currently uses slot `9c`; the traditional-signing, ML-KEM and ECDH mappings travel with each profile. Software private identities remain separate `.p12` imports.

Validation covers public-only bundle round trips, malformed/oversized input, conflicting mappings, idempotent imports, trust separation, Android provider access restrictions and simulated token operations. Physical Mac–Android AirDrop/Quick Share delivery still requires testing on the two devices.

## Validation and limitations

- **Current Level 3 hardware:** physical Beta0 tests passed on macOS through PKCS#11 for ML-DSA-65 / ML-KEM-768 and MLDSA65-ECDSA-P384-SHA512 / MLKEM768-ECDH-P384-SHA3-256. All four keys were generated on-device with PIN Always / Touch Never. Both signed-and-encrypted S/MIME round trips passed. The new pure/hybrid public certificate pairs were copied into Android and independently read back byte-for-byte. Subsequent Android NFC round trips passed for both profiles.
- **Android software and adapter tests:** five instrumented test groups passed on Pixel 10 / Android 17, covering all six profiles, encrypted `.p12` reload, wrong-password rejection, tampering, UI startup, and actual YubiKit PIV code exercised with a simulated APDU card. Desktop PQ Mail decrypted and verified 12 Android-generated messages and loaded the corresponding `.p12` bundles. Physical Level 3 NFC round trips also passed; physical Level 3 pure and hybrid USB round trips passed twice each.
- **Earlier hardware tests:** physical Beta0 hardware tests passed for pure ML-DSA-65 and composite MLDSA65-RSA3072-PSS-SHA512 signing through PKCS#11, and pure ML-KEM-768 / hybrid MLKEM768-ECDH-P256 decryption. Saved messages were independently reopened and verified. The earlier ykman external-μ signing demo also passed.
- Automated tests cover software profiles, simulated external signing/decryption including all three provisioning levels in pure and hybrid modes, serialization, tampering, key matching, PIN cache cleanup, identity bindings, and provisioning refusal/partial failures. Simulators do not establish physical-device support. Level 2 physical hardware round trips remain unverified; Level 5 pure/hybrid macOS PKCS#11 round trips and compressed bundle restore passed on November 19, 2026 (see below); the normal provisioning UI requires an empty compatible key.
- Gmail API OAuth with the shared client and read/send scopes was observed in the Mac app: 12 inbox messages loaded, with 3 matching the S/MIME-only filter. Mock API tests cover paging and pure/hybrid signed/encrypted MIME transfer for all three levels. On November 17, 2026, two synthetic self-addressed messages were sent and received through the live Gmail API: one signed and one signed-and-encrypted. MLDSA87-ECDSA-P384-SHA512 signatures verified, and MLKEM1024-ECDH-P384-SHA3-256 YubiKey decryption completed with authenticated AES-256-GCM decryption. Earlier full-mail OAuth, Keychain restoration after restart, and the ten-message IMAP inbox were also observed. Live SMTP delivery, third-party interoperability, Windows hardware use and a production security audit are not established by these tests.
- The reader accepts opaque and detached signatures, AuthEnvelopedData and conventional EnvelopedData, common text MIME layouts, and attachments. Encrypted-only messages are explicitly labeled unsigned; signature or decryption failures are not downgraded. Desktop HTML uses the safe local viewer described above.
- **Attachment and conventional interoperability tests:** desktop regression tests and Android emulator tests passed for binary/Unicode-named attachments in all six PQ profiles, RSA/ECDSA signatures, RSA/ECDH encryption, arbitrary-alias software `.p12` import, detached signatures, AES-GCM and legacy AES-CBC envelopes, and unsigned encrypted messages. These are local generated-message tests, not independent third-party client or physical YubiKey validation of the new features.
- Trust uses exact certificate fingerprints, validity and key-usage checks. There is no CA chain building or revocation checking. Outer mail headers are not signed or encrypted. The app distinguishes signature validity from trust and flags sender/certificate mismatches.

Public demonstration certificates are separately published in [hybrid-mail-test-certificates](https://github.com/ve7jtb/hybrid-mail-test-certificates). Private keys, user identity files, device identifiers, user OAuth tokens, custom client credentials and local hardware artifacts are excluded from this source repository.

## Source map

The Android UI, USB/NFC backend, build instructions and instrumentation tests are under `android/`. Its build reuses the canonical S/MIME sources and substitutes Android platform adapters.

Desktop Java code is under `src/dev/hybridmail/`: `MailApp` is the Swing UI; `MailEngine` handles S/MIME and mail transport; `Identity` and `DesktopState` manage identities and storage; `ExternalMu` / `ExternalKem` bridge token operations; `TokenProvision` invokes the native provisioning helper. `adapters/` contains the Python OpenSSL/PKCS#11 and legacy ykman adapters. `native-src/` contains platform credential helpers and Rust provisioning code. Tests are in the Java sources, `tests/`, and the Rust helper.

Third-party components retain their own licenses; see [notices](docs/THIRD-PARTY.txt). No project license has been selected yet.

Gmail **Signed or encrypted only** filters each page using its top-level Content-Type: opaque S/MIME, multipart/signed with a PKCS#7 or OpenPGP signature protocol, or multipart/encrypted with the OpenPGP encryption protocol. It does not fetch message bodies or establish signature validity. Pages cover 50 inbox entries before filtering, so a page may show fewer or no matches while **Older** remains available. Inline OpenPGP and protected content nested inside forwarded messages or ordinary attachments are not included. The filter identifies message formats, not valid signatures or trusted senders.

### Bundled Java security baseline

Desktop builds require Java 25.0.5.1 or newer in the Java 25 GA line. Set `JAVA_HOME` to that JDK; compilation, dependency builds and packaging reject older runtimes and early-access builds. Windows CI pins Azul Zulu 25.0.5.1 (November 2026 security update). Mac and Windows packaging also check the actual bundled runtime and produce a `java-runtime*.txt` report alongside the package. Updating system Java does not update an already installed PQ Mail app; replace the app with the rebuilt package.

This baseline includes the November Base64 intrinsic fix (CVE-2026-114938); see [Azul’s November release notes](https://docs.azul.com/core/release-notes). Android uses ART and iOS uses OpenSSL, so this desktop JDK change does not replace their runtimes.

### Linux amd64 and ARM64

Linux builds provide a `.deb` installer and a portable `.tar.gz` app image for each architecture. They target Ubuntu 24.04 or newer (glibc 2.39+), bundle patched Java 25.0.5.1, OpenSSL 3.5 LTS (patched 3.5.10-dev snapshot), the PKCS#11 provider/module and YubiKey provisioning helper. No system JDK or ykman is required. Install the Debian package with `sudo apt install ./PQ-Mail-1.2.1-Linux-amd64.deb` (use `arm64` for ARM). The desktop menu entry launches PQ Mail.

The portable archive requires Python 3, PC/SC (`pcscd`, `libccid`, `libpcsclite1`), GTK/X11/font libraries and `libsecret-1-0`. Run `PQ Mail/bin/PQ Mail` after extraction. A graphical desktop session is required; Wayland desktops need XWayland for Java Swing. Enable the distribution’s PC/SC service/socket if it is not active. Do not run PQ Mail as root.

Settings and identities use `$XDG_DATA_HOME/pq-mail`, normally `~/.local/share/pq-mail`. Google OAuth refresh tokens and custom client credentials use the desktop Secret Service (for example GNOME Keyring or a compatible KWallet service); there is no plaintext fallback. The keyring must be available and unlocked. Software `.p12` passwords and YubiKey PINs are not saved. Certificate sharing uses file export/import on Linux.

The Linux workflow builds natively on amd64 and ARM64, tests software S/MIME/OpenPGP and simulated token operations, tests a disposable Secret Service store/read/delete cycle, and runs the software profiles in the packaged JVM. Physical YubiKey operation on Linux still requires hardware testing. Build with `scripts/build-dependencies.sh`, `build.sh test`, `scripts/build-linux-native.sh`, and `scripts/package-linux.sh`; see `.github/workflows/linux-packages.yml` for the build prerequisites.

Linux 1.2.1 validation (November 18, 2026): native Ubuntu 24.04 amd64 and ARM64 [build/profile/Secret Service tests](https://github.com/ve7jtb/pq-mail/actions/runs/44366025968) passed. Both `.deb` packages passed checksum verification, installation and desktop-window startup in [clean-runner installation tests](https://github.com/ve7jtb/pq-mail/actions/runs/44368695400). Download the `.deb` and portable archive from the build run’s `PQ-Mail-Linux-amd64` or `PQ-Mail-Linux-arm64` artifacts. These checks use synthetic software identities and simulated token operations; they do not establish physical Linux YubiKey compatibility.

The ARM64 Debian package was also installed in the local **Codex Linux** UTM VM (Ubuntu 26.04.1 ARM64). Level 2/3/5 pure/hybrid software identity round trips passed in the installed bundled JVM, and the installed desktop window opened under Xvfb as the normal non-root user. No accounts, email or physical YubiKey were used.

New desktop Level 3 YubiKey provisioning creates all ten keys in one flow and offers **Also create v6 hybrid and both v4 compatibility certificates**, selected by default. Unchecking skips certificate issuance, not the full key layout; the ordinary OpenPGP creation action can issue them later from those existing keys. The choice is saved for interrupted-setup recovery. Level 5 retains its eight-key compatibility profile; Level 2 does not support OpenPGP.

### Existing Level 5 classical OpenPGP and certificate backups

**Current outgoing policy:** these classical certificates remain readable and can be restored for incoming verification/decryption, but Compose requires a hybrid post-quantum signer. The earlier classical round-trip results below describe compatibility testing, not an enabled outgoing signing option.

Desktop and Android can use a Level 5 **hybrid identity's P-384 components** for RFC 9580 v6 OpenPGP: ECDSA in slot **83**, ECDH in **82** (explicit legacy mappings remain supported). This OpenPGP profile is **classical, not post-quantum**; Level 5 pure/hybrid S/MIME remains unchanged. Both P-384 slots use their existing PIN/touch policies. Level 5 pure-only certificates do not contain the classical public keys; select the hybrid identity for OpenPGP.

New desktop YubiKey provisioning offers OpenPGP creation by default for Level 3 (separated v6 plus both v4 views) and Level 5 (its P-384 compatibility profiles), with an opt-out. Android offers the same choice when issuing certificates for existing keys. Creation and desktop email/SAN updates prompt **Back up now / Not now**. **Back up certificate bundle to YubiKey…** regenerates a signed bundle from the selected email/SAN profile set, including both S/MIME profiles, any saved OpenPGP public identity, serial and slot mappings. **Restore certificate bundle from YubiKey…** reviews and restores it without granting trust. This backs up public certificates, not private keys, PINs or account credentials. Adding SANs preserves a saved OpenPGP identity when its primary email remains unchanged; changing that email creates new OpenPGP certifications if enabled.

Software and simulated-token P-384 round trips, independent Bouncy Castle OpenPGP signature checks and bidirectional ECDH/v2-SEIPD exchange are tested. Physical P-384 OpenPGP token testing remains pending. iOS currently supports the earlier Level 3 hybrid OpenPGP profile only and cannot restore a Level 5 bundle containing this new classical OpenPGP identity yet.

### RFC 9980 OpenPGP with additional YubiKey keys

Desktop Level 3 YubiKey identities can create an RFC 9980 OpenPGP certificate
using ML-DSA-65 + Ed25519 and ML-KEM-768 + X25519, with additional keys in slots
84/85. Creation offers **Back up certificate bundle to YubiKey**, preserving the
S/MIME certificates and their existing slots. The alternative P-384 composite
OpenPGP profile is **experimental NIST/Brainpool draft** support.
See [OpenPGP setup, backup and platform limitations](docs/OPENPGP.md#rfc-9980-certificates-with-extra-yubikey-keys).

### OpenPGP v4 interoperability validation

The v4 adapter uses `bcpg` built from the same pinned Bouncy Castle revision as the other jars. Tests cover Ed25519, RSA and ECDSA signatures, key/subkey revocation and expiration, unsupported critical metadata, tampering and wrong keys. `scripts/test-v4-openpgp.sh` generates disposable GnuPG keys, verifies detached and compressed v4 signatures in PQ Mail, then independently decrypts PQ Mail’s v4 envelope in GnuPG and compares the hybrid-signed contents. No email or hardware keys are used. The published `dkg@fifthhorseman.net` certificate was also checked locally; its current encryption subkey was selected instead of its expired predecessor.

The new v4 adapter and Compose lookup are shared by the Java desktop/Android implementation; they have not been ported to the separate Swift/OpenSSL iOS implementation.

Classical-only encryption requires an **Encrypt anyway** confirmation, and valid classical-only signatures carry a **not post-quantum resistant** warning. These warnings also apply to conventional S/MIME. A hybrid signature containing ML-DSA or a hybrid KEM containing ML-KEM does **not** get the corresponding warning. Signing and encryption are assessed independently; a hybrid signature does not upgrade classical ciphertext protection. Trust and post-quantum algorithm status are separate.

### Saved OpenPGP contacts and trust (desktop)

Imported sender/recipient keys and successful Compose keyserver lookups are saved as **untrusted OpenPGP contacts** in Certificates. They survive app restarts and can be used offline. Choose **Details**, **Use selected certificate**, **Export**, or **Remove** just as for S/MIME contacts. Earlier session-only imports must be imported or looked up once again. Your own identity certificates remain in their existing identity storage.

**Mark trusted** requires explicit confirmation of the contact email and **entire primary-key fingerprint**, checked independently with its owner. Trust is scoped to that email/fingerprint pair, including valid bound subkeys; it does not transfer to another email or replacement primary key. A refreshed valid certificate with the same primary fingerprint retains that pair’s trust. **Remove trust** persists across restarts. Removing the contact also removes its trust and retains its public certificate in `removed-contacts`. Trust does not bypass certificate validation or suppress classical-only algorithm warnings.

Read & verify reports the saved trust decision for the actual From mailbox only after signature validation and a matching certified email. Saved contacts can supply incoming verification keys after restart; if an encrypted message has multiple matching signer certificates, select one explicitly before decrypting to avoid repeated token operations.

**Choosing trusted OpenPGP email addresses:** In Certificates, select an OpenPGP contact and choose **Mark trusted…**. The dialog lists every currently validated, self-certified email address, shows the full primary-key fingerprint, and provides **Select all email addresses**. Existing trust choices and the selected contact are checked initially. **Save trust choices** trusts checked addresses and removes trust from unchecked addresses for this primary key; selected aliases are added to Certificates. **Cancel** saves nothing. This covers valid signing and encryption subkeys bound to that primary key, while retaining expiry, revocation, usage checks and classical-algorithm warnings.

### Manual mail servers and sent confirmation

Use **Settings → Mail accounts → Mail servers…** (also available in Compose) to save IMAP/SMTP hostnames, ports and usernames without starting a connection or sending mail. IMAP uses TLS (normally 993); SMTP requires STARTTLS (normally 587). Passwords/app passwords are requested in **Connect your email → Other mail provider** and **Send… → Other host (SMTP)** and are not saved. Gmail API remains separate and uses Google sign-in. After Gmail or the SMTP server accepts a message, PQ Mail displays a **Message sent** confirmation with recipient, subject and sending service. This confirms submission, not delivery or reading; failed sends do not display it.

Incoming signed PGP/MIME can use attached OpenPGP public certificates for signature verification without saving them or granting trust. The reader provides separate **Save sender OpenPGP certificate…** and **Trust signer fingerprint…** actions; trust remains scoped to selected certified emails and the full primary-key fingerprint. Discovery is bounded and accepts only certificates whose self-signatures/key bindings validate. Certificates hidden inside encrypted payloads still require an available sender key before opening.

### Desktop recipient preference and compatibility

PQ Mail prefers a matching v6 certificate over v4, then prefers a usable supported hybrid encryption subkey within that certificate. Classical encryption requires confirmation; no usable subkey means encryption is unavailable. V6 does not itself mean post-quantum: a classical v6 certificate still outranks a hybrid v4 certificate under this policy. Certificate import or receipt never grants trust automatically.

For v4 recipients, the desktop RFC 9980 YubiKey identity signs with its existing Ed25519 key and attaches `public-key-v4.asc` (Ed25519 primary, ML-KEM-768 + X25519 subkey) and `public-key-v6.asc` (hybrid signing/encryption). Both attachments are covered by the message signature and are inside encryption when enabled. Their fingerprints remain stable because the compatibility certificate reuses the original key creation timestamps. Public certificates are generated during composition; this does not generate token keys or write an updated on-key backup. A receiving client must support algorithm 35 to use the hybrid subkey. Proton/Thunderbird interoperability for this new outbound mode is not yet established.

Local regression tests cover v6-first selection (including classical v6 over hybrid v4), hybrid subkey preference and revocation fallback, Ed25519 certificate/message validation, both attached certificates, v3 hybrid encryption/decryption and tamper rejection, and continued v6 hybrid signing for v6 or unknown recipients. Hardware calls were simulated in these tests; no email was sent.

### Complete Level 3 OpenPGP setup and recovery

**Keys → Create identity on empty YubiKey… → Level 3** now creates the complete ten-key layout above, then pure/hybrid S/MIME certificates, a v6 OpenPGP certificate with a separate certification primary, and two v4 compatibility views. The v6 primary uses 86/87, hybrid signing uses 9c/84, hybrid encryption uses 9d/85, and standalone classical compatibility uses 88/89. All supplied email addresses are certified in the new v6 and v4 views. Completed certificate issuance is journaled so resuming does not replace fingerprints.

The separate **Create / migrate v6 identity (86–89)…** button is removed. **Resume interrupted setup…** also detects an unfinished older OpenPGP migration for the selected identity and offers certificate/trust/bundle recovery, without generating keys. Incomplete older key journals require inspection. See [setup and recovery details](docs/OPENPGP.md#complete-level-3-setup-and-recovery-desktop).

Creation offers **Back up now / Not now** for the signed, compressed on-key bundle. It includes v6 and full v4 certificates; the classical-only v4 view is derived from the latter on restore. Tests use simulated keys/cards to cover initial issuance, email aliases, v6/v4 signing/decryption, interrupted issuance with stable fingerprints, compressed bundle restore, refusal of mismatched/unrecorded occupied slots, and recovery of interrupted older migrations. No physical key was provisioned for this desktop update.

### Level 5 v4 OpenPGP compatibility

Fresh Level 5 YubiKey provisioning creates eight keys: the S/MIME keys in 9c (ML-DSA-87), 9d (ML-KEM-1024), 83 (P-384 signing), 82 (P-384 ECDH), plus 84 (ML-KEM-768), 85 (X25519), 88 (P-384 compatibility signing), and 89 (P-384 fallback ECDH). All use PIN Always; 9c, 9d, 84, 88 and 89 require touch; 82, 83 and 85 do not. The creation dialog offers certificate generation by default, with an opt-out; opting out does not remove generated keys.

The v4 compatibility certificate uses P-384 certification/signing, preferred ML-KEM-768 + X25519 encryption, and a P-384 ECDH fallback subkey. Its classical-only view shares the primary fingerprint. The hybrid KEM is a lower-strength compatibility option, not Level 5 encryption. Classical encryption requires explicit warning/confirmation; v4 signatures are identified as classical even when encryption is hybrid. No automatic downgrade occurs after a cryptographic failure.

Both compatibility views are preserved by the compressed B2 on-key bundle (the classical-only view is derived from the full certificate). Restore verifies public keys against slots 84/85/88/89. Desktop PKCS#11 and Android YubiKit routing are implemented; local software tests verify both encryption paths, P-384 signatures, dedicated slot routing, compressed bundle restore and wrong-key rejection. Physical macOS testing passed as described below. Android routing is implemented but this new Level 5 v4 profile has not been verified on a physical Android device. iOS does not yet support this Level 5 v4 compatibility profile.

### Level 5 hardware validation — November 19, 2026

A PQC Beta0 YubiKey completed certificate-only issuance using its existing keys, followed by successful local tests with the installed, original OpenSSL/PKCS#11 provider and Yubico module:

- Pure ML-DSA-87 / ML-KEM-1024 and hybrid MLDSA87-ECDSA-P384-SHA512 / MLKEM1024-ECDH-P384-SHA3-256 S/MIME signing, encryption and decryption.
- OpenPGP v4 P-384 signatures with both ML-KEM-768 + X25519 hybrid encryption/decryption and P-384 classical fallback encryption/decryption.
- Signed, compressed on-key certificate-bundle backup, read-back verification, and import into a fresh local identity store, including the v4 compatibility certificate.
- All nine public keys (eight application keys plus a separate timing-test key) matched their saved snapshots. Before/after slot metadata and PIN/touch policies were identical. No keys were regenerated and no email was sent.

Every tested key had PIN Always. Touch was Always in 9c, 9d and 84, and Never in 82, 83, 85, 88 and 89; the extra test key in 86 also had Touch Never. The tested key's pre-existing 88/89 policies were preserved. New provisioning defaults require touch in 88/89 as documented above; this run does not validate those new touch-required defaults. The timing-test key is not part of the application's eight-key provisioning profile or certificate bundle.

Earlier touch-required signing attempts returned PC/SC `NotTransacted` and the reader disappeared. After replacing the USB-A-to-C adapter, slot 9c signing passed using the original installed PKCS#11 backend with PIN Always / Touch Always. Experimental APDU framing changes were not needed for that successful original-backend run and are not included in this update. This points to the previous adapter/connection, without claiming a general USB or firmware diagnosis. Three no-touch diagnostic ML-DSA-87 signatures also verified, with card-operation times of 1.267, 0.557 and 0.489 seconds (including USB transfer, excluding PIN entry); those measurements used the diagnostic backend and are not a benchmark of the shipped backend.

### PKCS#11 signing performance — November 19, 2026

Desktop signing now supports a single-process OpenSSL helper that checks the
live token public key, signs through PKCS#11, and verifies the signature before
returning it. The Yubico module uses opt-in, slot-scoped metadata discovery,
avoiding a full PIV-slot scan and generated attestation certificates for routine
signing. The original signing and APDU transport implementations are preserved.

On macOS with a PQC Beta0 YubiKey, ML-DSA-87 on a dedicated no-touch test key
produced these results (ten measured operations per path after two warm-ups):

| Signing path | Median elapsed | Range |
| --- | ---: | ---: |
| Optimized PKCS#11, separate public-key check and signing processes | 1.174 s | 1.078–1.889 s |
| Single-process PKCS#11 helper | **0.710 s** | 0.642–1.130 s |
| ykman with a separate live public-key check | 1.073 s | 0.870–3.170 s |

The single-process helper reduced median elapsed time by **40% versus the
optimized two-process adapter**, and **34% versus this ykman workflow**. These
are end-to-end timings including public-key checking, process startup,
authentication and signing; they exclude human PIN entry and the benchmark's
independent verification. The helper additionally verifies internally. They are
not card-only timings or guarantees for other devices. All 36 signatures
verified, and every helper invocation used exactly one PIN callback. An earlier
helper run with extra interactive PIN prompts is excluded from the comparison.

Median helper phases were 264 ms for the live public-key check, 10 ms for the
private-key check/login, 400 ms for signing, 0.6 ms for verification and 19 ms for
cleanup. Scoped discovery was independently checked against all nine occupied
slots' public keys. The installed, signed Mac app then passed a separate
**ML-DSA-87 signing test in slot 9c with PIN Always / Touch Always**: its
4,627-byte signature verified. Before/after snapshots confirmed that all nine
public keys and PIN/touch policies were unchanged. This touch-required test is
functional validation; its elapsed time includes human PIN entry and touch.

Mac packaging builds and tests the helper automatically. Other packages retain
the existing two-process path until they bundle the helper. A helper failure
never triggers a signing retry or a fallback. PINs are supplied through an
anonymous pipe/callback, cleared after the operation, and never placed in
arguments, environment variables or files. See [PKCS#11 details](docs/PKCS11.md).

Compose defaults to **OpenPGP**. If the recipient has saved S/MIME certificates
and no matching saved OpenPGP certificate, it defaults to **S/MIME** instead.
Recipients with both formats, or no known certificate, default to OpenPGP.
An explicit format choice is retained until the recipient changes; selecting a
specific contact certificate selects its format. This does not grant trust or
automatically enable encryption.


### Desktop passkey vault and Level 5 software OpenPGP

The **Keys → Passkey vault** controls create/unlock a PRF-encrypted local vault, add backup passkeys, rename them, remove their access, and lock the session. Enrollment first requests a discoverable assertion for an existing PQ Mail credential. A new credential is created only after that attempt and an explicit **Create new passkey** choice; cancellation never automatically creates one. Registration requires a discoverable credential and user verification, with a fresh random 32-byte user handle for every enrollment. Two installations do not reuse a fixed user handle. After unlocking, **Use existing passkey** opens the RP-scoped discoverable credential chooser and enrolls the selected existing credential using a PRF assertion, without a registration ceremony or replacement. This wraps the current local vault key; it does not transfer another vault’s contents. Removal affects this vault; remove the credential in your provider separately when appropriate. The last unlocking credential cannot be removed.

Desktop WebAuthn runs at `https://ve7jtb.github.io/pq-mail/passkey/` with RP ID `ve7jtb.github.io`, the same RP as Android. The browser invokes the chosen passkey provider. PRF evaluation is requested during creation; providers that require it use one follow-up assertion. Unsupported PRF fails closed. The temporary IPv4 loopback callback checks the exact origin, host, nonce, challenge, RP hash and user-verification flags. Responses are encrypted with ephemeral P-256 ECDH and AES-256-GCM. The hosted page has no analytics or third-party scripts and does not upload passkey results. Browsers may request local-app network permission. This is a browser flow, not Apple's native AuthenticationServices passkey API.

The vault uses a random 256-bit content key and per-passkey PRF-derived wrapping keys. Each new/imported software `.p12` uses its own random 256-bit password, stored only inside the vault. New PKCS#12 files explicitly encrypt private keys with AES-256. The certificate safe uses AES-128; public certificates are not private-key material. **Protect / upgrade software identity** converts a saved password-based identity without changing its S/MIME keys, and adds missing Level 5 software OpenPGP profiles. Original password-protected files remain recovery backups; remove them yourself if no longer wanted. **Export passkey-wrapped identity** creates a `.pqidentity` bundle for a passkey also enrolled on the receiving instance. It contains only encrypted software identities and their random PKCS#12 password, protected by a fresh AES-256-GCM content key wrapped through that passkey’s PRF. The receiving app requires the same enrolled credential, evaluates the bundled salt, reviews the decrypted identities, and re-encrypts them under a new local vault password. No OAuth tokens, server settings or local vault content key are included. Android and desktop share the transfer format. Existing password-protected PKCS#12 imports remain supported.

Level 5 software identities contain a v6 ML-DSA-87 + Ed448 certification primary, a separate hybrid signing subkey, and ML-KEM-1024 + X448 encryption. Their two v4 public views use P-521 signing: one prefers ML-KEM-768 + X25519 encryption, and the other offers classical ECDH P-521. Classical signatures and fallback encryption remain clearly warned. The three public views and all private components survive PKCS#12 export/import; v6 is preferred when available.

New unprotected OAuth credential writes and custom Google client secrets use the vault. Existing authenticated Mac Keychain protection for the Google OAuth refresh token remains available. **Move saved settings into vault** migrates legacy IMAP/SMTP settings and unprotected account credentials; old Keychain items are removed only after the encrypted copy is saved. Legacy credentials also migrate when first restored. Vault lock releases loaded software identities, OAuth sessions and inbox connections; Java does not guarantee erasure of every immutable object from process memory. Vault contents are not automatically synchronized. A same-RP passkey alone does not transfer the encrypted vault or PKCS#12 files between devices.

Desktop automated tests use synthetic PRF material and temporary identities: vault wrapping/tamper/lock, passkey management and duplicate-enrollment preservation, settings migration, six signed-only/encrypted v6/v4 OpenPGP round trips, signature tampering, portable PKCS#12 export/import, passkey-wrapped transfer, and browser callback encryption. Browser tests also cover assertion-first enrollment, connection-check failure before authenticator access, saved Chrome selection, and 50 HTTP callback acknowledgements before listener shutdown.

**Live macOS / Chrome validation (November 19, 2026):** The existing security-key passkey unlocked the vault after **Lock vault** reported that software keys and mail sessions were released. PQ Mail was then fully quit (the old process exited) and relaunched. The app required a fresh unlock, remembered the passkey label and Chrome preference, and accepted the same passkey again; both runs ended with **Passkey vault unlocked**. No passkey was created or replaced and no email was sent. This verifies the tested Mac, Chrome and security-key combination; native Apple AuthenticationServices and other desktop browsers have not been validated.

Selecting an already enrolled passkey while managing an unlocked vault is now an informational no-op: its label, PRF salt, wrapped vault key and payload are preserved. It no longer produces the misleading Java I/O error.

**Mac packaging:** Sign the bundled Java runtime and native components inside-out with the app identity using `scripts/sign-macos.sh`, preserving the separately provisioned Keychain helper. Signing only the outer app can pass bundle verification yet fail at launch when Java libraries have a different Team ID. The repaired package was launch-tested before the live vault tests.

**Native Linux passkeys:** amd64 and ARM64 packages include an assertion-only YubiKit USB HID helper. Choose **Keys → Passkey method → Native Linux — YubiKey USB**, select your saved passkey name, enter the FIDO2 PIN in PQ Mail, and touch the key. Existing credential IDs and PRF salts are reused. Existing-passkey enrollment is supported; creating a new passkey still requires the explicitly selected Browser method. PINs and PRF output stay in anonymous pipes/memory, cancellation terminates the helper, and failed operations never automatically retry a PIN or open a browser. The Debian package includes standard FIDO udev-rule dependencies. Synthetic protocol/vault tests and package checks do not replace a live Linux YubiKey unlock/restart test, which remains pending. See [Linux native passkeys](docs/LINUX-PASSKEYS.md).

**Native Windows passkeys:** Both x64 and ARM64 builds include `pqmail-passkey.exe`. Choose **Keys → Passkey method → Native Windows — security key** to unlock an existing PRF vault with the Windows dialog, or **Native Windows — platform passkey** for a PRF-capable platform provider. It reuses the enrolled credential ID and original PRF salt. The helper loads only the system `webauthn.dll`, requires WebAuthn API v4+ and user verification, and keeps PRF output in a parent/child process pipe. Cancellation, missing PRF, and unsupported APIs leave the vault locked without opening a browser. **Use existing passkey** supports native assertion-based enrollment; creation still requires the explicitly selected Browser method. Installer CI checks native architecture, request/options/result handling and helper loading. A real Windows YubiKey unlock and restart test remains pending; compilation and synthetic tests do not establish hardware interoperability. See [Windows passkey setup](docs/WINDOWS.md#native-passkey-vault-unlock).

**Native macOS passkeys (integration awaiting live validation):** **Keys → Passkey method** can select AuthenticationServices for an existing USB security-key passkey or a platform passkey. The native helper uses the same RP (`ve7jtb.github.io`), enrolled credential ID and raw PRF salt as the browser, requires user verification, and returns its result through an anonymous process pipe. There is no browser, loopback listener, new credential, or automatic browser fallback during native unlock. **Use existing passkey** supports native discovery; creating a new credential still uses the explicitly selected Browser method. Native security-key PRF requires macOS 26.4 or later. Builds without the provisioned helper retain the browser method.

Build the helper with `PQ_MAIL_APPLE_TEAM` using `bash scripts/build-passkey-helper.sh`; set `PQ_MAIL_NATIVE_PASSKEYS=1` when packaging it. It needs the App ID `io.github.ve7jtb.pqmail.passkey`, the Associated Domains entitlement `webcredentials:ve7jtb.github.io`, and a matching nonexpired provisioning profile. Developer ID builds also require `PQ_MAIL_PASSKEY_PROFILE`. The RP's `.well-known/apple-app-site-association` must authorize the actual `TEAMID.io.github.ve7jtb.pqmail.passkey` identifier. Packaging checks the helper signature, profile, team, App ID and domain entitlement. Personal Teams cannot provision this capability. See [native passkey setup](docs/NATIVE-PASSKEYS.md).

Desktop passkey troubleshooting: **Keys → Passkey browser** uses explicit **Use Google Chrome** / **Use default browser** buttons and confirms the saved choice. Browser network access is checked before any authenticator operation. A local connection error is not evidence of a missing passkey. If the browser cannot reach localhost, start a fresh request in Chrome and approve local-app access. HTTP callback acknowledgements are flushed before the listener shuts down.

Build dependency security notes, exact source pins, and the remaining Rust RSA dependency finding are in [the November 2026 dependency review](docs/DEPENDENCY-SECURITY-2026-11.md).
