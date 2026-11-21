#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
source scripts/check-java.sh
command -v javac >/dev/null || { echo 'Install JDK 25 and set JAVA_HOME.' >&2; exit 1; }
[[ -f lib/bcprov-jdk18on-1.88-SNAPSHOT.jar ]] || { echo 'Run ./scripts/build-dependencies.sh first.' >&2; exit 1; }
mkdir -p build/classes
if [[ "$(uname -s)" == Darwin ]]; then
  mkdir -p build/native
  bash scripts/build-share-helper.sh
  clang -x objective-c -fobjc-arc -fblocks -O2 -framework LocalAuthentication -framework Foundation -framework Security -framework CoreFoundation native-src/keychain.c -o build/native/hybrid-mail-keychain
  codesign --force --sign - --identifier dev.hybridmail.keychain build/native/hybrid-mail-keychain
fi
javac -encoding UTF-8 -cp 'lib/*' -d build/classes src/dev/hybridmail/*.java
# Optional shared installed-app client. Keep configuration out of source control.
python3 scripts/bundle-google-client.py
python3 scripts/bundle-chat-client.py
jar --create --file build/hybrid-mail.jar --main-class dev.hybridmail.MailApp -C build/classes .
if [[ "${1:-}" == test ]]; then
  java scripts/CheckJava.java --test
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.PasskeyBrowserTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.PasskeyCallbackTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.NativePasskeyTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.LinuxPasskeyTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.WindowsPasskeyTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.DesktopVaultTest
  if command -v node >/dev/null; then node tests/test_desktop_passkey.cjs; fi
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.ComposeFormatPolicyTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.SelfTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.TokenIdentityTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.TokenKemTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.Token87Test
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.DesktopStateTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.DesktopInboxSearchTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.MailAccountTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.GmailApiTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.GoogleChatExperimentTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.GoogleChatVaultTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.GoogleChatTransportTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.ChatBundleTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.MicrosoftMailTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.HotmailWrapperTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.OnKeyBundleTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.OnKeySingleTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.CertificateBundleTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.ConventionalTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.SoftwareProfilesTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.OpenPgpTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.OpenPgpTransportTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.Rfc9980Test tests/fixtures
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.Level3OpenPgpSetupTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.OpenPgpMigrationTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.LegacyOpenPgpPolicyTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.OpenPgpContactsTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.PgpTrustSelectionTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.VerifiedMimeTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.SafeMailHtmlTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.FormattedComposeTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.Level5CompatibilityTest
  java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' dev.hybridmail.V4RecipientPacketTest
  # Companion tests use synthetic keys and fake storage, never a physical card.
  for companion_test in Level5CompanionTest CompanionEncodingTest CompanionCompactTest UltraCertificateTest CompanionUltraStorageTest CompanionDesktopTest Level3CompanionTest TokenPolyfillProvisionTest Level3PolyfillDesktopTest Level3ManagementTest; do
    java -Djava.awt.headless=true -cp 'build/hybrid-mail.jar:lib/*' "dev.hybridmail.$companion_test"
  done
  python3 -m unittest discover -s tests -v
fi
