#!/usr/bin/env python3
"""Compile the canonical desktop crypto core on Android, excluding process adapters.
Only platform shims below differ; algorithms and CMS processing stay shared.
"""
from pathlib import Path
import zipfile
root = Path(__file__).resolve().parent
src = root.parent / 'src/dev/hybridmail'
out = root / 'app/build/generated/shared/dev/hybridmail'
out.mkdir(parents=True, exist_ok=True)
# The public-certificate parser routes optional v5 keys through LibreOpenPgp.
# Sharing that codec does not enable desktop process/companion adapters here.
for name in ['IdentityTransfer','PrfVault','RegistrationCbor','SoftwareIdentityVault','SoftwareOpenPgp','ComposeFormatPolicy','Level5Compatibility','OnKeyBundle','OnKeyStorage','CertificateBundle','Identity','TokenProfile','MailEngine','ImapInbox','MailInbox','ExternalMu','ExternalKem','OpenPgp','VerifiedMime','LegacyOpenPgp','LibreOpenPgp','OpenPgpRecipients','CryptoWarnings']:
    s=(src/(name+'.java')).read_text()
    if name=='ExternalMu':
        marker='    /** Executable protocol:'
        assert s.count(marker)==1
        s=s[:s.index(marker)]+'}\n'
        s=s.replace('new Provider("ExternalMu", "1.0",','new Provider("ExternalMu", 1.0,')
    if name=='ExternalKem':
        a=s.index('    public static Backend executable(')
        b=s.index('    public static void validatePublicKey',a)
        s=s[:a]+s[b:]
    s=s.replace('entries.getFirst()', 'entries.get(0)')
    s=s.replace('HexFormat.ofDelimiter(":").withUpperCase().formatHex(', 'AndroidHex.format(')
    (out/(name+'.java')).write_text(s)
libs=root/'app/build/android-libs'
libs.mkdir(parents=True,exist_ok=True)
for old in libs.glob('*.jar'): old.unlink()
jars=list((root.parent/'lib').glob('*.jar'))
assert len(jars)>=8, 'Build desktop dependencies first: scripts/build-dependencies.sh'
for p in jars:
    if p.name.startswith(('jakarta.activation', 'angus-activation')): continue
    with zipfile.ZipFile(p) as source, zipfile.ZipFile(libs/p.name,'w',zipfile.ZIP_DEFLATED) as dest:
        for item in source.infolist():
            n=item.filename
            if n.startswith('META-INF/versions/') or n.endswith('module-info.class') or n.upper().endswith(('.SF','.RSA','.DSA')):continue
            dest.writestr(item,source.read(n))

# Run the canonical legacy certificate policy tests on Android too.
test_out=root/'app/build/generated/shared-tests/dev/hybridmail'
test_out.mkdir(parents=True,exist_ok=True)
for name in ['LegacyOpenPgpTest','LegacyOpenPgpPolicyTest']:
    (test_out/(name+'.java')).write_text((src/(name+'.java')).read_text())
