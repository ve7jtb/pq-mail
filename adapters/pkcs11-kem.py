#!/usr/bin/env python3
"""PKCS#11 ML-KEM decapsulation/ECDH. Shared secrets go only through stdout pipe."""
import base64
import hmac
import importlib.util
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile

_spec=importlib.util.spec_from_file_location('pkcs11_sign',Path(__file__).with_name('pkcs11-mu.py'))
_common=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_common)
AdapterError=_common.AdapterError


def object_id(slot):
    slots={'9d':3}
    slots.update({format(n,'02x'):n-0x82+5 for n in range(0x82,0x96)})
    if slot.lower() not in slots:raise AdapterError('Use a separate encryption slot: 9d or 82–95; signing slots are excluded')
    return '%'+format(slots[slot.lower()],'02X')


def read_request(stream):
    lines=[stream.readline(8193) for _ in range(3)]
    if any(len(line)>8192 or not line.endswith(b'\n') for line in lines):raise AdapterError('Malformed KEM request')
    if lines[0] not in (b'ML-KEM-768\n',b'ML-KEM-1024\n',b'ECDH-P256\n',b'ECDH-P384\n',b'X25519\n'):raise AdapterError('Unsupported private operation')
    try:public,data=[base64.b64decode(line.strip(),validate=True) for line in lines[1:]]
    except ValueError as error:raise AdapterError('Invalid request encoding') from error
    algorithm=lines[0].decode().strip()
    if algorithm=='ML-KEM-768':
        if not 1190<=len(public)<=1250 or len(data)!=1088:raise AdapterError('Expected ML-KEM-768 key and 1088-byte ciphertext')
    elif algorithm=='ML-KEM-1024':
        if not 1570<=len(public)<=1620 or len(data)!=1568:raise AdapterError('Expected ML-KEM-1024 and 1568-byte ciphertext')
    elif algorithm=='X25519':
        if len(public)!=44 or len(data)!=44:raise AdapterError('Expected X25519 SPKIs')
    elif not 80<=len(public)<=150 or not 80<=len(data)<=150:raise AdapterError('Expected P-256 recipient and peer SPKIs')
    return algorithm,public,data


def export_public(executable,provider,module,serial,slot,algorithm,run=subprocess.run):
    check_config(executable,serial)
    if _common.polyfill_mode() and slot!=selected_slot(algorithm):raise AdapterError('Wrong Level 3 polyfill slot')
    uri='pkcs11:serial='+serial+';id='+object_id(slot)+';type=public'
    with tempfile.TemporaryDirectory(prefix='hybrid-mail-kem-public-') as directory:
        folder=Path(directory);config=folder/'openssl.cnf';public=folder/'public.der'
        config.write_text(_common.configuration(provider,module,public=True),encoding='utf-8')
        result=run([executable,'pkey','-provider','default','-provider','pkcs11','-pubin','-in',uri,'-pubout','-outform','DER','-out',str(public)],
                   stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env=_common.child_environment(config,object_id(slot)),timeout=30)
        if result.returncode or not public.exists():raise AdapterError('Cannot export encryption slot public key'+_common.safe_openssl_error(result))
        size=public.stat().st_size
        if not (1190<=size<=1250 if algorithm=='ML-KEM-768' else 1570<=size<=1620 if algorithm=='ML-KEM-1024' else size==44 if algorithm=='X25519' else 80<=size<=150):raise AdapterError('Unexpected encryption public key type')
        return public.read_bytes()


def check_config(executable,serial):
    if not Path(executable).is_absolute() or not serial.isdecimal():raise AdapterError('Set absolute OPENSSL_BIN and explicit PKCS11_SERIAL')


def single_process_recover(helper,algorithm,public,data,provider,module,serial,slot,pin,run):
    with tempfile.TemporaryDirectory(prefix='pqmail-kem-session-') as directory:
        folder=Path(directory);config=folder/'openssl.cnf'
        config.write_text(_common.configuration(provider,module),encoding='utf-8')
        expected=folder/'expected.der';expected.write_bytes(public)
        incoming=folder/'public-input.der';incoming.write_bytes(data)
        result=run([str(helper),algorithm,'pkcs11:serial='+serial+';id='+object_id(slot)+';type=',str(expected),str(incoming)],
                   input=bytes(pin)+b'\n',stdout=subprocess.PIPE,stderr=subprocess.PIPE,
                   env=_common.child_environment(config,object_id(slot)),timeout=100,**_common.native_process_options())
        if result.returncode:raise AdapterError(single_process_failure(result,algorithm))
        if len(result.stdout)!=(48 if algorithm=='ECDH-P384' else 32):raise AdapterError('Invalid token shared secret length')
        return result.stdout


def single_process_failure(result,algorithm):
    """Expose fixed helper stages and public error codes, never raw stderr.

    The previous OpenSSL-only parser discarded the helper's failure stage,
    making failures before PIN input indistinguishable from private-operation
    failures. A closed stage list also rejects injected paths or input data.
    """
    raw=getattr(result,'stderr',b'')
    if not isinstance(raw,bytes):raw=b''
    raw=raw[:32768]
    stages=(b'arguments',b'input',b'PIN callback setup',b'providers',b'public key check',
            b'PIN input',b'private key check',b'recover',b'output')
    prefix=b'PQ Mail single-session decryption failed at '
    suffix=b'; no retry'
    steps=(b'key-type',b'context',b'ciphertext-length',b'decapsulate-init',b'decapsulate',
           b'peer-decode',b'peer-check',b'derive-init',b'derive-set-peer',b'derive',b'secret-length')
    stage='';details=[];callbacks=False;recovery_step=False
    for line in raw.splitlines():
        if line.startswith(prefix) and line.endswith(suffix):
            value=line[len(prefix):-len(suffix)]
            if value in stages and not stage:stage=' at '+value.decode('ascii')
        elif len(details)<8 and re.fullmatch(rb'PQMAIL_ERROR [0-9A-F]{8,16} [A-Za-z0-9 _()-]{1,120}',line):
            details.append(line.decode('ascii'))
        elif not callbacks and re.fullmatch(rb'PQMAIL_PIN_CALLBACKS [0-9]{1,4}',line):
            details.append(line.decode('ascii'));callbacks=True
        elif not recovery_step and line.startswith(b'PQMAIL_KEM_STEP ') and line[16:] in steps:
            details.append(line.decode('ascii'));recovery_step=True
    return 'Single-process PKCS#11 '+algorithm+' failed'+stage+'; no retry'+('; '+'; '.join(details) if details else '')


def recover(algorithm,public,data,executable,provider,module,serial,slot,pin,run=subprocess.run):
    try:
        check_config(executable,serial)
        if algorithm not in ('ML-KEM-768','ML-KEM-1024','ECDH-P256','ECDH-P384','X25519'):raise AdapterError('Unsupported private operation')
        if not 6<=len(pin)<=8 or any(c<32 or c>126 for c in pin):raise AdapterError('Invalid PIN input format')
        # Do not accept a direct caller's slot override for this closed layout.
        # Its ML-KEM secret key is software; the device only performs X25519 and
        # no-touch P-384 wrapping-key operations.
        if _common.polyfill_mode() and slot!=selected_slot(algorithm):raise AdapterError('Wrong Level 3 polyfill slot')
        helper=Path(executable).with_name('pqmail-pkcs11-kem.exe' if os.name=='nt' else 'pqmail-pkcs11-kem')
        if helper.is_file():
            return single_process_recover(helper,algorithm,public,data,provider,module,serial,slot,pin,run)
        actual=export_public(executable,provider,module,serial,slot,algorithm,run)
        if not hmac.compare_digest(public,actual):raise AdapterError('Encryption slot public key does not match the recipient identity')
        uri='pkcs11:serial='+serial+';id='+object_id(slot)+';type=private'
        with tempfile.TemporaryDirectory(prefix='hybrid-mail-kem-') as directory:
            folder=Path(directory);config=folder/'openssl.cnf';input_file=folder/'public-input.der'
            config.write_text(_common.configuration(provider,module),encoding='utf-8');input_file.write_bytes(data)
            env=_common.child_environment(config,object_id(slot));env['HYBRID_MAIL_PIN_STDIN']='1'
            command=[executable,'pkeyutl','-provider','default','-provider','pkcs11','-inkey',uri]
            command+=['-decap','-in',str(input_file)] if algorithm.startswith('ML-KEM-') else ['-derive','-peerkey',str(input_file),'-peerform','DER']
            if os.name=='nt':
                result=run(command+['-passin','stdin'],input=bytes(pin)+b'\n',stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=100)
            else:
                read_fd,write_fd=os.pipe()
                try:
                    os.write(write_fd,pin);os.write(write_fd,b'\n');os.close(write_fd);write_fd=-1
                    result=run(command+['-passin','fd:'+str(read_fd)],pass_fds=(read_fd,),stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=100)
                finally:
                    os.close(read_fd)
                    if write_fd!=-1:os.close(write_fd)
            if result.returncode:raise AdapterError('PKCS#11 '+algorithm+' failed; no retry'+_common.safe_openssl_error(result))
            if len(result.stdout)!=(48 if algorithm=='ECDH-P384' else 32):raise AdapterError('Invalid token shared secret length')
            return result.stdout
    finally:pin[:]=b'\0'*len(pin)


def selected_slot(algorithm):
    if _common.polyfill_mode():
        if os.environ.get('PQMAIL_POLYFILL_CERTIFICATION') is not None:raise AdapterError('Certification profile cannot decrypt')
        if algorithm not in ('X25519','ECDH-P384'):raise AdapterError('Level 3 polyfill keeps ML-KEM decapsulation in software')
        return '9d' if algorithm=='X25519' else '83'
    slot=os.environ.get('PKCS11_KEM_SLOT' if algorithm.startswith('ML-KEM-') else 'PKCS11_ECDH_SLOT','')
    if algorithm=='X25519':slot='85'
    if os.environ.get('PQMAIL_COMPATIBILITY_SLOT'):
        if algorithm!='X25519' or os.environ['PQMAIL_COMPATIBILITY_SLOT']!='89':raise AdapterError('Invalid compatibility slot')
        slot='89'
    if os.environ.get("PQMAIL_LEVEL5_COMPATIBILITY"):
        if os.environ["PQMAIL_LEVEL5_COMPATIBILITY"]!="1" or algorithm not in ("ML-KEM-768","X25519","ECDH-P384"):raise AdapterError("Invalid Level 5 compatibility encryption operation")
        slot={"ML-KEM-768":"84","X25519":"85","ECDH-P384":"89"}[algorithm]
    return slot

def main():
    pin=None
    try:
        values=[os.environ.get(n,'') for n in ('OPENSSL_BIN','PKCS11_PROVIDER','PKCS11_MODULE','PKCS11_SERIAL')]
        if not all(values):raise AdapterError('Set OpenSSL, provider, module and token serial configuration')
        if sys.argv[1:] in (['--export-mlkem'],['--export-ecdh']):
            polyfill=_common.polyfill_mode()
            algorithm='ML-KEM-768' if sys.argv[1]=='--export-mlkem' else 'ECDH-P384' if polyfill else 'ECDH-P256'
            slot=selected_slot(algorithm) if polyfill else os.environ.get('PKCS11_KEM_SLOT' if algorithm.startswith('ML-KEM-') else 'PKCS11_ECDH_SLOT','')
            sys.stdout.buffer.write(export_public(*values,slot,algorithm));return 0
        if len(sys.argv)!=1 or os.environ.get('HYBRID_MAIL_PIN_STDIN')!='1':raise AdapterError('Use the app PIN dialog for token decryption')
        algorithm,public,data=read_request(sys.stdin.buffer)
        pin=bytearray(sys.stdin.buffer.readline(10))
        if not pin.endswith(b'\n'):raise AdapterError('Missing app PIN input')
        del pin[-1:]
        slot=selected_slot(algorithm)
        secret=recover(algorithm,public,data,*values,slot,pin)
        sys.stdout.buffer.write(secret);sys.stdout.buffer.flush();return 0
    except (AdapterError,OSError,subprocess.SubprocessError) as error:
        message=str(error) if isinstance(error,AdapterError) else 'PKCS#11 KEM I/O failure or timeout'
        print('PQ Mail: '+message,file=sys.stderr);return 1
    finally:
        if pin is not None:pin[:]=b'\0'*len(pin)

if __name__=='__main__':sys.exit(main())
