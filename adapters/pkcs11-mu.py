#!/usr/bin/env python3
"""OpenSSL pkcs11-provider PR #818 -> Yubico PKCS#11 external-mu signing.

PIN uses an anonymous pipe from the app to OpenSSL; never args/env/files.
Terminal callers can use the provider native PIN prompt.
Requires OPENSSL_BIN, PKCS11_PROVIDER, PKCS11_MODULE and PKCS11_SERIAL.
"""
import base64
import hmac
import io
import importlib.util
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile

# Share only the wire protocol; no ykman command or fallback is used.
_spec = importlib.util.spec_from_file_location("mu_protocol", Path(__file__).with_name("ykman-mu.py"))
_protocol = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_protocol)
AdapterError = _protocol.AdapterError
def read_request(stream):
    algorithm = stream.readline(16385)
    profiles={b"Ed25519\n":(48,44,44),b"ML-DSA-44\n":(64,1320,1360),b"ML-DSA-65\n":(64,1900,2100),b"ML-DSA-87\n":(64,2590,2650),b"ECDSA-P256-SHA256\n":(32,80,150),b"ECDSA-P384-SHA384\n":(48,110,150),b"RSA3072-PSS-SHA256\n":(32,390,500)}
    if algorithm not in profiles:raise AdapterError("Unsupported signing algorithm")
    fields=[stream.readline(16385) for _ in range(2)]
    if any(len(line)>16384 or not line.endswith(b"\n") for line in fields):raise AdapterError("Malformed signing request")
    try:spki,payload=[base64.b64decode(line.strip(),validate=True) for line in fields]
    except ValueError as error:raise AdapterError("Invalid base64 request") from error
    size,low,high=profiles[algorithm]
    # Ed25519 signs the OpenPGP hash as a raw message, including SHA-256
    # selected by classical GnuPG callers; ML-DSA still requires external mu.
    valid_size = len(payload) in (32,48,64) if algorithm==b"Ed25519\n" else len(payload)==size
    if not valid_size or not low<=len(spki)<=high:raise AdapterError("Invalid signing key or input length")
    return algorithm.decode().strip(),spki,payload


def ec_object_id(slot):
    # Yubico PIV mapping: 9a=1, 9c=2, 9d=3, 9e=4; retired 82..95=5..24.
    slots = {"9a":1,"9d":3,"9e":4}
    slots.update({format(n,"02x"):n-0x82+5 for n in range(0x82,0x96)})
    if slot.lower() not in slots:
        raise AdapterError("Set PKCS11_TRADITIONAL_SLOT to the existing conventional slot; 9c is reserved for ML-DSA")
    return "%" + format(slots[slot.lower()],"02X")


def polyfill_mode():
    """Select only the closed Level 3 classical-card mapping.

    A certificate cannot name arbitrary commands or override another profile.
    Generic PKCS11_* slot defaults are ignored by this explicit profile; named
    compatibility/certification profiles conflict and must be cleared by callers.
    """
    value=os.environ.get("PQMAIL_LEVEL3_POLYFILL")
    certification=os.environ.get("PQMAIL_POLYFILL_CERTIFICATION")
    if value is None:
        if certification is not None:
            raise AdapterError("Polyfill certification requires the Level 3 polyfill profile")
        return False
    if value!="1" or (certification is not None and certification!="1"):
        raise AdapterError("Invalid Level 3 polyfill profile flag")
    if any(os.environ.get(name) for name in ("PQMAIL_LEVEL5_COMPATIBILITY","PQMAIL_COMPATIBILITY_SLOT","PQMAIL_CERTIFICATION_SLOTS")):
        raise AdapterError("Conflicting token profiles for Level 3 polyfill")
    return True


def signing_object_id(algorithm,ec_slot):
    if polyfill_mode():
        if algorithm!="Ed25519":
            raise AdapterError("Level 3 polyfill keeps ML-DSA signing in software")
        # 9c is permitted only in this closed profile, without weakening the
        # historical ec_object_id guard that reserves it for token ML-DSA.
        return "%05" if os.environ.get("PQMAIL_POLYFILL_CERTIFICATION")=="1" else "%02"
    object_id="%02" if algorithm.startswith("ML-DSA-") else ec_object_id("84" if algorithm=="Ed25519" else ec_slot)
    if os.environ.get("PQMAIL_LEVEL5_COMPATIBILITY"):
        if os.environ["PQMAIL_LEVEL5_COMPATIBILITY"]!="1" or algorithm!="ECDSA-P384-SHA384":raise AdapterError("Invalid Level 5 compatibility signing operation")
        object_id=ec_object_id("88")
    compatibility=os.environ.get("PQMAIL_COMPATIBILITY_SLOT","")
    if compatibility:
        if compatibility!="88" or algorithm!="Ed25519":raise AdapterError("Invalid compatibility slot")
        object_id=ec_object_id("88")
    certification=os.environ.get("PQMAIL_CERTIFICATION_SLOTS","")
    if certification:
        if certification!="86,87" or algorithm not in ("ML-DSA-65","ML-DSA-87","Ed25519"):
            raise AdapterError("Invalid certification slot configuration")
        object_id=ec_object_id("86" if algorithm in ("ML-DSA-65","ML-DSA-87") else "87")
    return object_id


def config_path(value):
    if (os.name!="nt" and "\\" in value) or not Path(value).is_absolute() or any(c in value for c in '\r\n"$'):
        raise AdapterError("Provider/module paths must be absolute and contain no config metacharacters")
    return '"' + value.replace('\\','/') + '"'


def configuration(provider, module, public=False):
    return ("openssl_conf = init\nconfig_diagnostics = 1\n"
            "[init]\nproviders = providers\n"
            "[providers]\ndefault = default_provider\npkcs11 = token_provider\n"
            "[default_provider]\nactivate = 1\n"
            "[token_provider]\nmodule = " + config_path(provider) + "\n"
            "pkcs11-module-path = " + config_path(module) + "\n"
            # Cache only inside this short-lived OpenSSL invocation, for an
            # ALWAYS_AUTHENTICATE key's context-specific login after user login.
            "pkcs11-module-cache-pins = cache\nactivate = 1\n" + ("pkcs11-module-login-behavior = never\n" if public else ""))


def native_process_options():
    """Keep descendants in the trusted outer supervisor's isolated POSIX group.

    Sequoia/GnuPG supervisors explicitly set this flag after creating their own
    process group. Starting another session here would let native helpers escape
    that group's deadline cleanup. Ordinary app/Terminal calls keep the existing
    new-session behavior. This flag never changes algorithm, slot or PIN policy.
    """
    supervised = os.environ.get("PQMAIL_SUPERVISED_PROCESS_GROUP")
    if supervised is not None:
        if supervised != "1" or os.name != "posix":
            raise AdapterError("Invalid supervised process-group configuration")
        return {"start_new_session": False}
    return {} if os.name == "nt" else {"start_new_session": True}


def child_environment(config_file, object_id=None):
    env = os.environ.copy()
    for name in list(env):
        if name.startswith("PKCS11_PROVIDER_") or name in ("OPENSSL_CONF", "OPENSSL_CONF_INCLUDE", "OPENSSL_MODULES", "YKCS11_DISCOVERY", "YKCS11_DISCOVERY_ID"):
            del env[name]
    if object_id is not None:
        if not re.fullmatch(r"%[0-9a-fA-F]{2}", object_id) or not 1 <= int(object_id[1:],16) <= 24:
            raise AdapterError("Invalid discovery object ID")
        # Limit live metadata discovery to the exact key we will compare/sign.
        # Older modules ignore these flags and retain their existing behavior.
        env["YKCS11_DISCOVERY"] = "metadata"
        env["YKCS11_DISCOVERY_ID"] = str(int(object_id[1:],16))
    env["OPENSSL_CONF"] = str(config_file)
    return env


def export_traditional(executable, provider, module, serial, slot, terminal, ml=False):
    if not serial.isdecimal() or not Path(executable).is_absolute():
        raise AdapterError("Set explicit token serial and absolute OpenSSL path")
    polyfill=polyfill_mode()
    if polyfill and ml:raise AdapterError("Level 3 polyfill has no on-device ML-DSA key")
    selected=signing_object_id("Ed25519",slot) if polyfill else "%02" if ml else ec_object_id(slot)
    uri="pkcs11:serial="+serial+";id="+selected+";type=public"
    with tempfile.TemporaryDirectory(prefix="hybrid-mail-ec-public-") as temporary:
        folder=Path(temporary);config=folder/"openssl.cnf";public=folder/"public.der"
        config.write_text(configuration(provider,module,public=True),encoding="utf-8")
        result=subprocess.run([executable,"pkey","-provider","default","-provider","pkcs11",
                               "-pubin","-in",uri,"-pubout","-outform","DER","-out",str(public)],
                              stdin=terminal,stderr=terminal,stdout=subprocess.DEVNULL,env=child_environment(config),timeout=30)
        if result.returncode or not public.exists() or not (public.stat().st_size==44 if polyfill else 1900<=public.stat().st_size<=2650 if ml else 80<=public.stat().st_size<=500):
            raise AdapterError("Cannot export conventional public key from configured slot")
        return public.read_bytes()


def public_keys_match(expected, actual_file, algorithm, executable, folder, env, run):
    actual=actual_file.read_bytes()
    if hmac.compare_digest(expected,actual):return True
    if algorithm!="RSA3072-PSS-SHA256":return False
    # Composite key decoding may omit rsaEncryption's NULL parameters. Compare
    # canonical PKCS#1 RSAPublicKey (modulus and exponent), not SPKI wrappers.
    expected_file=folder/"expected-public.der";expected_file.write_bytes(expected)
    canonical=[]
    for index,source in enumerate((expected_file,actual_file)):
        target=folder/("rsa-canonical-"+str(index)+".der")
        result=run([executable,"rsa","-provider","default","-pubin","-inform","DER","-in",str(source),
                    "-RSAPublicKey_out","-outform","DER","-out",str(target)],
                   stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,env=env,timeout=10)
        if result.returncode or not target.exists() or not 390<=target.stat().st_size<=410:
            raise AdapterError("Cannot canonicalize RSA-3072 public key")
        canonical.append(target.read_bytes())
    return hmac.compare_digest(*canonical)


def safe_openssl_error(result):
    # Only OpenSSL error identifiers and reason fields; never input values or debug dumps.
    raw=getattr(result,"stderr",None)
    if not isinstance(raw,bytes):return ""
    matches=re.findall(rb"error:[0-9A-Fa-f]+:[^:\r\n]+:[^:\r\n]*:[^:\r\n]+",raw)
    return "; "+b"; ".join(matches[:3]).decode("ascii",errors="replace")[:600] if matches else ""


def single_process_sign(helper,spki,payload,provider,module,serial,object_id,algorithm,pin,run):
    try:
        if not 6<=len(pin)<=8 or any(c<32 or c>126 for c in pin):
            raise AdapterError("Invalid PIN input format")
        with tempfile.TemporaryDirectory(prefix="pq-mail-pkcs11-sign-") as directory:
            folder=Path(directory);config=folder/"openssl.cnf";public=folder/"expected.der";data=folder/"input.bin";signature=folder/"signature.bin"
            config.write_text(configuration(provider,module),encoding="utf-8")
            public.write_bytes(spki);data.write_bytes(payload)
            env=child_environment(config,object_id)
            # The helper checks the live key before reading the PIN, and uses
            # the provider callback. Never retry/fall back after a failure.
            command=[str(helper),algorithm,"pkcs11:serial="+serial+";id="+object_id+";type=",str(public),str(data),str(signature)]
            options=native_process_options()
            result=run(command,input=bytes(pin)+b"\n",stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,env=env,timeout=100,**options)
            if result.returncode:
                raw=getattr(result,"stderr",b"") or b""
                match=re.search(rb"single-session signer failed at ([a-z -]+); no retry",raw)
                stage=" at "+match.group(1).decode("ascii") if match else ""
                details=[]
                for line in raw.splitlines():
                    if re.fullmatch(rb"PQMAIL_ERROR [0-9A-F]{8,16} [A-Za-z0-9 _()-]{1,120}",line) or re.fullmatch(rb"PQMAIL_PIN_CALLBACKS [0-9]{1,4}",line):
                        details.append(line.decode("ascii"))
                raise AdapterError("Single-process PKCS#11 signing failed"+stage+"; no retry"+("; "+"; ".join(details[:9]) if details else ""))
            if not signature.exists() or signature.stat().st_size>8192:raise AdapterError("Missing or oversized signature")
            signed=signature.read_bytes();validate_signature_length(algorithm,len(signed));return signed
    finally:pin[:]=b"\0"*len(pin)

def validate_signature_length(algorithm,size):
    valid = {"Ed25519":size==64,"ML-DSA-44":size==2420,"ML-DSA-65":size==3309,"ML-DSA-87":size==4627,
             "ECDSA-P384-SHA384":8<=size<=104,"ECDSA-P256-SHA256":8<=size<=72,"RSA3072-PSS-SHA256":size==384}
    if not valid.get(algorithm,False):raise AdapterError("Unexpected signature length")


def sign(spki, mu, executable, provider, module, serial, terminal, run=subprocess.run, algorithm="ML-DSA-65", ec_slot="", pin=None):
    # A rejected profile/key/configuration must clear the supplied PIN just as
    # a failed private operation does. The CLI also clears its buffer on exit.
    try:return _sign(spki,mu,executable,provider,module,serial,terminal,run,algorithm,ec_slot,pin)
    finally:
        if pin is not None:pin[:]=b"\0"*len(pin)


def _sign(spki, mu, executable, provider, module, serial, terminal, run, algorithm, ec_slot, pin):
    if not serial.isdecimal():
        raise AdapterError("Set PKCS11_SERIAL to the intended token serial")
    if not Path(executable).is_absolute():
        raise AdapterError("OPENSSL_BIN must be an absolute path")
    config = configuration(provider, module)
    # The Yubico module maps PIV signature slot 9c to binary CKA_ID 02.
    if algorithm not in ("ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "ECDSA-P256-SHA256", "ECDSA-P384-SHA384", "RSA3072-PSS-SHA256", "Ed25519"):
        raise AdapterError("Unsupported signing algorithm")
    object_id=signing_object_id(algorithm,ec_slot)
    helper=Path(executable).with_name("pqmail-pkcs11-sign.exe" if os.name=="nt" else "pqmail-pkcs11-sign")
    if pin is not None and helper.is_file():
        return single_process_sign(helper,spki,mu,provider,module,serial,object_id,algorithm,pin,run)
    uri = "pkcs11:serial=" + serial + ";id=" + object_id + ";type="
    with tempfile.TemporaryDirectory(prefix="hybrid-mail-pkcs11-") as temporary:
        folder = Path(temporary)
        config_file, public_file, mu_file, sig_file = (folder / n for n in ("openssl.cnf", "public.der", "mu.bin", "signature.bin"))
        config_file.write_text(configuration(provider,module,public=True), encoding="utf-8")
        env = child_environment(config_file, object_id)
        common = dict(stdin=terminal, stderr=subprocess.PIPE if pin is not None else terminal, stdout=subprocess.DEVNULL, env=env)
        exported = run([executable,"pkey","-provider","default","-provider","pkcs11",
                        "-pubin","-in",uri+"public","-pubout","-outform","DER","-out",str(public_file)],
                       timeout=30, **common)
        if exported.returncode:
            raise AdapterError("Cannot export PKCS#11 public key; check module, serial and selected slot"+safe_openssl_error(exported))
        if public_file.stat().st_size > 4096 or not public_keys_match(spki,public_file,algorithm,executable,folder,env,run):
            raise AdapterError("PKCS#11 selected slot public key does not match this identity")
        config_file.write_text(config,encoding="utf-8")
        mu_file.write_bytes(mu)
        terminal.write(("\nPQ Mail: PKCS#11 " + algorithm + " signing. Enter PIN and touch the key.\n").encode())
        terminal.flush()
        options = ["-rawin"] if algorithm=="Ed25519" else ["-pkeyopt","mu:1"] if algorithm.startswith("ML-DSA-") else ["-pkeyopt","digest:sha384" if algorithm=="ECDSA-P384-SHA384" else "digest:sha256"]
        if algorithm == "RSA3072-PSS-SHA256":
            options += ["-pkeyopt","rsa_padding_mode:pss","-pkeyopt","rsa_pss_saltlen:32","-pkeyopt","rsa_mgf1_md:sha256"]
        command = [executable,"pkeyutl","-provider","default","-provider","pkcs11",
                      "-sign"] + options + ["-inkey",uri+"private",
                      "-in",str(mu_file),"-out",str(sig_file)]
        if pin is None:
            signed=run(command,timeout=100,**common)
        else:
            if not 6<=len(pin)<=8 or any(c<32 or c>126 for c in pin):
                raise AdapterError("Invalid PIN input format")
            env["HYBRID_MAIL_PIN_STDIN"]="1"
            if os.name=="nt":
                args=dict(common);args.pop("stdin",None)
                try:signed=run(command+["-passin","stdin"],input=bytes(pin)+b"\n",timeout=100,**args)
                finally:pin[:]=b"\0"*len(pin)
            else:
                read_fd,write_fd=os.pipe()
                try:
                    os.write(write_fd,pin);os.write(write_fd,b"\n")
                    os.close(write_fd);write_fd=-1
                    env["HYBRID_MAIL_PIN_STDIN"]="1"
                    signed=run(command+["-passin","fd:"+str(read_fd)],pass_fds=(read_fd,),timeout=100,**common)
                finally:
                    os.close(read_fd)
                    if write_fd!=-1:os.close(write_fd)
                    pin[:]=b"\0"*len(pin)
        if signed.returncode:
            raise AdapterError("PKCS#11 "+algorithm+" signing failed; no retry"+safe_openssl_error(signed))
        size = sig_file.stat().st_size
        validate_signature_length(algorithm,size)
        return sig_file.read_bytes()


def main():
    terminal = None
    pin = None
    try:
        values=[os.environ.get(n,"") for n in ("OPENSSL_BIN","PKCS11_PROVIDER","PKCS11_MODULE","PKCS11_SERIAL")]
        if not all(values):
            raise AdapterError("Set OPENSSL_BIN, PKCS11_PROVIDER, PKCS11_MODULE and PKCS11_SERIAL")
        try:
            terminal=open(os.devnull if os.environ.get("HYBRID_MAIL_PIN_STDIN")=="1" else "/dev/tty","r+b",buffering=0)
        except OSError as error:
            raise AdapterError("Launch from Terminal for OpenSSL's PIN/touch prompts") from error
        if sys.argv[1:] in (["--export-traditional"],["--export-ml"]):
            sys.stdout.buffer.write(export_traditional(*values,os.environ.get("PKCS11_TRADITIONAL_SLOT",""),terminal,ml=sys.argv[1]=="--export-ml"))
            return 0
        if len(sys.argv)!=1:
            raise AdapterError("Unsupported adapter arguments")
        algorithm,spki,mu=read_request(sys.stdin.buffer)
        if os.environ.get("HYBRID_MAIL_PIN_STDIN")=="1":
            pin=bytearray(sys.stdin.buffer.readline(10))
            if not pin.endswith(b"\n"):
                raise AdapterError("Missing app PIN input")
            del pin[-1:]
        result=sign(spki,mu,*values,terminal,algorithm=algorithm,ec_slot=os.environ.get("PKCS11_TRADITIONAL_SLOT",""),pin=pin)
        sys.stdout.buffer.write(base64.b64encode(result)+b"\n")
        sys.stdout.buffer.flush()
        return 0
    except (AdapterError,OSError,subprocess.SubprocessError) as error:
        message=str(error) if isinstance(error,AdapterError) else "PKCS#11 adapter I/O failure or timeout"
        stream=sys.stderr.buffer if os.environ.get("HYBRID_MAIL_PIN_STDIN")=="1" else (terminal if terminal is not None else sys.stderr.buffer)
        stream.write(("PQ Mail: "+message+"\n").encode());stream.flush()
        return 1
    finally:
        if pin is not None:pin[:]=b"\0"*len(pin)
        if terminal is not None:terminal.close()


if __name__=="__main__":sys.exit(main())
