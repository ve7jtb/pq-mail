import importlib.util
import io
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location("pkcs11_mu",Path(__file__).parents[1]/"adapters"/"pkcs11-mu.py")
ADAPTER=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(ADAPTER)
PUBLIC=b"p"*1974;MU=bytes(range(64));SIGNATURE=b"s"*3309

class Pkcs11AdapterTest(unittest.TestCase):
    def test_ed25519_sha256_request(self):
        import base64
        public=bytes.fromhex("302a300506032b6570032100")+bytes(32)
        digest=bytes(range(32))
        request=b"Ed25519\n"+base64.b64encode(public)+b"\n"+base64.b64encode(digest)+b"\n"
        self.assertEqual(ADAPTER.read_request(io.BytesIO(request)),("Ed25519",public,digest))

    def setUp(self):self.terminal=io.BytesIO();self.commands=[];self.paths=[]
    def fake(self,wrong_key=False,fail_sign=False,bad_length=False,fail_export=False):
        def run(command,**kwargs):
            self.commands.append(command)
            self.assertNotIn("--pin",command);self.assertNotIn("-passin",command)
            self.assertFalse(any("pin-value" in x or "pin-source" in x for x in command))
            self.assertIs(kwargs["stdin"],self.terminal);self.assertIs(kwargs["stderr"],self.terminal)
            self.assertNotIn("PKCS11_PROVIDER_MODULE",kwargs["env"])
            self.assertNotIn("PKCS11_PROVIDER_DEBUG",kwargs["env"])
            conf=Path(kwargs["env"]["OPENSSL_CONF"]);self.paths.append(conf)
            self.assertIn('module = "/provider/pkcs11.dylib"',conf.read_text())
            self.assertIn('pkcs11-module-path = "/module/libykcs11.dylib"',conf.read_text())
            self.assertNotIn("token-pin",conf.read_text())
            out=Path(command[-1]);self.paths.append(out)
            if command[1]=="pkey":
                self.assertIn("pkcs11:serial=123456;id=%02;type=public",command)
                if fail_export:return subprocess.CompletedProcess(command,1)
                out.write_bytes(b"wrong" if wrong_key else PUBLIC)
            else:
                self.assertIn("pkcs11:serial=123456;id=%02;type=private",command)
                self.assertEqual(command[command.index("-pkeyopt")+1],"mu:1")
                self.assertNotIn("-rawin",command)
                self.assertFalse(any("context-string" in x for x in command))
                self.assertEqual(Path(command[command.index("-in")+1]).read_bytes(),MU)
                if fail_sign:return subprocess.CompletedProcess(command,1)
                out.write_bytes(b"bad" if bad_length else SIGNATURE)
            return subprocess.CompletedProcess(command,0)
        return run
    def call(self,runner,serial="123456",provider="/provider/pkcs11.dylib"):
        return ADAPTER.sign(PUBLIC,MU,"/openssl",provider,"/module/libykcs11.dylib",serial,self.terminal,runner)
    def test_sign_and_cleanup(self):
        with patch.dict(os.environ,{"PKCS11_PROVIDER_MODULE":"/wrong","PKCS11_PROVIDER_DEBUG":"file:/wrong"}):
            self.assertEqual(self.call(self.fake()),SIGNATURE)
        self.assertEqual(len(self.commands),2);self.assertTrue(all(not p.exists() for p in self.paths))
    def test_wrong_key_does_not_sign(self):
        with self.assertRaises(ADAPTER.AdapterError):self.call(self.fake(wrong_key=True))
        self.assertEqual(len(self.commands),1)
    def test_export_failure(self):
        with self.assertRaises(ADAPTER.AdapterError):self.call(self.fake(fail_export=True))
        self.assertEqual(len(self.commands),1)
    def test_sign_failure_no_retry(self):
        with self.assertRaises(ADAPTER.AdapterError):self.call(self.fake(fail_sign=True))
        self.assertEqual(len(self.commands),2)
    def test_invalid_signature_length(self):
        with self.assertRaises(ADAPTER.AdapterError):self.call(self.fake(bad_length=True))
    def test_explicit_serial(self):
        for serial in ("","123;id=%01","abc"):
            with self.assertRaises(ADAPTER.AdapterError):self.call(self.fake(),serial=serial)
        self.assertEqual(self.commands,[])
    def test_config_injection(self):
        for path in ('relative','/bad\nactivate=0','/bad"','/$ENV::HOME','/bad\\path'):
            with self.assertRaises(ADAPTER.AdapterError):self.call(self.fake(),provider=path)
        self.assertEqual(self.commands,[])
    def test_paths_with_spaces(self):self.assertIn('"/some folder/provider"',ADAPTER.configuration('/some folder/provider','/module'))
    def test_timeout_no_retry(self):
        def timeout(command,**kwargs):
            self.commands.append(command);raise subprocess.TimeoutExpired(command,30)
        with self.assertRaises(subprocess.TimeoutExpired):self.call(timeout)
        self.assertEqual(len(self.commands),1)

class EcdsaAdapterTest(unittest.TestCase):
    def test_digest_signing_and_slot(self):
        public=b"e"*91;digest=b"d"*32;signature=b"s"*70;commands=[]
        def run(command,**kwargs):
            commands.append(command)
            out=Path(command[-1])
            if command[1]=="pkey":
                self.assertIn("pkcs11:serial=123456;id=%01;type=public",command)
                out.write_bytes(public)
            else:
                self.assertIn("pkcs11:serial=123456;id=%01;type=private",command)
                self.assertIn("digest:sha256",command);self.assertNotIn("mu:1",command);self.assertNotIn("-rawin",command)
                self.assertEqual(Path(command[command.index("-in")+1]).read_bytes(),digest)
                out.write_bytes(signature)
            return subprocess.CompletedProcess(command,0)
        result=ADAPTER.sign(public,digest,"/openssl","/provider","/module","123456",io.BytesIO(),run,
                            algorithm="ECDSA-P256-SHA256",ec_slot="9a")
        self.assertEqual(result,signature);self.assertEqual(len(commands),2)
    def test_slot_guard(self):
        for slot in ("", "9c", "9a;type=private", "ff"):
            with self.assertRaises(ADAPTER.AdapterError):ADAPTER.ec_object_id(slot)
        self.assertEqual(ADAPTER.ec_object_id("82"),"%05")
        self.assertEqual(ADAPTER.ec_object_id("95"),"%18")
    def test_protocol(self):
        import base64
        request=b"ECDSA-P256-SHA256\n"+base64.b64encode(b"e"*91)+b"\n"+base64.b64encode(b"d"*32)+b"\n"
        self.assertEqual(ADAPTER.read_request(io.BytesIO(request)),("ECDSA-P256-SHA256",b"e"*91,b"d"*32))
        with self.assertRaises(ADAPTER.AdapterError):ADAPTER.read_request(io.BytesIO(request.replace(base64.b64encode(b"d"*32),base64.b64encode(b"d"*64))))

class RsaPinAdapterTest(unittest.TestCase):
    def test_pss_parameters_and_anonymous_pin_pipe(self):
        public=b"r"*422;digest=b"d"*32;signature=b"s"*384;commands=[];pin=bytearray(b"654321")
        def run(command,**kwargs):
            commands.append(command)
            self.assertFalse(any("654321" in arg for arg in command))
            self.assertFalse(any("654321" in value for value in kwargs["env"].values()))
            out=Path(command[command.index("-out")+1])
            config=Path(kwargs["env"]["OPENSSL_CONF"]).read_text()
            self.assertNotIn("654321",config)
            if command[1]=="pkey":
                self.assertIn("pkcs11-module-login-behavior = never",config)
                self.assertIn("pkcs11:serial=123456;id=%01;type=public",command)
                out.write_bytes(public)
            else:
                self.assertIn("rsa_padding_mode:pss",command);self.assertIn("rsa_pss_saltlen:32",command)
                self.assertIn("rsa_mgf1_md:sha256",command);self.assertIn("digest:sha256",command)
                self.assertNotIn("-rawin",command)
                fd=int(command[command.index("-passin")+1].split(":")[1])
                self.assertEqual(kwargs["pass_fds"],(fd,));self.assertEqual(os.read(fd,20),b"654321\n")
                self.assertEqual(Path(command[command.index("-in")+1]).read_bytes(),digest)
                out.write_bytes(signature)
            return subprocess.CompletedProcess(command,0)
        result=ADAPTER.sign(public,digest,"/openssl","/provider","/module","123456",io.BytesIO(),run,
                           algorithm="RSA3072-PSS-SHA256",ec_slot="9a",pin=pin)
        self.assertEqual(result,signature);self.assertEqual(pin,bytearray(6));self.assertEqual(len(commands),2)
    def test_rsa_protocol(self):
        import base64
        data=b"RSA3072-PSS-SHA256\n"+base64.b64encode(b"r"*422)+b"\n"+base64.b64encode(b"d"*32)+b"\n"
        self.assertEqual(ADAPTER.read_request(io.BytesIO(data))[0],"RSA3072-PSS-SHA256")

class RsaEncodingRegressionTest(unittest.TestCase):
    def test_equivalent_spki_and_different_exponent(self):
        import base64, shutil, tempfile
        executable=os.environ.get("OPENSSL_BIN") or shutil.which("openssl")
        if not executable:self.skipTest("OpenSSL 3 needed for canonicalization regression")
        version=subprocess.run([executable,"version"],capture_output=True,text=True)
        if not version.stdout.startswith("OpenSSL 3."):self.skipTest("OpenSSL 3 needed for canonicalization regression")
        # Generated software fixture public key, not a hardware/user key.
        original=base64.b64decode("MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAyrv0xBd7HBxGXJjULFyA4WBKQx8YxPh2XFsDOP/GSYhPEYd0kTiu1HSzduUUvr4Qi9ElQfiN9oW+gTqd/CnDeDSmJch0x2TP9ii94BrGqM7xuzmq5PpOvL4OONjjwUVj1altriQNwN3t4lxOWPIkYjwcGIzQ+X8GRFQbw1EaHLM87O/ckpwFFfV49C6ki9axR3lienzFNA466cUAp0kszcZOT9Qewubp3zG5vBGIOj6iRvwQvnFh/ka/YLFSHfRAxx/F0C7CqrlSufUnQHQ5bKwkds5jLDzIDgul9d7L9HKtx0m8U0OjH8Dy/u9GArxlwvdhAG427Pl9E/LoJBI69Zn3i4ypHTmEsfMK5c8rKTA5dEVEV1nEEo9PV3aAwXeaYN5UTkVYggPgV5mpn+yjcgo6s/pAJ/OgB97Lv32B4UOkze+M4G+kl5vzU2eSAabICFXBjM5fcpP5C1D3HwqPj4R/IfKFm2iF/nCUP9R1ooXqWM5qNlLstnHxId7qH7c1AgMBAAE=")
        decoded=base64.b64decode("MIIBoDALBgkqhkiG9w0BAQEDggGPADCCAYoCggGBAMq79MQXexwcRlyY1CxcgOFgSkMfGMT4dlxbAzj/xkmITxGHdJE4rtR0s3blFL6+EIvRJUH4jfaFvoE6nfwpw3g0piXIdMdkz/YoveAaxqjO8bs5quT6Try+DjjY48FFY9Wpba4kDcDd7eJcTljyJGI8HBiM0Pl/BkRUG8NRGhyzPOzv3JKcBRX1ePQupIvWsUd5Ynp8xTQOOunFAKdJLM3GTk/UHsLm6d8xubwRiDo+okb8EL5xYf5Gv2CxUh30QMcfxdAuwqq5Urn1J0B0OWysJHbOYyw8yA4LpfXey/RyrcdJvFNDox/A8v7vRgK8ZcL3YQBuNuz5fRPy6CQSOvWZ94uMqR05hLHzCuXPKykwOXRFRFdZxBKPT1d2gMF3mmDeVE5FWIID4FeZqZ/so3IKOrP6QCfzoAfey799geFDpM3vjOBvpJeb81NnkgGmyAhVwYzOX3KT+QtQ9x8Kj4+EfyHyhZtohf5wlD/UdaKF6ljOajZS7LZx8SHe6h+3NQIDAQAB")
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory);actual=folder/"actual.der";actual.write_bytes(original)
            args=(actual,"RSA3072-PSS-SHA256",executable,folder,os.environ.copy(),subprocess.run)
            self.assertTrue(ADAPTER.public_keys_match(decoded,*args))
            different=bytearray(decoded);different[-1]=3
            self.assertFalse(ADAPTER.public_keys_match(bytes(different),*args))

if __name__=="__main__":unittest.main()

class DiscoveryEnvironmentTest(unittest.TestCase):
    def test_scoped_metadata_and_inherited_flags(self):
        with patch.dict(os.environ,{"YKCS11_DISCOVERY":"bad", "YKCS11_DISCOVERY_ID":"24"}):
            unscoped=ADAPTER.child_environment("/tmp/config")
            self.assertNotIn("YKCS11_DISCOVERY",unscoped)
            self.assertNotIn("YKCS11_DISCOVERY_ID",unscoped)
            for encoded,expected in [("%02","2"),("%09","9"),("%0B","11"),("%0c","12")]:
                env=ADAPTER.child_environment("/tmp/config",encoded)
                self.assertEqual(env["YKCS11_DISCOVERY"],"metadata")
                self.assertEqual(env["YKCS11_DISCOVERY_ID"],expected)
    def test_invalid_discovery_id_rejected(self):
        for value in ["", "%00", "%19", "%02;type=private", "02", "%ff"]:
            with self.assertRaises(ADAPTER.AdapterError):ADAPTER.child_environment("/tmp/config",value)

class SingleProcessAdapterTest(unittest.TestCase):
    def test_single_call_key_binding_and_secret_cleanup(self):
        import tempfile
        with tempfile.TemporaryDirectory() as temp:
            helper=Path(temp)/'pqmail-pkcs11-sign';helper.touch();calls=[];pin=bytearray(b'654321');paths=[]
            def run(command,**kw):
                calls.append(command);paths.extend([Path(command[3]),Path(command[4])])
                self.assertEqual(command[2],'pkcs11:serial=123456;id=%02;type=')
                self.assertEqual(Path(command[3]).read_bytes(),b'p'*2614)
                self.assertEqual(Path(command[4]).read_bytes(),MU)
                self.assertEqual(kw['input'],b'654321\n')
                self.assertNotIn('654321',' '.join(command));self.assertNotIn('654321',str(kw['env']))
                self.assertEqual(kw['env']['YKCS11_DISCOVERY_ID'],'2')
                Path(command[5]).write_bytes(b's'*4627)
                return subprocess.CompletedProcess(command,0)
            result=ADAPTER.sign(b'p'*2614,MU,str(Path(temp)/'openssl'),'/provider','/module','123456',io.BytesIO(),run,algorithm='ML-DSA-87',pin=pin)
            self.assertEqual(len(result),4627);self.assertEqual(len(calls),1);self.assertEqual(pin,bytearray(6));self.assertTrue(all(not p.exists() for p in paths))
    def test_failure_and_timeout_never_fall_back(self):
        import tempfile
        for timeout in [False,True]:
            with tempfile.TemporaryDirectory() as temp:
                (Path(temp)/'pqmail-pkcs11-sign').touch();pin=bytearray(b'654321');calls=[]
                def run(command,**kw):
                    calls.append(command)
                    if timeout:raise subprocess.TimeoutExpired(command,100)
                    return subprocess.CompletedProcess(command,1,stderr=b'PQ Mail single-session signer failed at public key check; no retry\n')
                with self.assertRaises((ADAPTER.AdapterError,subprocess.TimeoutExpired)):
                    ADAPTER.sign(b'p'*2614,MU,str(Path(temp)/'openssl'),'/provider','/module','123456',io.BytesIO(),run,algorithm='ML-DSA-87',pin=pin)
                self.assertEqual(len(calls),1);self.assertEqual(pin,bytearray(6))
