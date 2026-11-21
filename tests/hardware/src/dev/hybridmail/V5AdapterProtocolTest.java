package dev.hybridmail;

import static dev.hybridmail.OpenPgp.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;

/** Exercise the actual Java subprocess boundary with fake executable adapters.
 * All key material is disposable software state. The fake adapters cannot
 * access a card, and no real PIN, account or private-key file is used. */
public final class V5AdapterProtocolTest {
    static void adapter(Path file,String algorithm,PublicKey key,byte[] request,byte[] response,boolean compatibility)throws Exception{
        // Only public request bytes and a public signature/test response are
        // embedded in this temporary executable. The synthetic PIN arrives
        // exclusively over stdin; the child neither logs nor persists it.
        String script="import base64, os, sys\n"
            +"assert sys.stdin.buffer.readline() == b'"+algorithm+"\\n'\n"
            +"assert base64.b64decode(sys.stdin.buffer.readline().rstrip(b'\\n'), validate=True) == base64.b64decode('"+Base64.getEncoder().encodeToString(key.getEncoded())+"')\n"
            +"assert base64.b64decode(sys.stdin.buffer.readline().rstrip(b'\\n'), validate=True) == base64.b64decode('"+Base64.getEncoder().encodeToString(request)+"')\n"
            +"pin = bytearray(sys.stdin.buffer.readline(10))\n"
            +"assert len(pin) == 7 and pin[-1] == 10\n"
            +"pin[:] = b'\\0' * len(pin)\n"
            +"assert os.environ['HYBRID_MAIL_PIN_STDIN'] == '1'\n"
            +(compatibility?"assert os.environ['PQMAIL_COMPATIBILITY_SLOT'] == '88'\n":"")
            +"sys.stdout.buffer.write(base64.b64decode('"+Base64.getEncoder().encodeToString(response)+"'))\n";
        // The real DesktopState.process helper invokes Python for .py files;
        // this test therefore covers the same executable and stdin/stdout
        // path as the hardware driver, including Base64 response decoding.
        Files.writeString(file,script);
    }
    static char[] syntheticPin(){return new char[]{'6','5','4','3','2','1'};}
    static void expectFailure(V5InstalledReceive.Backend backend,byte[] digest)throws Exception{
        try{boolean failed=false;try{backend.sign(digest);}catch(Exception expected){failed=true;}
            check(failed,"Malformed signing output was accepted");
        }finally{backend.clearSecrets();check(backend.pin==null,"Operation PIN was not cleared");}
    }
    public static void main(String[] args)throws Exception{
        MailEngine.init();
        var ed=KeyPairGenerator.getInstance("Ed25519","BC").generateKeyPair();
        var ml=KeyPairGenerator.getInstance("ML-KEM-768","BC").generateKeyPair();
        var x=KeyPairGenerator.getInstance("X25519","BC").generateKeyPair();
        byte[] digest=hash("SHA-512",bytes("Synthetic v5 adapter protocol regression"));
        Signature signer=Signature.getInstance("Ed25519","BC");signer.initSign(ed.getPrivate());signer.update(digest);byte[] expected=signer.sign();
        var input=new V5InstalledReceive.Input(null,null,ed.getPublic(),new Keys(ml.getPublic(),x.getPublic()),b(),b());
        Path app=Files.createTempDirectory("pq-v5-adapter-protocol-");Files.createDirectories(app.resolve("adapters"));
        Path signing=app.resolve("adapters/pkcs11-mu.py"),kem=app.resolve("adapters/pkcs11-kem.py");
        try{
            byte[] encoded=cat(Base64.getEncoder().encode(expected),b(10));
            check(encoded.length==89&&expected.length==64,"Unexpected Ed25519 test shape");
            adapter(signing,"Ed25519",ed.getPublic(),digest,encoded,true);
            var backend=new V5InstalledReceive.Backend(input,app,"123",syntheticPin());
            try{byte[] actual=backend.sign(digest);check(Arrays.equals(expected,actual),"Signing response was not decoded");
                signer.initVerify(ed.getPublic());signer.update(digest);check(signer.verify(actual),"Decoded signature does not verify");
            }finally{backend.clearSecrets();check(backend.pin==null,"Operation PIN was not cleared");}
            System.out.println("PASS Base64-plus-newline signing response decodes from 89 bytes to a valid 64-byte Ed25519 signature");
            adapter(signing,"Ed25519",ed.getPublic(),digest,bytes("not base64!\n"),true);
            expectFailure(new V5InstalledReceive.Backend(input,app,"123",syntheticPin()),digest);
            adapter(signing,"Ed25519",ed.getPublic(),digest,cat(Base64.getEncoder().encode(Arrays.copyOf(expected,63)),b(10)),true);
            expectFailure(new V5InstalledReceive.Backend(input,app,"123",syntheticPin()),digest);
            System.out.println("PASS malformed Base64 and truncated decoded signatures are rejected");
            // KEM output deliberately includes bytes that are not Base64.
            // Its raw protocol must remain unchanged by the signing repair.
            byte[] ciphertext=new byte[1088],secret=new byte[32];Arrays.fill(secret,(byte)0xff);
            adapter(kem,"ML-KEM-768",ml.getPublic(),ciphertext,secret,false);
            backend=new V5InstalledReceive.Backend(input,app,"123",syntheticPin());
            try{check(Arrays.equals(secret,backend.decapsulate(ml.getPublic(),ciphertext)),"Raw KEM output changed");}
            finally{backend.clearSecrets();}
            System.out.println("PASS KEM responses remain raw bytes; fake adapters only, no hardware used");
        }finally{
            try(var files=Files.walk(app)){for(Path path:files.sorted(Comparator.reverseOrder()).toList())Files.delete(path);}
        }
    }
}
