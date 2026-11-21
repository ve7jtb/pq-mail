package dev.hybridmail;

import static dev.hybridmail.OpenPgp.*;
import com.google.gson.JsonParser;
import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.PublicKey;
import java.util.*;
import org.bouncycastle.openpgp.*;

/** Explicit Level 3 v5 hardware operations, using only existing slot 88/9d/85
 * keys. Local certificate creation belongs to the GnuPG harness. This driver
 * cannot provision keys, alter policies, write card objects or send mail. */
public final class V5InstalledReceive {
    record Input(PublicIdentity own,PublicIdentity v5,PublicKey signer,Keys encryption,byte[] ciphertext,byte[] message){}

    static byte[] read(Path path,int limit)throws Exception{
        try(var stream=Files.newInputStream(path)){
            byte[] value=stream.readNBytes(limit+1);check(value.length<=limit,"Oversized local input");return value;
        }
    }

    /** A selected staged test app is allowed; a different source-tree jar
     * silently shadowing its classes is not. The harness records its hashes. */
    static Path app(Path requested)throws Exception{
        Path selected=requested.toRealPath();
        Path loaded=Path.of(OpenPgp.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
        check(loaded.equals(selected.resolve("hybrid-mail.jar").toRealPath()),"PQ Mail classes must come from the selected app jar");
        return selected;
    }

    /** Bind the local v5 certificate to the signed on-card v6 public identity
     * and the full SPKIs that the restorer matched to the live selected card.
     * This is additional routing evidence, not a substitute for fresh live
     * snapshots taken by the surrounding hardware harness. */
    static Input load(Path restored,Path out,String serial)throws Exception{
        check(serial.matches("[1-9][0-9]{0,9}"),"Explicit YubiKey serial required");
        var manifest=JsonParser.parseString(new String(read(restored.resolve("identity.json"),65536),StandardCharsets.UTF_8)).getAsJsonObject();
        check(manifest.get("serial").getAsString().equals(serial)&&manifest.get("bundleSignatureVerified").getAsBoolean()
            &&manifest.get("liveKeysMatched").getAsBoolean(),"Expected verified public restore of the selected card");
        var bundle=OnKeyBundle.decode(OnKeyStorage.unpack(read(restored.resolve("certificate-bundle.pqmzip"),65536)));
        check(Integer.toString(bundle.serial()).equals(serial),"Signed bundle belongs to another card");
        var exported=new PublicIdentity(read(restored.resolve("openpgp-v6.asc"),131072));
        var matches=new ArrayList<OnKeyBundle.Profile>();
        for(var profile:bundle.profiles())if(profile.pgp().length>0&&new PublicIdentity(profile.pgp()).fingerprint().equals(exported.fingerprint()))matches.add(profile);
        check(matches.size()==1,"Expected a unique signed OpenPGP profile");
        var profile=matches.get(0);var own=new PublicIdentity(profile.pgp());
        check(Arrays.equals(own.primary,exported.primary)&&Arrays.equals(own.signingBody(),exported.signingBody())
            &&Arrays.equals(own.subkey,exported.subkey),"Restored v6 public keys differ from signed bundle");
        OpenPgp.match(own,profile.entry().identity());
        check(rfc9980(own)&&profile.entry().kemSlot().equals("9d"),"Expected existing Level 3 RFC 9980 hardware layout");
        var slots=manifest.getAsJsonObject("slots");
        var decryption=slots.getAsJsonArray("decryption");var classical=slots.getAsJsonArray("classical");
        check(decryption.size()==2&&decryption.get(0).getAsString().equals("9d")&&decryption.get(1).getAsString().equals("85")
            &&classical.size()==2&&classical.get(0).getAsString().equals("88"),"Unexpected existing slot mappings");
        var v5=new PublicIdentity(read(out.resolve("openpgp-v5.pgp"),131072));
        check(v5.version()==5&&v5.matchesEmail(own.email),"Expected local v5 certificate for the restored identity");
        PublicKey signer=LibreOpenPgp.signingKey(v5);Keys encryption=LibreOpenPgp.encryptionKeys(v5);
        check(Arrays.equals(signer.getEncoded(),own.classicalKey(true).getEncoded())
            &&Arrays.equals(encryption.pq().getEncoded(),own.encryption.pq().getEncoded())
            &&Arrays.equals(encryption.ec().getEncoded(),own.encryption.ec().getEncoded()),"V5 certificate does not use the existing hardware keys");
        for(var entry:Map.of("88",signer,"9d",encryption.pq(),"85",encryption.ec()).entrySet()){
            byte[] spki=read(restored.resolve("slot-"+entry.getKey()+"-public.der"),4096);
            check(Arrays.equals(spki,entry.getValue().getEncoded()),"Restored component SPKI mismatch");
            check(hex(hash("SHA-256",spki)).equalsIgnoreCase(manifest.getAsJsonObject("publicKeySha256").get(entry.getKey()).getAsString()),"Restored component digest mismatch");
        }
        byte[] message=read(out.resolve("v5-message.txt"),16384);
        check(Arrays.equals(message,V5HardwareInterop.MESSAGE),"Unexpected synthetic message bytes");
        byte[] ciphertext=read(out.resolve("stock-v5-encrypted.pgp"),1048576);
        check(ciphertext.length>0,"Missing GnuPG encryption fixture");
        return new Input(own,v5,signer,encryption,ciphertext,message);
    }

    /** One operation-scoped PIN is supplied on stdin to each component. No
     * private call is retried, and unexpected routing or duplicate component
     * calls fail before another native invocation. The PIN is never an argv,
     * environment, log or file value. */
    static final class Backend implements ExternalKem.Backend {
        final Input input;final Path app;final Map<String,String> config;
        char[] pin;int signs,kem,ec,operations;
        Backend(Input input,Path app,String serial,char[] pin){
            this.input=input;this.app=app;this.pin=pin;
            config=Map.of("OPENSSL_BIN",app.resolve("native/bin/openssl").toString(),
                "PKCS11_PROVIDER",app.resolve("native/lib/pkcs11.dylib").toString(),
                "PKCS11_MODULE",app.resolve("native/lib/libykcs11.dylib").toString(),
                "PKCS11_SERIAL",serial,"PKCS11_KEM_SLOT","9d","PKCS11_ECDH_SLOT","85");
        }
        public Backend newOperation(){if(++operations!=1)throw new IllegalStateException("Repeated private operation");return this;}
        public void clearSecrets(){if(pin!=null){Arrays.fill(pin,'\0');pin=null;}}
        byte[] sign(byte[] digest)throws Exception{
            check(pin!=null&&++signs==1&&digest.length==64,"Expected one Ed25519/SHA-512 signature");
            var signing=new HashMap<>(config);signing.put("PQMAIL_COMPATIBILITY_SLOT","88");
            // The signing adapter prints Base64 plus a newline; request the
            // same decoding used by the production signing backend. KEM/ECDH
            // below returns raw shared-secret bytes and must keep rawOutput
            // enabled. Mixing those two protocols makes a valid 64-byte
            // Ed25519 signature look like an 89-byte ASCII response.
            byte[] result=ExternalMu.invoke(app.resolve("adapters/pkcs11-mu.py").toString(),"Ed25519",input.signer,digest,pin.clone(),false,signing);
            check(result.length==64,"Wrong Ed25519 signature length");return result;
        }
        byte[] call(String algorithm,PublicKey expected,PublicKey actual,byte[] value)throws Exception{
            check(pin!=null&&Arrays.equals(expected.getEncoded(),actual.getEncoded()),"Wrong private component requested");
            byte[] result=ExternalMu.invoke(app.resolve("adapters/pkcs11-kem.py").toString(),algorithm,actual,value,pin.clone(),true,config);
            if(result.length!=32){wipe(result);throw new java.security.SignatureException("Wrong shared-secret length");}return result;
        }
        public byte[] decapsulate(PublicKey key,byte[] ciphertext)throws Exception{
            check(++kem==1&&ciphertext.length==1088,"Expected one ML-KEM-768 operation");return call("ML-KEM-768",input.encryption.pq(),key,ciphertext);
        }
        public byte[] derive(PublicKey key,PublicKey peer)throws Exception{
            check(++ec==1,"Expected one X25519 operation");return call("X25519",input.encryption.ec(),key,peer.getEncoded());
        }
    }

    static char[] pin(String operation)throws Exception{
        Console console=System.console();check(console!=null,"Run in a local Terminal for the hidden PIN prompt");
        char[] value=console.readPassword("YubiKey PIN (PQ Mail v5 %s; touch only if flashing): ",operation);
        try{check(value!=null&&value.length>=6&&value.length<=8,"Invalid PIV PIN length");
            for(char c:value)check(c>=32&&c<=126,"Invalid PIV PIN character");return value;
        }catch(Exception error){if(value!=null)Arrays.fill(value,'\0');throw error;}
    }

    /** Extract only one unsigned synthetic literal, after the codec has
     * authenticated the encrypted payload. A detached signature is checked
     * separately; the report must not claim an inline-signed message. */
    static byte[] literal(byte[] data)throws Exception{
        var factory=LegacyOpenPgp.objects(data);Object first=factory.nextObject();int depth=0;
        while(first instanceof PGPCompressedData c){
            check(++depth<=3,"Unexpected compression nesting");
            // Consume the compression stream before asking its parent parser
            // for another packet; otherwise it interprets compressed octets
            // as a new OpenPGP header instead of checking for trailing data.
            byte[] expanded=LegacyOpenPgp.bounded(c.getDataStream());
            check(factory.nextObject()==null,"Unexpected compression structure");
            factory=LegacyOpenPgp.objects(expanded);first=factory.nextObject();
        }
        check(first instanceof PGPLiteralData,"Expected synthetic literal packet");
        byte[] value=LegacyOpenPgp.bounded(((PGPLiteralData)first).getInputStream());
        check(factory.nextObject()==null,"Unexpected additional payload packets");return value;
    }

    public static void main(String[] args)throws Exception{
        check(args.length==5,"Usage: --preflight|--sign|--decrypt RESTORED OUT APP-CONTENTS-APP SERIAL");
        check(List.of("--preflight","--sign","--decrypt").contains(args[0]),"Unknown operation");
        Path app=app(Path.of(args[3]));MailEngine.init();
        for(String name:List.of("PQMAIL_LEVEL3_POLYFILL","PQMAIL_LEVEL5_COMPATIBILITY","PQMAIL_COMPATIBILITY_SLOT","PQMAIL_CERTIFICATION_SLOTS"))
            check(System.getenv(name)==null||System.getenv(name).isBlank(),"Conflicting inherited key-layout override");
        for(String relative:List.of("adapters/pkcs11-mu.py","adapters/pkcs11-kem.py","native/bin/openssl",
            "native/bin/pqmail-pkcs11-sign","native/bin/pqmail-pkcs11-kem","native/lib/pkcs11.dylib","native/lib/libykcs11.dylib"))
            check(Files.isRegularFile(app.resolve(relative)),"Missing PKCS#11 dependency");
        Path out=Path.of(args[2]);Input input=load(Path.of(args[1]),out,args[4]);
        // Parse the complete recipient and payload framing without contacting
        // the card. Unsupported or structurally invalid packets fail before
        // the PIN prompt. Ciphertext authentication still needs private-key
        // operations; tampering must then fail without returning plaintext.
        LibreOpenPgp.validateEnvelope(input.ciphertext,input.v5);
        if(args[0].equals("--preflight")){
            System.out.println("PASS local signed-bundle, v5 certificate, slot bindings and packet preflight; no private operation");return;
        }
        boolean signing=args[0].equals("--sign");
        Path result=out.resolve(signing?"pqmail-v5-signing.txt":"pqmail-v5-receive.txt");
        Path signature=out.resolve("pqmail-v5-signature.pgp");
        check(!Files.exists(result)&&(!signing||!Files.exists(signature)),"Private operation already has a saved result; do not repeat");
        byte[] detached=signing?null:read(out.resolve("v5-signature.pgp"),16384);
        if(detached!=null)LibreOpenPgp.verifyDetached(detached,input.message,input.v5);
        var backend=new Backend(input,app,args[4],pin(signing?"Ed25519 signing":"ML-KEM-768/X25519 decryption"));
        try{
            if(signing){
                byte[] sig=LibreOpenPgp.signDetached(input.message,input.v5,backend::sign);
                LibreOpenPgp.verifyDetached(sig,input.message,input.v5);
                check(backend.signs==1&&backend.kem==0&&backend.ec==0,"Unexpected private signing calls");
                Files.write(signature,sig,StandardOpenOption.CREATE_NEW);
                Files.writeString(result,"PASS PQ Mail v5 Ed25519/SHA-512 signing; slot 88 calls=1; PIN prompts=1\n",StandardOpenOption.CREATE_NEW);
            }else{
                byte[] packets=null,plain=null;
                try{packets=LibreOpenPgp.decrypt(input.ciphertext,input.v5,backend);plain=literal(packets);
                    check(Arrays.equals(plain,input.message),"Decrypted bytes differ from synthetic message");
                    LibreOpenPgp.verifyDetached(detached,plain,input.v5);
                    check(backend.operations==1&&backend.kem==1&&backend.ec==1&&backend.signs==0,"Unexpected private decryption calls");
                    Files.writeString(result,"PASS PQ Mail v5 hybrid decryption and integrity; exact synthetic bytes\n"
                        +"PASS GnuPG detached Ed25519 signature verified separately; encrypted fixture has no inline signature\n"
                        +"ML-KEM-768 slot 9d calls=1; X25519 slot 85 calls=1; PIN prompts=1\n",StandardOpenOption.CREATE_NEW);
                }finally{wipe(packets);wipe(plain);}
            }
            System.out.print(Files.readString(result));
        }finally{backend.clearSecrets();}
    }
}
