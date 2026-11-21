package dev.hybridmail;

import static dev.hybridmail.OpenPgp.*;
import com.google.gson.JsonParser;
import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.PublicKey;
import java.util.*;
import org.bouncycastle.openpgp.*;

/** Opt-in, local hardware test extension. It loads PQ Mail's installed
 * classes and existing PKCS#11 executable; it has no provisioning, policy-write,
 * app-update, account or mail capability. A separate harness owns the live-card
 * before/after snapshots. Local restored files alone do not prove live state. */
public final class V4InstalledReceive {
    record Input(Identity identity,PublicIdentity own,PublicIdentity compatibility,
                 byte[] ciphertext,byte[] expected,byte[] signature){}

    static byte[] read(Path path,int limit)throws Exception{
        try(var stream=Files.newInputStream(path)){
            byte[] result=stream.readNBytes(limit+1);
            check(result.length<=limit,"Oversized local test input");return result;
        }
    }

    /** Bind every test mode, including the software self-test, to the exact
     * installed application supplied by the caller. Driver classes may precede
     * it on the classpath; duplicate application classes may not. */
    static Path installedApp(Path requested)throws Exception{
        Path app=requested.toRealPath();
        Path loaded=Path.of(OpenPgp.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toRealPath();
        check(loaded.equals(app.resolve("hybrid-mail.jar").toRealPath()),
            "PQ Mail classes must come from the selected installed app jar");
        return app;
    }

    /** Check all public inputs before any PIN is requested. In particular, the
     * stored bundle signature, recipient fingerprint, and public SPKIs must
     * agree; an algorithm match by itself never selects a hardware credential. */
    static Input load(Path restored,Path out,String serial,boolean signatureRequired)throws Exception{
        check(serial.matches("[1-9][0-9]{0,9}"),"Explicit YubiKey serial required");
        var manifest=JsonParser.parseString(new String(read(restored.resolve("identity.json"),65536),StandardCharsets.UTF_8)).getAsJsonObject();
        check(manifest.get("serial").getAsString().equals(serial)
            &&manifest.get("bundleSignatureVerified").getAsBoolean()
            &&manifest.get("liveKeysMatched").getAsBoolean(),"Expected successful restore for the selected serial");
        var bundle=OnKeyBundle.decode(OnKeyStorage.unpack(read(restored.resolve("certificate-bundle.pqmzip"),65536)));
        check(Integer.toString(bundle.serial()).equals(serial),"Signed bundle names another key");
        var exportedOwn=new PublicIdentity(read(restored.resolve("openpgp-v6.asc"),131072));
        var exportedCompat=new PublicIdentity(read(restored.resolve("openpgp-v4-hybrid.asc"),131072));
        var profiles=new ArrayList<OnKeyBundle.Profile>();
        // Sequoia can canonicalize packet headers/order on export without
        // changing public-key packet bodies or their complete fingerprints.
        // Select by that identity, then use the signed bundle's original bytes.
        for(var candidate:bundle.profiles())if(candidate.pgp().length>0
            &&new PublicIdentity(candidate.pgp()).fingerprint().equals(exportedOwn.fingerprint()))profiles.add(candidate);
        check(profiles.size()==1,"Expected exactly one matching restored OpenPGP profile");
        var profile=profiles.get(0);var id=profile.entry().identity();
        var own=new PublicIdentity(profile.pgp());var compat=new PublicIdentity(profile.compatibility());
        check(Arrays.equals(own.primary,exportedOwn.primary)&&Arrays.equals(own.signingBody(),exportedOwn.signingBody())
            &&Arrays.equals(own.subkey,exportedOwn.subkey),"Exported v6 public keys differ from the signed bundle");
        check(Arrays.equals(compat.primary,exportedCompat.primary)&&Arrays.equals(compat.subkey,exportedCompat.subkey),
            "Exported v4 public keys differ from the signed bundle");
        check(profile.entry().kemSlot().equals("9d")&&rfc9980(own)&&own.subkey[5]==35,
            "Expected Level 3 ML-KEM-768/X25519 layout");
        OpenPgp.match(own,id);OpenPgp.checkCompatibility(own,compat);
        check(compat.version()==4&&compat.legacy!=null&&compat.legacy.recipient.getAlgorithm()==35,
            "Expected v4 hybrid recipient");
        var slots=manifest.getAsJsonObject("slots").getAsJsonArray("decryption");
        check(slots.size()==2&&slots.get(0).getAsString().equals("9d")&&slots.get(1).getAsString().equals("85"),
            "Unexpected restored hybrid decryption mapping");
        for(var item:Map.of("9d",own.encryption.pq(),"85",own.encryption.ec()).entrySet()){
            byte[] spki=read(restored.resolve("slot-"+item.getKey()+"-public.der"),4096);
            check(Arrays.equals(spki,item.getValue().getEncoded()),"Restored public component mismatch");
            check(hex(hash("SHA-256",spki)).equalsIgnoreCase(manifest.getAsJsonObject("publicKeySha256").get(item.getKey()).getAsString()),
                "Restored public component hash mismatch");
        }
        byte[] ciphertext=read(out.resolve("fixed-gpg-v4-encrypted.pgp"),1048576);
        validatePacket(ciphertext,compat);
        byte[] expected=read(out.resolve("message.txt"),16384);
        Path signature=out.resolve("v4-signature.pgp");
        byte[] detached=Files.exists(signature)?read(signature,16384):null;
        check(!signatureRequired||detached!=null,"Run the existing v4 signing test first");
        if(detached!=null)compat.legacy.verify(detached,expected);
        return new Input(id,own,compat,ciphertext,expected,detached);
    }

    static void validatePacket(byte[] encoded,PublicIdentity compatibility)throws Exception{
        var packets=packets(encoded);
        check(packets.stream().map(Packet::tag).toList().equals(List.of(1,18)),"Expected one PKESK and protected payload");
        byte[] body=packets.get(0).body();
        check(body.length>=24&&body[0]==6&&body[1]==21&&body[2]==4,
            "This regression requires a v6 PKESK addressed to a v4 key");
        var recipient=v4Recipient(body);recipient.requireKey(compatibility.subkey,35);
        hybridSession(recipient); // Includes complete ciphertext/wrapped-key bounds before backend use.
        check(packets.get(1).body().length>0&&packets.get(1).body()[0]==1,
            "Expected the fixed GnuPG sender's SEIPD v1 fixture");
    }

    /** Parse only the synthetic unsigned literal produced by the public-only
     * GnuPG sender. Envelope integrity is verified by installed PQ Mail first.
     * The detached signature is checked separately; this is not an inline-
     * signed encrypted message and the result must not claim that it is. */
    static byte[] literal(byte[] encoded)throws Exception{
        var factory=LegacyOpenPgp.objects(encoded);Object first=factory.nextObject();int depth=0;
        while(first instanceof PGPCompressedData compressed){
            check(++depth<=3&&factory.nextObject()==null,"Unexpected compressed test structure");
            factory=LegacyOpenPgp.objects(LegacyOpenPgp.bounded(compressed.getDataStream()));first=factory.nextObject();
        }
        check(first instanceof PGPLiteralData,"Expected the synthetic GnuPG literal packet");
        byte[] bytes=LegacyOpenPgp.bounded(((PGPLiteralData)first).getInputStream());
        check(factory.nextObject()==null,"Unexpected trailing test packets");return bytes;
    }

    static void receive(Input input,ExternalKem.Backend backend)throws Exception{
        byte[] packets=null,plaintext=null;
        try{
            // This is the installed application's v4 compatibility receive
            // implementation, including the reviewed v6-to-v4 packet fix.
            packets=OpenPgp.openCompatibilityEncrypted(input.ciphertext,input.own,input.identity,backend);
            plaintext=literal(packets);
            check(Arrays.equals(plaintext,input.expected),"Recovered synthetic bytes differ");
            check(input.signature!=null,"Missing independent detached signature");
            input.compatibility.legacy.verify(input.signature,plaintext);
        }finally{wipe(packets);wipe(plaintext);backend.clearSecrets();}
    }

    /** One supplied PIN authorizes only this logical decryption. Each native
     * helper receives a disposable copy via stdin; no PIN is placed in argv,
     * an environment value, a file, or a diagnostic. No failed call is retried. */
    static final class InstalledBackend implements ExternalKem.Backend {
        final Input input;final String adapter;final Map<String,String> config;
        char[] pin;int mlCalls,xCalls,operations;
        InstalledBackend(Input input,Path app,String serial,char[] pin){
            this.input=input;this.pin=pin;adapter=app.resolve("adapters/pkcs11-kem.py").toString();
            config=Map.of("OPENSSL_BIN",app.resolve("native/bin/openssl").toString(),
                "PKCS11_PROVIDER",app.resolve("native/lib/pkcs11.dylib").toString(),
                "PKCS11_MODULE",app.resolve("native/lib/libykcs11.dylib").toString(),
                "PKCS11_SERIAL",serial,"PKCS11_KEM_SLOT","9d","PKCS11_ECDH_SLOT","85");
        }
        public InstalledBackend newOperation(){operations++;return this;}
        public void clearSecrets(){if(pin!=null){Arrays.fill(pin,'\0');pin=null;}}
        byte[] call(String algorithm,PublicKey expected,PublicKey actual,byte[] data)throws Exception{
            check(pin!=null&&Arrays.equals(expected.getEncoded(),actual.getEncoded()),"Private request does not match restored recipient");
            byte[] result=ExternalMu.invoke(adapter,algorithm,actual,data,pin.clone(),true,config);
            check(result.length==32,"Unexpected shared-secret length");return result;
        }
        public byte[] decapsulate(PublicKey key,byte[] ciphertext)throws Exception{
            check(++mlCalls==1&&ciphertext.length==1088,"Only one ML-KEM decapsulation is authorized");
            return call("ML-KEM-768",input.own.encryption.pq(),key,ciphertext);
        }
        public byte[] derive(PublicKey key,PublicKey peer)throws Exception{
            check(++xCalls==1,"Only one X25519 derivation is authorized");
            return call("X25519",input.own.encryption.ec(),key,peer.getEncoded());
        }
    }

    static char[] pin(boolean stdin)throws Exception{
        char[] result;
        if(stdin){
            // The parent harness prompts using getpass and passes one bounded
            // ASCII line over an anonymous pipe. Reject overlong input instead
            // of accepting a prefix; never echo any byte from this stream.
            char[] temporary=new char[9];int length=0;
            try{for(;;){int next=System.in.read();if(next=='\n')break;
                check(next>=32&&next<=126&&length<8,"Invalid PIN line");temporary[length++]=(char)next;}
                result=Arrays.copyOf(temporary,length);
            }finally{Arrays.fill(temporary,'\0');}
        }else{
            Console console=System.console();check(console!=null,"Run in Terminal or use the harness PIN pipe");
            result=console.readPassword("YubiKey PIN (installed PQ Mail v4 hybrid decryption; touch if flashing): ");
        }
        try{check(result!=null&&result.length>=6&&result.length<=8,"Invalid PIN length");
            for(char c:result)check(c>=32&&c<=126,"Invalid PIN character");return result;
        }catch(Exception failure){if(result!=null)Arrays.fill(result,'\0');throw failure;}
    }

    static void selfTest(Path app)throws Exception{
        // Exercise this test harness with disposable software components. It
        // validates extraction, byte comparison and detached verification as
        // well as the actual installed Java decryption implementation.
        var id=Identity.generateSoftwareProfile("interop@example.test",TokenProfile.LEVEL3,List.of()).get(1);
        var backend=new Rfc9980Test.Hardware(id);
        var own=createRfc9980(id,backend,backend.ed.getPublic(),backend.x.getPublic());
        var compat=compatibilityCertificate(own,d->backend.signEd25519(backend.ed.getPublic(),d));
        byte[] expected,signature,encoded;Path temporary=Files.createTempDirectory("pqmail-v4-interop-selftest-");
        try{
            // Exercise the same public prepare/verify CLI that the hardware
            // runner uses, with temporary public certificates and synthetic
            // data. Secret key material remains only in software memory.
            Path publicFile=temporary.resolve("public.asc");Files.write(publicFile,compat.export());
            V4HardwareInterop.main(new String[]{"prepare",publicFile.toString(),temporary.toString(),app.toString()});
            expected=read(temporary.resolve("message.txt"),16384);
            signature=frame(2,v4Signature(expected,0,compat.primary,b(),d->backend.signEd25519(backend.ed.getPublic(),d)));
            Files.write(temporary.resolve("v4-signature.pgp"),signature);
            V4HardwareInterop.main(new String[]{"verify",publicFile.toString(),temporary.toString(),app.toString()});
            // The CLI's refusal to overwrite results prevents accidental
            // replacement of evidence when a failed hardware run is resumed.
            OnKeyBundleTest.fails(()->V4HardwareInterop.main(new String[]{"prepare",publicFile.toString(),temporary.toString(),app.toString()}));
            encoded=read(temporary.resolve("pqmail-v4-encrypted.pgp"),1048576);
        }finally{
            try(var files=Files.walk(temporary)){for(Path file:files.sorted(Comparator.reverseOrder()).toList())Files.delete(file);}
        }
        var packets=packets(encoded);var r=new Reader(packets.get(0).body());
        check(r.one()==3,"Expected v3 software fixture");r.take(8);check(r.one()==35,"Expected hybrid software fixture");
        byte[] ct=r.take(1120);check(r.one()==41&&r.one()==9&&r.left()==40,"Expected AES-256 fixture");
        byte[] changed=cat(frame(1,cat(b(6,21,4),fingerprint(compat.subkey),b(35),ct,b(40),r.take(40))),frame(18,packets.get(1).body()));
        validatePacket(changed,compat);receive(new Input(id,own,compat,changed,expected,signature),backend);
        check(backend.pq.kem==1&&backend.xCalls==1,"Wrong software component routing");
        byte[] damaged=changed.clone();damaged[damaged.length-1]^=1;
        OnKeyBundleTest.fails(()->receive(new Input(id,own,compat,damaged,expected,signature),backend));
        System.out.println("PASS disposable software harness: installed v6-to-v4 decryption, byte comparison, detached signature, tamper rejection; no hardware used");
    }

    public static void main(String[] args)throws Exception{
        MailEngine.init();
        if(args.length==2&&args[0].equals("--self-test")){selfTest(installedApp(Path.of(args[1])));return;}
        check(args.length==5||args.length==6,"Usage: --preflight|--decrypt RESTORED OUT APP-CONTENTS-APP SERIAL [--pin-stdin]");
        boolean decrypt=args[0].equals("--decrypt");check(decrypt||args[0].equals("--preflight"),"Expected --preflight or --decrypt");
        check(args.length==5||args[5].equals("--pin-stdin"),"Unknown option");
        Path app=installedApp(Path.of(args[3]));Path loaded=app.resolve("hybrid-mail.jar");
        for(String name:List.of("PQMAIL_LEVEL3_POLYFILL","PQMAIL_LEVEL5_COMPATIBILITY","PQMAIL_COMPATIBILITY_SLOT","PQMAIL_CERTIFICATION_SLOTS"))
            check(System.getenv(name)==null||System.getenv(name).isBlank(),"Conflicting inherited key-layout override");
        for(String relative:List.of("adapters/pkcs11-kem.py","native/bin/openssl","native/bin/pqmail-pkcs11-kem","native/lib/pkcs11.dylib","native/lib/libykcs11.dylib"))
            check(Files.isRegularFile(app.resolve(relative)),"Missing installed PKCS#11 dependency");
        Input input=load(Path.of(args[1]),Path.of(args[2]),args[4],decrypt);
        System.out.println("PASS installed jar and signed restored public inputs; v6 PKESK names the full v4 hybrid fingerprint");
        if(!decrypt){System.out.println("PASS local-file preflight only; no PIN or hardware operation");return;}
        Path result=Path.of(args[2]).resolve("pqmail-fixed-gpg-receive.txt");
        check(!Files.exists(result),"This receive test already has a saved result; do not repeat");
        var backend=new InstalledBackend(input,app,args[4],pin(args.length==6));
        long start=System.nanoTime();
        try{receive(input,backend);
            check(backend.operations==1&&backend.mlCalls==1&&backend.xCalls==1,"Unexpected private operation count");
            System.out.println("PASS installed PQ Mail ML-KEM-768/X25519 decryption and integrity; exact synthetic bytes; slots 9d/85");
            System.out.println("PASS existing detached v4 Ed25519 signature checked separately; encrypted fixture has no inline signature");
            System.out.println("PRIVATE_OPERATIONS ML-KEM-768=1 X25519=1 PIN_PROMPTS=1 elapsed_ms="+((System.nanoTime()-start)/1000000));
            // Save only the non-secret outcome and hashes of public/synthetic
            // inputs. The parent harness separately records live key/policy
            // snapshots; this helper makes no unchanged-hardware claim itself.
            Files.writeString(result,"PASS installed PQ Mail v6-PKESK/v4-recipient hybrid decryption and integrity; exact synthetic bytes\n"
                +"PASS detached v4 Ed25519 signature verified separately; ciphertext has no inline signature\n"
                +"ML-KEM-768 slot 9d calls=1; X25519 slot 85 calls=1; PIN prompts=1\n"
                +"jar_sha256="+hex(hash("SHA-256",read(loaded,16777216)))+"\n"
                +"ciphertext_sha256="+hex(hash("SHA-256",input.ciphertext))+"\n",StandardOpenOption.CREATE_NEW);
        }finally{backend.clearSecrets();}
    }
}
