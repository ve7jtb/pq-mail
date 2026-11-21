package dev.hybridmail;

import static dev.hybridmail.OpenPgp.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.openpgp.*;
import java.io.ByteArrayOutputStream;

/** Software-only GnuPG fixture interoperability. The deliberately fixed
 * password opens disposable test keys, never a user's identity or a token. */
public final class LibreOpenPgpTest {
    static final class Software implements ExternalKem.Backend {
        final PrivateKey ml,x;final OpenPgp.Keys publicKeys;int mlCalls,xCalls;
        Software(KeyStore keys,PublicIdentity cert,char[] password)throws Exception{
            ml=(PrivateKey)keys.getKey("9d",password);x=(PrivateKey)keys.getKey("85",password);publicKeys=LibreOpenPgp.encryptionKeys(cert);
        }
        public byte[] decapsulate(PublicKey key,byte[] ciphertext)throws Exception{
            check(Arrays.equals(key.getEncoded(),publicKeys.pq().getEncoded()),"Wrong software ML-KEM key");mlCalls++;
            return new MLKEMExtractor((MLKEMPrivateKeyParameters)PrivateKeyFactory.createKey(ml.getEncoded())).extractSecret(ciphertext);
        }
        public byte[] derive(PublicKey key,PublicKey peer)throws Exception{
            check(Arrays.equals(key.getEncoded(),publicKeys.ec().getEncoded()),"Wrong software X25519 key");xCalls++;return OpenPgp.derive(x,peer);
        }
    }
    static byte[] literal(byte[] data)throws Exception{
        var objects=LegacyOpenPgp.objects(data);Object first=objects.nextObject();int depth=0;
        while(first instanceof PGPCompressedData compressed){check(++depth<=3,"Compression nesting");byte[] inflated=LegacyOpenPgp.bounded(compressed.getDataStream());check(objects.nextObject()==null,"Invalid compressed fixture");objects=LegacyOpenPgp.objects(inflated);first=objects.nextObject();}
        check(first instanceof PGPLiteralData,"Expected unsigned synthetic literal");byte[] result=LegacyOpenPgp.bounded(((PGPLiteralData)first).getInputStream());check(objects.nextObject()==null,"Trailing fixture packets");return result;
    }
    static void compressedV4()throws Exception{
        // Use a live, self-certified disposable v4 signing key. The compressed
        // body's stream must be consumed before looking for a following outer
        // packet; otherwise zlib bytes are mistaken for an OpenPGP header.
        var signing=LegacyOpenPgpPolicyTest.pair("Ed25519",22);
        var encryption=LegacyOpenPgpPolicyTest.pair("X25519",18);
        var cert=new PublicIdentity(LegacyOpenPgpPolicyTest.ring(signing,encryption,0).getEncoded());
        byte[] plain=bytes("Synthetic compressed v4 regression");
        var signer=new PGPSignatureGenerator(LegacyOpenPgpPolicyTest.builder(signing,8),signing.getPublicKey());signer.init(0,signing.getPrivateKey());
        byte[] one=signer.generateOnePassVersion(false).getEncoded();signer.update(plain);
        byte[] signed=cat(one,frame(11,cat(b(98,0),n(0,4),plain)),signer.generate().getEncoded());
        var output=new ByteArrayOutputStream();var compressor=new PGPCompressedDataGenerator(2);
        try(var stream=compressor.open(output)){stream.write(signed);}
        check(Arrays.equals(OpenPgp.openSigned(output.toByteArray(),cert,new boolean[]{true}),plain),"Compressed v4 signature failed");
        System.out.println("PASS compressed v4 signature consumes bounded compressed stream before outer packet checks");
    }
    public static void main(String[] args)throws Exception{
        MailEngine.init();compressedV4();check(args.length==3,"Usage: V5-PUBLIC-FIXTURE-DIR DISPOSABLE-P12-FIXTURE OUTPUT-DIR");
        Path fixture=Path.of(args[0]),out=Path.of(args[2]);Files.createDirectories(out);
        var own=new PublicIdentity(Files.readAllBytes(fixture.resolve("public-v5.pgp")));
        check(own.version()==5&&own.canEncrypt()&&own.quantumEncryption(),"V5 public profile not usable");
        byte[] expected=Files.readAllBytes(fixture.resolve("plain.txt"));
        own.legacy.verify(Files.readAllBytes(fixture.resolve("detached.pgp")),expected);
        System.out.println("PASS GnuPG v5 fixture certificate self-certifications and detached Ed25519 signature");
        char[] password="synthetic-fixture-password".toCharArray();var keys=KeyStore.getInstance("PKCS12","BC");
        try(var input=Files.newInputStream(Path.of(args[1]))){keys.load(input,password);}
        var backend=new Software(keys,own,password);PrivateKey ed=(PrivateKey)keys.getKey("84",password);Arrays.fill(password,'\0');
        byte[] incoming=Files.readAllBytes(fixture.resolve("stock-encrypted.pgp"));
        byte[] opened=LibreOpenPgp.decrypt(incoming,own,backend);
        check(Arrays.equals(literal(opened),expected),"Stock GnuPG plaintext differs");
        check(backend.mlCalls==1&&backend.xCalls==1,"Wrong software component calls");
        System.out.println("PASS stock GnuPG v5 algorithm-8 hybrid decryption and exact plaintext");
        byte[] packet=frame(11,cat(b(98,0),n(0,4),expected));
        byte[] outgoing=encrypt(packet,own);Files.write(out.resolve("pqmail-encrypted.pgp"),outgoing);
        check(Arrays.equals(literal(LibreOpenPgp.decrypt(outgoing,own,backend)),expected),"PQ Mail local round trip differs");
        byte[] signature=LibreOpenPgp.signDetached(expected,own,digest->{Signature signer=Signature.getInstance("Ed25519","BC");signer.initSign(ed);signer.update(digest);return signer.sign();});
        Files.write(out.resolve("pqmail-signature.pgp"),signature);Files.write(out.resolve("message.txt"),expected);
        // Integrity failure and wrong recipients must never yield a successful
        // plaintext. A structurally wrong recipient is rejected before any
        // backend invocation; the test checks call counters for that boundary.
        byte[] badIncoming=incoming.clone();badIncoming[badIncoming.length-1]^=1;OnKeyBundleTest.fails(()->LibreOpenPgp.decrypt(badIncoming,own,backend));
        byte[] bad=outgoing.clone();bad[bad.length-1]^=1;
        OnKeyBundleTest.fails(()->LibreOpenPgp.decrypt(bad,own,backend));
        var packets=LibreOpenPgp.packetsV5(outgoing);byte[] wrong=packets.get(0).body().clone();wrong[1]^=1;
        byte[] wrongMessage=cat(frame(1,wrong),frame(packets.get(1).tag(),packets.get(1).body()));int calls=backend.mlCalls+backend.xCalls;
        OnKeyBundleTest.fails(()->LibreOpenPgp.decrypt(wrongMessage,own,backend));check(calls==backend.mlCalls+backend.xCalls,"Wrong recipient reached backend");
        // Every public envelope discriminator is rejected before component
        // access. Fixed offsets are intentional: the profile's fields have
        // strict 32/1088/40-octet lengths and this fixture has exactly one PKESK.
        for(int offset:new int[]{9,10,44,1136,1137}){
            byte[] body=packets.get(0).body().clone();body[offset]^=1;
            byte[] malformed=cat(frame(1,body),frame(packets.get(1).tag(),packets.get(1).body()));
            int count=backend.mlCalls+backend.xCalls;OnKeyBundleTest.fails(()->LibreOpenPgp.decrypt(malformed,own,backend));
            check(count==backend.mlCalls+backend.xCalls,"Malformed public envelope reached backend");
        }
        // Preserve packet framing while removing the final OCB tag. Failure
        // must be detected by the authenticated stream after key recovery.
        var aead=LibreOpenPgp.packetsV5(incoming);check(aead.get(1).tag()==20,"Expected stock AEAD regression fixture");
        byte[] noTag=cat(frame(1,aead.get(0).body()),frame(20,slice(aead.get(1).body(),0,aead.get(1).body().length-16)));
        int beforeTag=backend.mlCalls+backend.xCalls;OnKeyBundleTest.fails(()->LibreOpenPgp.decrypt(noTag,own,backend));
        check(backend.mlCalls+backend.xCalls==beforeTag+2,"Truncated final-tag regression did not reach authenticated payload verification");
        // Check declared v5 key-material bounds before the BC parser retains
        // unknown algorithm-8 material. This fixture must fail without asking
        // a backend to sign, decrypt, or reinterpret a different key profile.
        var certificatePackets=LibreOpenPgp.packetsV5(own.encoded);var malformedCert=new Buffer();
        for(var item:certificatePackets){byte[] body=item.body().clone();if(item.tag()==6){body[6]=0x7f;body[7]=(byte)255;body[8]=(byte)255;body[9]=(byte)255;}malformedCert.put(frame(item.tag(),body));}
        OnKeyBundleTest.fails(()->new PublicIdentity(malformedCert.toByteArray()));
        OnKeyBundleTest.fails(()->new PublicIdentity(cat(own.encoded,frame(5,b(5,0)))));
        byte[] wrongSignature=signature.clone();wrongSignature[wrongSignature.length-1]^=1;OnKeyBundleTest.fails(()->LibreOpenPgp.verifyDetached(wrongSignature,expected,own));
        System.out.println("PASS PQ Mail v5 signing/encryption, integrity rejection and pre-private-operation recipient checks; no hardware used");
    }
}
