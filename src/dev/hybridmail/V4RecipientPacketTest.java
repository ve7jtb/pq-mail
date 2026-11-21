package dev.hybridmail;

import static dev.hybridmail.OpenPgp.*;
import java.nio.file.*;
import java.security.PublicKey;
import java.util.*;

/** Offline receive regressions: packet version and certificate version differ.
 * All private operations use temporary software keys behind the same backend
 * interface as a token. This test never enumerates or contacts a physical card. */
public final class V4RecipientPacketTest {
    private static final String TEXT="Synthetic signed v4-recipient regression";

    /** Count the operation boundary as well as private calls: invalid public
     * framing must fail before even requesting a backend/PIN-cache operation. */
    private static final class CountingBackend implements ExternalKem.Backend {
        final ExternalKem.Backend delegate;
        int operations,privateCalls;
        CountingBackend(ExternalKem.Backend delegate){this.delegate=delegate;}
        public CountingBackend newOperation(){operations++;return this;}
        public void clearSecrets(){delegate.clearSecrets();}
        public byte[] decapsulate(PublicKey key,byte[] ct)throws Exception{
            privateCalls++;return delegate.decapsulate(key,ct);
        }
        public byte[] derive(PublicKey key,PublicKey peer)throws Exception{
            privateCalls++;return delegate.derive(key,peer);
        }
        public byte[] decapsulateLevel5Compatibility(PublicKey key,byte[] ct)throws Exception{
            privateCalls++;return delegate.decapsulateLevel5Compatibility(key,ct);
        }
        public byte[] deriveLevel5Compatibility(PublicKey key,PublicKey peer)throws Exception{
            privateCalls++;return delegate.deriveLevel5Compatibility(key,peer);
        }
        public byte[] deriveCompatibility(PublicKey key,PublicKey peer)throws Exception{
            privateCalls++;return delegate.deriveCompatibility(key,peer);
        }
    }

    /** Retain the already signed MIME and encrypted content when replacing only
     * PKESK framing. This produces real, independently authenticated end-to-end
     * messages; it does not mock the session-key unwrap or signature verifier. */
    private record Fixture(Identity identity,PublicIdentity own,PublicIdentity sender,
                           CountingBackend backend,byte[] v3,byte[] protectedData) {
        byte[] message(byte[] recipient,byte[] encrypted)throws Exception{
            return mimeWrap(bytes("Content-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n"),
                cat(bytes("Content-Type: application/octet-stream\r\n\r\n"),
                    armor(cat(frame(1,recipient),frame(18,encrypted)),"MESSAGE")),
                true,own.email,own.email,"Recipient packet test");
        }
        void accepts(byte[] recipient)throws Exception{
            var opened=OpenPgp.open(message(recipient,protectedData),sender,own,identity,backend);
            check(opened.encrypted()&&opened.fromMatches()&&!opened.postQuantum()
                &&opened.text().contains(TEXT),"Signed compatibility message did not verify/decrypt");
        }
        void rejectsBeforeBackend(byte[] recipient)throws Exception{
            int operations=backend.operations,calls=backend.privateCalls;
            OnKeyBundleTest.fails(()->OpenPgp.open(message(recipient,protectedData),sender,own,identity,backend));
            check(operations==backend.operations&&calls==backend.privateCalls,
                "Invalid recipient reached the private-key backend");
        }
    }

    private static Fixture fixture(Identity id,PublicIdentity own,PublicIdentity signer,
                                   ExternalMu.Backend signing,ExternalKem.Backend decryption)throws Exception{
        byte[] message=composeForRecipient(id,own,signer,true,own.email,own.email,
            "Recipient packet test",TEXT,signing);
        var p=parts(message);var packets=packets(unarmor(decoded(mime(p.second())),"MESSAGE"));
        check(packets.size()==2&&packets.get(0).tag()==1&&packets.get(1).tag()==18,
            "Fixture must contain one recipient and one protected payload");
        // The fixed GnuPG sender uses a v6 PKESK with its existing SEIPD v1
        // payload. Exercise precisely that combination, including implicit
        // AES-256 in the new PKESK, rather than assuming v6 implies SEIPD v2.
        check(packets.get(1).body()[0]==1,"Expected SEIPD v1 compatibility fixture");
        return new Fixture(id,own,signer,new CountingBackend(decryption),
            packets.get(0).body(),packets.get(1).body());
    }

    private static byte[] addressedV6(Fixture f)throws Exception{
        Reader r=new Reader(f.v3);
        check(r.one()==3,"Expected v3 PKESK fixture");r.take(8);
        check(r.one()==35,"Expected ML-KEM-768/X25519 fixture");
        byte[] ct=r.take(1120);
        check(r.one()==41&&r.one()==9&&r.left()==40,"Expected v3 AES-256 wrapping");
        // v6 carries a full v4 fingerprint. Its length includes key version 4,
        // and its wrapped-key length excludes the omitted symmetric-cipher byte.
        return cat(b(6,21,4),fingerprint(f.sender.subkey),b(35),ct,b(40),r.take(40));
    }

    private static void exercises(Fixture f)throws Exception{
        f.accepts(f.v3);byte[] v6=addressedV6(f);f.accepts(v6);

        // Change only the high fingerprint bytes, preserving the old v3 key ID.
        // Acceptance here would show an unsafe full-fingerprint-to-key-ID match.
        byte[] wrong=v6.clone();wrong[3]^=1;f.rejectsBeforeBackend(wrong);
        byte[] wrongV3=f.v3.clone();wrongV3[1]^=1;f.rejectsBeforeBackend(wrongV3);

        // Reject truncated headers, ciphertexts, and key wraps, as well as a
        // spurious trailing byte, before creating any private operation.
        for(int length:new int[]{0,1,2,3,22,23,24,100,v6.length-1})
            f.rejectsBeforeBackend(Arrays.copyOf(v6,length));
        f.rejectsBeforeBackend(cat(v6,b(0)));
        byte[] wrongLength=v6.clone();wrongLength[1]=33;f.rejectsBeforeBackend(wrongLength);
        byte[] wrongAlgorithm=v6.clone();wrongAlgorithm[23]=36;f.rejectsBeforeBackend(wrongAlgorithm);
        byte[] wrongWrap=v6.clone();wrongWrap[1144]=41;f.rejectsBeforeBackend(wrongWrap);

        // Historical GnuPG output advertised a 20-byte fingerprint but emitted
        // twelve extra bytes. Reject this malformed encoding; interoperability
        // must not be obtained by silently skipping padding in hostile packets.
        f.rejectsBeforeBackend(cat(slice(v6,0,23),new byte[12],slice(v6,23,v6.length)));

        // A ciphertext byte at offset 35 must never select the ordinary X25519
        // route: for this packet format the algorithm is actually at offset 23.
        byte[] decoy=v6.clone();decoy[35]=25;
        check(!classicalEnvelope(cat(frame(1,decoy),frame(18,f.protectedData))),
            "Ciphertext byte was treated as recipient algorithm");

        // Payload tampering is necessarily checked after private recovery. It
        // must still fail integrity verification and never return display text.
        byte[] damaged=f.protectedData.clone();damaged[damaged.length-1]^=1;
        int calls=f.backend.privateCalls;
        OnKeyBundleTest.fails(()->OpenPgp.open(f.message(v6,damaged),f.sender,f.own,f.identity,f.backend));
        check(f.backend.privateCalls==calls+2,"Payload integrity test did not exercise both KEM components");
    }

    public static void main(String[] args)throws Exception{
        MailEngine.init();var level3=Identity.generateSoftwareProfile("v4-l3@example.org",TokenProfile.LEVEL3,List.of()).get(1);
        var hardware3=new Rfc9980Test.Hardware(level3);
        var own3=createRfc9980(level3,hardware3,hardware3.ed.getPublic(),hardware3.x.getPublic());
        var compat3=compatibilityCertificate(own3,d->hardware3.signEd25519(hardware3.ed.getPublic(),d));
        exercises(fixture(level3,own3,compat3,hardware3,hardware3));

        // Keep native v6-to-v6 packets and SEIPD v2 covered alongside the added
        // v6-to-v4 compatibility case. Its hybrid signature must remain valid.
        byte[] nativeV6=compose(level3,own3,own3,own3.email,own3.email,"Native v6",TEXT,hardware3);
        var nativeOpened=OpenPgp.open(nativeV6,own3,own3,level3,hardware3);
        check(nativeOpened.encrypted()&&nativeOpened.postQuantum()&&nativeOpened.text().equals(TEXT),
            "Existing v6 hybrid receive path regressed");

        var level5=Identity.generateSoftwareProfile("v4-l5@example.org",TokenProfile.LEVEL5,List.of()).get(1);
        var hardware5=new Level5CompatibilityTest.Backend(level5);var keys=new HashMap<String,PublicKey>();
        hardware5.extra.forEach((slot,pair)->keys.put(slot,pair.getPublic()));
        Path root=Files.createTempDirectory("pqmail-v4-recipient-test-");
        try{
            var compat5=Level5Compatibility.issue(root,level5,keys,hardware5);var own5=loadOwn(root,level5);
            exercises(fixture(level5,own5,compat5,hardware5,hardware5));
            check(hardware5.ml==3&&hardware5.x==3&&hardware5.ec==0,
                "Level 5 compatibility decryption used the wrong component routes");
        }finally{
            // Only public certificates are written to this temporary fixture
            // directory; remove them even if a regression assertion fails.
            try(var files=Files.walk(root)){for(Path file:files.sorted(Comparator.reverseOrder()).toList())Files.delete(file);}
        }
        System.out.println("PASS Level 3/5 v3 and v6 PKESK-to-v4 signed MIME; full fingerprint/framing checks before backend; integrity rejection; native v6 regression");
    }
}
