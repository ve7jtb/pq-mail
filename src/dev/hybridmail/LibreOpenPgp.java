package dev.hybridmail;

import static dev.hybridmail.OpenPgp.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.PublicKey;
import java.security.Signature;
import java.security.KeyPairGenerator;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.io.OutputStream;
import org.bouncycastle.openpgp.operator.*;
import java.util.*;
import org.bouncycastle.bcpg.BCPGInputStream;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.crypto.kems.MLKEMGenerator;
import org.bouncycastle.crypto.macs.KMAC;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;

/** Optional GnuPG/LibrePGP v5 compatibility. Its algorithm 8 and KMAC combiner
 * are deliberately separate from RFC 9980 algorithm 35. This implementation
 * accepts the Level 3 Ed25519 + ML-KEM-768/X25519 profile only; v6 remains the
 * default identity and this class never provisions keys or changes policies. */
final class LibreOpenPgp {
    static final int HYBRID=8;
    static final byte[] X_OID=b(3,0x2b,0x65,0x6e);

    /** Enforce the supported profile even if a general packet parser can retain
     * other algorithms. A valid certificate is necessary but not sufficient to
     * select a private key: the caller must also bind these SPKIs to its device. */
    static void validateCertificateEncoding(byte[] encoded)throws Exception{
        // Bound v5's declared key-material length against its enclosing packet
        // before BC retains an unknown algorithm-8 key. Keep this narrow
        // optional profile explicit instead of interpreting unknown curves.
        int primaries=0;
        for(Packet packet:packetsV5(encoded)){
            check(List.of(6,14,13,2).contains(packet.tag()),"Unsupported packet in v5 public certificate");
            if(packet.tag()!=6&&packet.tag()!=14)continue;
            Reader reader=new Reader(packet.body());check(reader.one()==5,"Mixed v5 key versions");reader.number(4);int algorithm=reader.one();
            check(reader.number(4)==reader.left(),"V5 key-material length mismatch");
            check(packet.tag()==6?algorithm==22:algorithm==HYBRID,"Unsupported v5 key profile");if(packet.tag()==6)primaries++;
        }
        check(primaries==1,"Expected one v5 primary key");
    }
    static LegacyOpenPgp certificate(PublicIdentity identity)throws Exception{
        check(identity.version()==5&&identity.legacy!=null,"Expected optional LibrePGP v5 certificate");
        var cert=identity.legacy;
        check(cert.primary.getAlgorithm()==22,"Only v5 Ed25519 compatibility signing is supported");
        check(LegacyOpenPgp.live(cert.primary,cert.primaryPolicy),"Expired v5 primary key");
        return cert;
    }
    static PublicKey signingKey(PublicIdentity identity)throws Exception{return signingKey(certificate(identity).primary);}
    static PublicKey signingKey(PGPPublicKey primary)throws Exception{
        Reader reader=new Reader(primary.getPublicKeyPacket().getEncodedContents());
        check(reader.one()==5,"Expected v5 signing key");reader.number(4);check(reader.one()==22,"Expected legacy Ed25519 algorithm");
        check(reader.number(4)==reader.left(),"Invalid v5 signing-key length");
        check(Arrays.equals(reader.take(10),b(9,0x2b,6,1,4,1,0xda,0x47,0xf,1)),"Unsupported v5 signing curve");
        int bits=(int)reader.number(2);check(bits>0&&bits<=263,"Invalid Ed25519 MPI");byte[] point=reader.take((bits+7)/8);
        // GnuPG v5 omits the historical 0x40 Ed25519 prefix. Accept the
        // precisely sized native form and the explicitly prefixed legacy form.
        if(point.length==33){check(point[0]==0x40,"Invalid Ed25519 prefix");point=slice(point,1,33);}
        check(point.length==32&&reader.left()==0,"Expected complete Ed25519 public point");return curve25519(point,true);
    }
    static PGPContentVerifierBuilderProvider verifier(){
        // Preserve BC's certification/subkey-binding hashing and packet-policy
        // checks, replacing only its v4-only legacy Ed25519 key conversion.
        return (algorithm,hashAlgorithm)->key->{
            try{check(algorithm==22,"Unsupported v5 signature algorithm");
                String name=switch(hashAlgorithm){case 8->"SHA-256";case 9->"SHA-384";case 10->"SHA-512";default->throw new GeneralSecurityException("Unsupported v5 signature hash");};
                MessageDigest digest=MessageDigest.getInstance(name,"BC");Signature signature=Signature.getInstance("Ed25519","BC");signature.initVerify(signingKey(key));
                return new PGPContentVerifier(){
                    public int getHashAlgorithm(){return hashAlgorithm;}public int getKeyAlgorithm(){return algorithm;}public long getKeyID(){return key.getKeyID();}
                    public OutputStream getOutputStream(){return new OutputStream(){public void write(int value){digest.update((byte)value);}public void write(byte[] value,int off,int length){digest.update(value,off,length);}};}
                    public boolean verify(byte[] expected){try{signature.update(digest.digest());return signature.verify(expected);}catch(GeneralSecurityException failure){return false;}}
                };
            }catch(Exception failure){throw new PGPException("Unsupported v5 signing key",failure);}
        };
    }
    static Keys encryptionKeys(PublicIdentity identity)throws Exception{return encryptionKeys(certificate(identity));}
    static Keys encryptionKeys(LegacyOpenPgp cert)throws Exception{
        check(cert.version==5&&cert.recipient!=null&&cert.recipient.getAlgorithm()==HYBRID,"Expected v5 ML-KEM-768/X25519 recipient");
        check(LegacyOpenPgp.live(cert.recipient,cert.bindings.get(cert.recipient.getKeyID())),"Expired v5 recipient binding");
        byte[] body=cert.recipient.getPublicKeyPacket().getEncodedContents();Reader r=new Reader(body);
        check(r.one()==5,"Expected v5 encryption key");r.number(4);check(r.one()==HYBRID,"Wrong v5 KEM algorithm");
        check(r.number(4)==r.left()&&Arrays.equals(r.take(4),X_OID),"Unsupported v5 hybrid curve or material length");
        byte[] point=mpi(r,263);check(point.length==33&&point[0]==0x40,"Invalid v5 X25519 public point");
        check(r.number(4)==1184&&r.left()==1184,"Expected ML-KEM-768 public key");
        return new Keys(pq(r.take(1184),false),curve25519(slice(point,1,33),false));
    }

    /** v5 document signatures hash six zero literal-metadata octets for a
     * detached signature, after the hashed signature header and before the
     * 05 ff / eight-byte-length trailer. BC handles v5 certifications, but its
     * generic document verifier omits these bytes, so this path is explicit. */
    static byte[] documentDigest(byte[] data,PGPSignature signature)throws Exception{
        check(signature.getVersion()==5&&signature.getSignatureType()==0&&signature.getKeyAlgorithm()==22,
            "Only detached binary v5 Ed25519 signatures are supported");
        byte[] trailer=signature.getSignatureTrailer();check(trailer.length>=10,"Truncated v5 signature trailer");
        int end=trailer.length-10;check(trailer[end]==5&&(trailer[end+1]&255)==255,"Invalid v5 signature trailer");
        String name=switch(signature.getHashAlgorithm()){case 8->"SHA-256";case 9->"SHA-384";case 10->"SHA-512";default->throw new GeneralSecurityException("Unsupported v5 document hash");};
        return hash(name,cat(data,slice(trailer,0,end),new byte[6],slice(trailer,end,trailer.length)));
    }
    static void verifySignature(PGPSignature signature,byte[] data,LegacyOpenPgp cert)throws Exception{
        LegacyOpenPgp.policy(signature);check(cert.version==5&&signature.getVersion()==5,"V5 signature version mismatch");
        check(LegacyOpenPgp.live(cert.primary,cert.primaryPolicy),"Expired v5 primary");
        var key=cert.signers.get(signature.getKeyID());check(key!=null&&key.isMasterKey(),"Uncertified v5 signing key");
        check(LegacyOpenPgp.seconds(signature.getCreationTime())>=LegacyOpenPgp.seconds(key.getCreationTime()),"Signature predates key");
        var issuer=signature.getHashedSubPackets().getIssuerFingerprint();
        check(issuer!=null&&issuer.getKeyVersion()==5&&Arrays.equals(issuer.getFingerprint(),key.getFingerprint()),"Wrong full v5 signing fingerprint");
        byte[] digest=documentDigest(data,signature);
        check(Arrays.equals(signature.getDigestPrefix(),slice(digest,0,2)),"V5 signature digest prefix mismatch");
        Signature verifier=Signature.getInstance("Ed25519","BC");
        verifier.initVerify(signingKey(key));verifier.update(digest);
        check(verifier.verify(signature.getSignature()),"Invalid v5 Ed25519 signature");
    }
    static void verifyDetached(byte[] signature,byte[] data,PublicIdentity cert)throws Exception{
        var objects=LegacyOpenPgp.objects(unarmor(signature,"SIGNATURE"));Object item=objects.nextObject();
        check(item instanceof PGPSignatureList&&((PGPSignatureList)item).size()==1&&objects.nextObject()==null,"Expected one detached v5 signature");
        verifySignature(((PGPSignatureList)item).get(0),data,certificate(cert));
    }
    static byte[] signDetached(byte[] data,PublicIdentity cert,Signer callback)throws Exception{
        var validated=certificate(cert);check(validated.signers.containsKey(validated.primary.getKeyID()),"V5 primary not authorized for signing");
        byte[] hashed=cat(sub(2,n(now(),4)),sub(33,cat(b(5),validated.primary.getFingerprint())));
        byte[] header=cat(b(5,0,22,10),n(hashed.length,2),hashed);
        byte[] digest=hash("SHA-512",cat(data,header,new byte[6],b(5,255),n(header.length,8)));
        byte[] signature=callback.sign(digest);check(signature.length==64,"Invalid Ed25519 signature size");
        byte[] packet=frame(2,cat(header,n(0,2),slice(digest,0,2),mpi(slice(signature,0,32)),mpi(slice(signature,32,64))));
        verifyDetached(packet,data,cert);return packet;
    }

    /** Decode bounded old/new packet headers without changing signed packet
     * bodies. GnuPG commonly writes its v5 PKESK using an old-style header.
     * Partial lengths are accepted only for encrypted/compressed payloads. */
    static List<Packet> packetsV5(byte[] encoded)throws Exception{
        check(encoded.length<=LIMIT,"V5 input exceeds limit");var reader=new Reader(encoded);var result=new ArrayList<Packet>();
        while(reader.left()>0){check(result.size()<64,"Too many v5 packets");int header=reader.one();check((header&128)!=0,"Invalid v5 packet header");
            int tag;var body=new Buffer();
            if((header&64)==0){tag=(header>>2)&15;int kind=header&3;check(kind!=3,"Unbounded old packet rejected");long length=reader.number(1<<kind);check(length<=LIMIT,"V5 packet exceeds limit");body.put(reader.take((int)length));}
            else{tag=header&63;int count;do{count=reader.length();check(count!=Integer.MIN_VALUE,"Invalid partial packet length");int length=Math.abs(count);
                check(length<=LIMIT-body.size()&&(count>=0||List.of(8,11,18,20).contains(tag)),"Invalid v5 partial packet");body.put(reader.take(length));}while(count<0);}
            if(tag==10){check(Arrays.equals(body.toByteArray(),bytes("PGP")),"Invalid marker packet");continue;}
            result.add(new Packet(tag,body.toByteArray()));
        }return result;
    }

    /** GnuPG's SOS field resembles an MPI but preserves a leading zero octet.
     * Do not normalize it through BigInteger: that would change X25519's fixed
     * 32-octet little-endian public value and therefore the KDF transcript. */
    static byte[] sos(byte[] value){int bits=value.length*8;if(value[0]!=0)bits-=(Integer.numberOfLeadingZeros(value[0]&255)-24);return cat(n(bits,2),value);}
    static byte[] readSos(Reader reader)throws Exception{int bits=(int)reader.number(2);check(bits>=249&&bits<=256,"Expected fixed-width X25519 SOS");byte[] point=reader.take(32);check(Arrays.equals(n(bits,2),slice(sos(point),0,2)),"Noncanonical X25519 SOS");return point;}
    static byte[] combine(byte[] ec,byte[] point,byte[] recipient,byte[] pq,byte[] pqCipher,int cipher,byte[] fp)throws Exception{
        check(ec.length==32&&!Arrays.equals(ec,new byte[32])&&point.length==32&&recipient.length==32&&pq.length==32&&pqCipher.length==1088&&fp.length==32,"Invalid v5 KEM component");
        byte[] ecHash=hash("SHA3-256",cat(ec,point,recipient));
        byte[] input=cat(n(1,4),ecHash,point,pq,pqCipher,b(cipher),fp);
        try{var kmac=new KMAC(256,bytes("KDF"));kmac.init(new KeyParameter(bytes("OpenPGPCompositeKeyDerivationFunction")));
            kmac.update(input,0,input.length);byte[] kek=new byte[32];kmac.doFinal(kek,0,32);return kek;
        }finally{wipe(ecHash);wipe(input);}
    }

    static byte[] encrypt(byte[] literalPackets,PublicIdentity recipient)throws Exception{return encrypt(literalPackets,certificate(recipient));}
    static byte[] encrypt(byte[] literalPackets,LegacyOpenPgp cert)throws Exception{
        check(literalPackets.length<=LIMIT,"V5 plaintext exceeds limit");Keys keys=encryptionKeys(cert);
        check(cert.cipher==9,"V5 Level 3 compatibility requires advertised AES-256");
        var builder=new JcePGPDataEncryptorBuilder(9).setWithIntegrityPacket(true).setSecureRandom(RANDOM).setProvider("BC");
        var generator=new PGPEncryptedDataGenerator(builder);
        // BC owns the random session key and integrity-protected SEIPD payload;
        // this method supplies only the LibrePGP-specific session-key envelope.
        generator.addMethod((encryptor,session)->{
            byte[] ec=null,pqSecret=null,kek=null;org.bouncycastle.crypto.SecretWithEncapsulation encapsulation=null;
            try{var ephemeral=KeyPairGenerator.getInstance("X25519","BC").generateKeyPair();byte[] point=raw(ephemeral.getPublic());ec=derive(ephemeral.getPrivate(),keys.ec());
                encapsulation=new MLKEMGenerator(RANDOM).generateEncapsulated((MLKEMPublicKeyParameters)PublicKeyFactory.createKey(keys.pq().getEncoded()));
                pqSecret=encapsulation.getSecret();byte[] ct=encapsulation.getEncapsulation();
                kek=combine(ec,point,raw(keys.ec()),pqSecret,ct,9,cert.recipient.getFingerprint());byte[] wrapped=wrap(true,kek,session);
                return PublicKeyEncSessionPacket.createV3PKESKPacket(cert.recipient.getKeyID(),HYBRID,
                    new byte[][]{sos(point),cat(n(ct.length,4),ct),cat(b(9,wrapped.length),wrapped)});
            }catch(Exception failure){throw new PGPException("V5 encapsulation failed",failure);}
            finally{wipe(ec);wipe(pqSecret);wipe(kek);if(encapsulation!=null)try{encapsulation.destroy();}catch(Exception ignored){}}
        });
        var result=new ByteArrayOutputStream();try(var stream=generator.open(result,(long)literalPackets.length)){stream.write(literalPackets);}return result.toByteArray();
    }
    record Envelope(byte[] point,byte[] pqCipher,byte[] wrapped,int cipher,Packet payload){}
    static Envelope envelope(byte[] encoded,PublicIdentity recipient)throws Exception{
        var cert=certificate(recipient);encryptionKeys(cert);var packets=packetsV5(unarmor(encoded,"MESSAGE"));
        check(packets.size()==2&&packets.get(0).tag()==1&&List.of(18,20).contains(packets.get(1).tag()),"Expected one v5 recipient and protected payload");
        Reader reader=new Reader(packets.get(0).body());check(reader.one()==3&&Arrays.equals(reader.take(8),slice(cert.recipient.getFingerprint(),0,8))&&reader.one()==HYBRID,"Wrong v5 hybrid recipient");
        byte[] point=readSos(reader);check(reader.number(4)==1088,"Invalid v5 ML-KEM ciphertext length");byte[] pq=reader.take(1088);int cipher=reader.one();
        check(cipher==9&&reader.one()==40&&reader.left()==40,"V5 compatibility requires wrapped AES-256");byte[] wrapped=reader.take(40);Packet payload=packets.get(1);
        if(payload.tag()==18)check(payload.body().length>23&&payload.body()[0]==1,"Expected v1 SEIPD");
        else check(payload.body().length>35&&payload.body()[0]==1&&payload.body()[1]==9&&payload.body()[2]==2&&(payload.body()[3]&255)<=16,"Expected bounded AES-256/OCB v5 AEAD");
        return new Envelope(point,pq,wrapped,cipher,payload);
    }
    static void validateEnvelope(byte[] encrypted,PublicIdentity recipient)throws Exception{envelope(encrypted,recipient);}
    static byte[] decrypt(byte[] encrypted,PublicIdentity recipient,ExternalKem.Backend backend)throws Exception{
        check(backend!=null,"V5 hybrid decryption requires selected component backend");Envelope request=envelope(encrypted,recipient);Keys keys=encryptionKeys(recipient);
        byte[] ec=null,pq=null,kek=null,session=null,plain=null;var operation=backend.newOperation();
        try{pq=operation.decapsulate(keys.pq(),request.pqCipher());ec=operation.derive(keys.ec(),curve25519(request.point(),false));
            kek=combine(ec,request.point(),raw(keys.ec()),pq,request.pqCipher(),request.cipher(),recipient.legacy.recipient.getFingerprint());session=wrap(false,kek,request.wrapped());check(session.length==32,"Invalid v5 session key");
            // The algorithm-8 envelope was already parsed and authenticated by
            // key unwrapping. Feed only its protected data packet to BC's
            // session-key decryptor, avoiding unsupported PKESK parsing entirely.
            var list=new PGPEncryptedDataList(new BCPGInputStream(new ByteArrayInputStream(frame(request.payload().tag(),request.payload().body()))));
            var data=list.extractSessionKeyEncryptedData();check(data.isIntegrityProtected()||data.isAEAD(),"Unprotected payload rejected");
            plain=LegacyOpenPgp.bounded(data.getDataStream(new JceSessionKeyDataDecryptorFactoryBuilder().setProvider("BC").build(new PGPSessionKey(9,session))));
            // Reading through EOF validates every AEAD chunk and final tag.
            // BC's verify() rejects legacy tag-20 AEAD before its AEAD branch;
            // invoke it only for the separate SEIPD-v1 MDC path.
            if(!data.isAEAD())check(data.verify(),"V5 message integrity failure");byte[] result=plain;plain=null;return result;
        }finally{wipe(ec);wipe(pq);wipe(kek);wipe(session);wipe(plain);operation.clearSecrets();}
    }
}
