package dev.hybridmail;

import java.io.*;
import java.util.*;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;

/** Validated v4, optional LibrePGP v5 and RFC 9980 v6 public key rings. Never supplies a private key. */
final class LegacyOpenPgp {
    final int version;
    final PGPPublicKey primary, recipient;
    final List<String> emails;
    final Map<Long,PGPPublicKey> signers=new HashMap<>();
    final Map<Long,PGPPublicKey> boundKeys=new HashMap<>();
    final Map<Long,PGPSignature> bindings=new HashMap<>();
    final PGPSignature primaryPolicy;
    final int cipher;
    static void require(boolean b,String s)throws Exception{OpenPgp.check(b,s);}
    static JcaPGPContentVerifierBuilderProvider verifier(){return new JcaPGPContentVerifierBuilderProvider().setProvider("BC");}
    static PGPObjectFactory objects(byte[] b){return new PGPObjectFactory(b,new JcaKeyFingerprintCalculator());}
    static byte[] bounded(InputStream in)throws Exception{
        try(in;var out=new ByteArrayOutputStream()){byte[] buf=new byte[8192];int n;while((n=in.read(buf))!=-1){require(out.size()+n<=OpenPgp.LIMIT,"OpenPGP decompressed data exceeds limit");out.write(buf,0,n);}return out.toByteArray();}}
    static long seconds(Date d){return d.getTime()/1000;}
    static void policy(PGPSignature s)throws Exception{
        require((s.getVersion()==4||s.getVersion()==5||s.getVersion()==6),"Expected v4/v5/v6 signature");
        require(List.of(8,9,10,11,12,14).contains(s.getHashAlgorithm()),"Legacy signatures require SHA-224 or stronger SHA-2");
        var h=s.getHashedSubPackets();require(h!=null&&h.hasSubpacket(2),"Signature has no authenticated creation time");
        for(int t:h.getCriticalTags())require(List.of(2,3,9,11,16,21,22,23,25,27,30,32,33,34,39).contains(t),"Unsupported critical signature subpacket: "+t);
        long created=seconds(s.getCreationTime()),expiry=h.getSignatureExpirationTime();
        require(created<=OpenPgp.now()+300,"Future signature");require(expiry==0||created+expiry>=OpenPgp.now(),"Expired signature");
    }
    static boolean live(PGPPublicKey k,PGPSignature s)throws Exception{
        policy(s);require(s.getVersion()==k.getVersion(),"Certificate signature version mismatch");long created=seconds(k.getCreationTime()),expiry=s.getHashedSubPackets().getKeyExpirationTime();
        return seconds(s.getCreationTime())>=created&&created<=OpenPgp.now()+300&&(expiry==0||created+expiry>=OpenPgp.now());
    }
    // Algorithm 8 has this hybrid meaning only inside the explicitly bounded
    // v5 profile. Do not reinterpret other packet versions using that number.
    static int rank(PGPPublicKey k){return k.getAlgorithm()==36?2:k.getAlgorithm()==35||k.getVersion()==5&&k.getAlgorithm()==8?1:0;}
    static boolean supported(PGPPublicKey k){return k.getVersion()==5?(k.getAlgorithm()==22&&k.isMasterKey()||k.getAlgorithm()==8&&!k.isMasterKey()):k.getVersion()==6?List.of(25,26,27,28,30,31,35,36).contains(k.getAlgorithm()):k.getVersion()==4&&switch(k.getAlgorithm()){
        case 1,2,3 -> k.getBitStrength()>=2048;
        case 30 -> k.getVersion()==6;
        case 35 -> !k.isMasterKey();
        case 18,19,22 -> k.getBitStrength()>=255;
        default -> false;
    };}
    @FunctionalInterface interface Check{boolean run(PGPSignature s)throws Exception;}
    // Treat packet issuer IDs as hints, never as proof of authorship. Only
    // signatures that verify under the supplied primary/subkey reach policy
    // selection; unrelated third-party certifications cannot change key flags.
    static List<PGPSignature> verified(Iterator<PGPSignature> it,PGPPublicKey issuer,Check check)throws Exception{
        var out=new ArrayList<PGPSignature>();int count=0;
        while(it!=null&&it.hasNext()){require(++count<=512,"Too many certificate signatures");var s=it.next();
            // A wrong issuer ID may be omitted, so only cryptographic verification establishes authorship.
            try{s.init(issuer.getVersion()==5?LibreOpenPgp.verifier():verifier(),issuer);if(check.run(s))out.add(s);}catch(PGPException|IllegalArgumentException e){/* invalid/third-party signature */}
        }return out;
    }
    static PGPSignature latest(List<PGPSignature> list){return list.stream().max(Comparator.comparing(PGPSignature::getCreationTime)).orElse(null);}
    LegacyOpenPgp(byte[] encoded)throws Exception{this(encoded,4);}
    LegacyOpenPgp(byte[] encoded,int version)throws Exception{
        this.version=version;
        require(encoded.length<=128*1024,"Public certificate exceeds 128 KiB");if(version==5)LibreOpenPgp.validateCertificateEncoding(encoded);var f=objects(encoded);Object o=f.nextObject();
        require(o instanceof PGPPublicKeyRing&&f.nextObject()==null,"Expected exactly one public certificate");var ring=(PGPPublicKeyRing)o;primary=ring.getPublicKey();
        require(primary.getVersion()==version&&supported(primary)&&primary.isMasterKey(),"Unsupported primary key");
        require(verified(primary.getSignaturesOfType(PGPSignature.KEY_REVOCATION),primary,s->s.verifyCertification(primary)).isEmpty(),"Revoked primary key");
        var policies=new ArrayList<PGPSignature>();
        policies.addAll(verified(primary.getSignaturesOfType(PGPSignature.DIRECT_KEY),primary,s->s.verifyCertification(primary)));
        // An email address becomes a candidate only through a live verified
        // self-certification. This certifies a key-to-address claim; the contact
        // trust store still determines whether the user trusts that claim.
        var addresses=new ArrayList<String>();
        var ids=primary.getUserIDs();int count=0;
        while(ids.hasNext()){require(++count<=64,"Too many certificate user IDs");String uid=ids.next();
            var self=verified(primary.getSignaturesForID(uid),primary,s->(s.getSignatureType()>=16&&s.getSignatureType()<=19||s.getSignatureType()==48)&&s.verifyCertification(uid,primary));
            if(self.stream().anyMatch(s->s.getSignatureType()==48))continue;
            var cert=latest(self);if(cert==null)continue;require(!cert.getHashedSubPackets().hasSubpacket(12),"Designated revocation keys are not supported");if(version==4||version==5)policies.add(cert);
            try{if(!live(primary,cert))continue;}catch(Exception e){continue;}
            int at=uid.lastIndexOf('<');String email=at>=0&&uid.endsWith(">")?uid.substring(at+1,uid.length()-1):uid;
            try{OpenPgp.validateEmail(email);addresses.add(email);}catch(Exception e){/* non-mail user ID */}
        }
        primaryPolicy=latest(policies);require(primaryPolicy!=null&&live(primary,primaryPolicy),"Expired or uncertified primary key");
        for(var policy:policies)require(!policy.getHashedSubPackets().hasSubpacket(12),"Designated revocation keys are not supported");
        require(version!=6||(primaryPolicy.getHashedSubPackets().getKeyFlags()&1)!=0,"Primary key cannot certify");
        int[] preferences=primaryPolicy.getHashedSubPackets().getPreferredSymmetricAlgorithms();cipher=preferences==null?7:Arrays.stream(preferences).anyMatch(v->v==9)?9:Arrays.stream(preferences).anyMatch(v->v==7)?7:0;
        require(!addresses.isEmpty(),"No current self-certified email address");emails=List.copyOf(addresses);
        if((primaryPolicy.getHashedSubPackets().getKeyFlags()&2)!=0)signers.put(primary.getKeyID(),primary);
        PGPPublicKey selected=null;var keys=ring.getPublicKeys();count=0;
        while(keys.hasNext()){require(++count<=64,"Too many subkeys");var k=keys.next();if(k.isMasterKey()||k.getVersion()!=version||!supported(k))continue;
            if(!verified(k.getSignaturesOfType(PGPSignature.SUBKEY_REVOCATION),primary,s->s.verifyCertification(primary,k)).isEmpty())continue;
            var bind=latest(verified(k.getSignaturesOfType(PGPSignature.SUBKEY_BINDING),primary,s->s.verifyCertification(primary,k)));if(bind==null)continue;
            try{if(!live(k,bind))continue;}catch(Exception e){continue;}
            boundKeys.put(k.getKeyID(),k);bindings.put(k.getKeyID(),bind);int flags=bind.getHashedSubPackets().getKeyFlags();
            if((flags&12)!=0&&(k.isEncryptionKey()||version==5&&k.getAlgorithm()==8)&&(selected==null||rank(k)>rank(selected)||rank(k)==rank(selected)&&k.getCreationTime().after(selected.getCreationTime())))selected=k;
            // Signing subkeys additionally prove possession with an embedded
            // primary-key-binding signature (back signature). An encryption
            // binding alone is insufficient to authorize document signatures.
            if((flags&2)!=0){boolean cross=false;var embeddedList=new ArrayList<PGPSignature>();for(var packets:Arrays.asList(bind.getHashedSubPackets(),bind.getUnhashedSubPackets())){if(packets!=null){var es=packets.getEmbeddedSignatures();for(int j=0;j<es.size();j++)embeddedList.add(es.get(j));}}var embedded=embeddedList;
                for(int i=0;i<embedded.size();i++){var s=embedded.get(i);if(s.getSignatureType()!=PGPSignature.PRIMARYKEY_BINDING)continue;
                    try{policy(s);s.init(verifier(),k);if(s.verifyCertification(primary,k))cross=true;}catch(PGPException e){/* invalid cross-certification */}}
                if(cross){require(!signers.containsKey(k.getKeyID()),"Ambiguous signing key ID");signers.put(k.getKeyID(),k);bindings.put(k.getKeyID(),bind);}
            }
        }recipient=selected;
        // Resolve the exact v5 component shapes now, before accepting this
        // certificate as an encryption candidate or dispatching a private call.
        if(version==5&&recipient!=null)LibreOpenPgp.encryptionKeys(this);
    }
    String signingAlgorithms(){
        return signers.isEmpty()?"No usable signing key":signers.values().stream().map(k->{
            if(k.getAlgorithm()==27)return "Ed25519";
            if(k.getAlgorithm()==31)return "ML-DSA-87 + Ed448";
            if(k.getAlgorithm()==30)return "ML-DSA-65 + Ed25519";
            if(k.getAlgorithm()==1||k.getAlgorithm()==3)return "RSA "+k.getBitStrength();
            String oid=k.getPublicKeyPacket().getKey() instanceof org.bouncycastle.bcpg.ECPublicBCPGKey ec?ec.getCurveOID().getId():"unknown";
            if(k.getAlgorithm()==22)return switch(oid){case "1.3.6.1.4.1.11591.15.1","1.3.101.112"->"Ed25519";case "1.3.101.113"->"Ed448";default->"EdDSA (curve "+oid+")";};
            return switch(oid){case "1.2.840.10045.3.1.7"->"ECDSA P-256";case "1.3.132.0.34"->"ECDSA P-384";case "1.3.132.0.35"->"ECDSA P-521";default->"ECDSA (curve "+oid+")";};
        }).distinct().sorted().collect(java.util.stream.Collectors.joining("; "));
    }
    String encryptionAlgorithm(){
        if(recipient==null)return "No usable encryption subkey";
        if(recipient.getAlgorithm()==36)return "ML-KEM-1024 + X448";
        if(recipient.getAlgorithm()==35)return "ML-KEM-768 + X25519";
        if(version==5&&recipient.getAlgorithm()==8)return "ML-KEM-768 + X25519 (LibrePGP v5)";
        if(recipient.getAlgorithm()==18&&recipient.getPublicKeyPacket().getKey() instanceof org.bouncycastle.bcpg.ECPublicBCPGKey ec){
            return switch(ec.getCurveOID().getId()){
                case "1.3.6.1.4.1.3029.1.5.1","1.3.101.110" -> "X25519";
                case "1.2.840.10045.3.1.7" -> "ECDH P-256";
                case "1.3.132.0.34" -> "ECDH P-384";
                case "1.3.132.0.35" -> "ECDH P-521";
                default -> "ECDH (curve "+ec.getCurveOID().getId()+")";
            };
        }
        return "RSA "+recipient.getBitStrength();
    }
    boolean matches(String email){return emails.stream().anyMatch(s->s.equalsIgnoreCase(email));}
    byte[] encrypt(byte[] signed)throws Exception{
        if(version==5)return LibreOpenPgp.encrypt(signed,this);
        // Revalidate at use, so a certificate cannot remain usable past expiration in a long-running app.
        require(live(primary,primaryPolicy),"Expired primary key");require(recipient!=null&&live(recipient,bindings.get(recipient.getKeyID())),"Certificate has no current encryption subkey");
        require(cipher!=0,"Recipient does not advertise supported AES encryption");
        var builder=new JcePGPDataEncryptorBuilder(cipher).setWithIntegrityPacket(true).setSecureRandom(OpenPgp.RANDOM).setProvider("BC");
        if(version==6){
            // RFC 9980 section 7.1 adds implicit AES-256/OCB for PQ certificates.
            int chosen=(primary.getAlgorithm()==30||primary.getAlgorithm()==31)?9:7,mode=2;var preferences=primaryPolicy.getHashedSubPackets().getSubpacket(39);
            if(preferences!=null){byte[] pairs=preferences.getData();require(pairs.length%2==0,"Invalid AEAD preferences");for(int i=0;i<pairs.length;i+=2)if((pairs[i]==7||pairs[i]==9)&&(pairs[i+1]==2||pairs[i+1]==3)){chosen=pairs[i];mode=pairs[i+1];break;}}
            builder=new JcePGPDataEncryptorBuilder(chosen).setWithAEAD(mode,16).setUseV6AEAD().setSecureRandom(OpenPgp.RANDOM).setProvider("BC");
        }
        var gen=new PGPEncryptedDataGenerator(builder);
        gen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(recipient).setProvider("BC").setSecureRandom(OpenPgp.RANDOM));
        var out=new ByteArrayOutputStream();try(var stream=gen.open(out,(long)signed.length)){stream.write(signed);}return out.toByteArray();
    }
    void verify(byte[] signature,byte[] data)throws Exception{
        var f=objects(signature);Object o=f.nextObject();require(o instanceof PGPSignatureList&&((PGPSignatureList)o).size()==1&&f.nextObject()==null,"Expected one detached signature");verify(((PGPSignatureList)o).get(0),data);
    }
    void verify(PGPSignature s,byte[] data)throws Exception{
        if(version==5){LibreOpenPgp.verifySignature(s,data,this);return;}
        policy(s);require(s.getVersion()==version,"Signature version does not match certificate");require(s.getSignatureType()==0||s.getSignatureType()==1,"Expected document signature");
        require(live(primary,primaryPolicy),"Expired primary key");var k=signers.get(s.getKeyID());require(k!=null,"Signature does not use a certified signing key");
        if(!k.isMasterKey())require(live(k,bindings.get(k.getKeyID())),"Expired signing subkey");
        require(seconds(s.getCreationTime())>=seconds(k.getCreationTime()),"Signature predates signing key");
        if(version==6){var issuer=s.getHashedSubPackets().getIssuerFingerprint();require(issuer!=null&&Arrays.equals(issuer.getFingerprint(),k.getFingerprint()),"Wrong signing fingerprint");}
        s.init(verifier(),k);s.update(data);require(s.verify(),"Invalid OpenPGP signature");
    }
    // Bound every decompression layer and reject extra packet sequences. The
    // literal bytes are returned only after document-signature verification;
    // parsing a literal packet must never itself trigger a "verified" display.
    byte[] openSigned(byte[] data)throws Exception{
        require(version!=5,"V5 inline signatures are not supported; use detached PGP/MIME signatures");
        var f=objects(data);Object first=f.nextObject();int depth=0;
        while(first instanceof PGPCompressedData c){require(++depth<=3,"Unsupported compressed packet nesting");data=bounded(c.getDataStream());require(f.nextObject()==null,"Trailing compressed packet");f=objects(data);first=f.nextObject();}
        require(first instanceof PGPOnePassSignatureList&&((PGPOnePassSignatureList)first).size()==1,"Expected one document signer");var one=((PGPOnePassSignatureList)first).get(0);
        Object literal=f.nextObject();require(literal instanceof PGPLiteralData,"Expected literal data");byte[] plain=bounded(((PGPLiteralData)literal).getInputStream());Object last=f.nextObject();
        Object trailing=f.nextObject();if(version==6&&trailing instanceof PGPPadding)trailing=f.nextObject();
        require(last instanceof PGPSignatureList&&((PGPSignatureList)last).size()==1&&trailing==null,"Expected final signature");var sig=((PGPSignatureList)last).get(0);
        require(one.getKeyID()==sig.getKeyID()&&one.getKeyAlgorithm()==sig.getKeyAlgorithm()&&one.getHashAlgorithm()==sig.getHashAlgorithm()&&one.getSignatureType()==sig.getSignatureType(),"One-pass signature mismatch");if(version==6)require(one.getVersion()==6&&Arrays.equals(one.getFingerprint(),sig.getHashedSubPackets().getIssuerFingerprint().getFingerprint()),"One-pass fingerprint/salt mismatch");verify(sig,plain);one.init(verifier(),signers.get(sig.getKeyID()));one.update(plain);require(one.verify(sig),"Invalid one-pass signature");return plain;
    }
}
