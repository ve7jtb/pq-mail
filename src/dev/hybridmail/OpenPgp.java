package dev.hybridmail;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x9.*;
import org.bouncycastle.asn1.sec.*;
import org.bouncycastle.crypto.kems.*;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.util.*;
import org.bouncycastle.jcajce.*;
import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import jakarta.mail.internet.*;

/** Bounded RFC 9580 / RFC 9980 codec for draft-nist-bp-comp-05 IDs 41/37.
 * No CMS signature representatives or CMS KEM labels are reused here.
 */
public final class OpenPgp {
    static {MailEngine.init();}
    static final class Buffer extends ByteArrayOutputStream {void put(byte[] value){write(value,0,value.length);}}
    static final int LIMIT=20*1024*1024;
    static final SecureRandom RANDOM=new SecureRandom();
    static void check(boolean value,String message)throws GeneralSecurityException{if(!value)throw new GeneralSecurityException(message);}
    static byte[] bytes(String s){return s.getBytes(StandardCharsets.UTF_8);}
    static byte[] cat(byte[]...items){var out=new Buffer();for(byte[] b:items)out.put(b);return out.toByteArray();}
    static byte[] b(int...values){byte[] out=new byte[values.length];for(int i=0;i<values.length;i++)out[i]=(byte)values[i];return out;}
    static byte[] n(long value,int size){byte[] out=new byte[size];for(int i=size-1;i>=0;i--){out[i]=(byte)value;value>>>=8;}return out;}
    static byte[] random(int count){byte[] out=new byte[count];RANDOM.nextBytes(out);return out;}
    static byte[] hash(String algorithm,byte[] value)throws Exception{return MessageDigest.getInstance(algorithm,"BC").digest(value);}
    static byte[] slice(byte[] d,int from,int to){return Arrays.copyOfRange(d,from,to);}
    static long now(){return System.currentTimeMillis()/1000;}
    static byte[] frame(int tag,byte[] body){return cat(b(0xc0|tag,255),n(body.length,4),body);}
    static byte[] sub(int tag,byte[] body){return cat(b(255),n(body.length+1,4),b(tag),body);}
    static byte[] keyHash(byte[] body){return cat(b(0x9b),n(body.length,4),body);}
    // V5 uses the 0x9a framing octet, distinct from v4's SHA-1 framing and
    // v6's 0x9b framing. Never select a fingerprint rule from key size alone.
    static byte[] fingerprint(byte[] body)throws Exception{return body[0]==4?hash("SHA-1",cat(b(0x99),n(body.length,2),body)):hash("SHA-256",body[0]==5?cat(b(0x9a),n(body.length,4),body):keyHash(body));}
    static String hex(byte[] value){StringBuilder s=new StringBuilder();for(byte v:value)s.append(String.format("%02x",v&255));return s.toString();}
    static void wipe(byte[] value){if(value!=null)Arrays.fill(value,(byte)0);}
    public static byte[] armor(byte[] data,String kind){return bytes("-----BEGIN PGP "+kind+"-----\r\n\r\n"+Base64.getMimeEncoder(64,b(13,10)).encodeToString(data)+"\r\n-----END PGP "+kind+"-----\r\n");}
    static byte[] unarmor(byte[] input,String kind)throws Exception {
        check(input.length<=LIMIT,"OpenPGP input exceeds limit");String s=new String(input,StandardCharsets.UTF_8);
        if(!s.startsWith("-----BEGIN"))return input;
        String[] lines=s.replace("\r\n","\n").split("\n");check(lines[0].equals("-----BEGIN PGP "+kind+"-----"),"Wrong armor type");
        boolean body=false,end=false;StringBuilder encoded=new StringBuilder();
        for(int i=1;i<lines.length;i++){String l=lines[i];if(l.equals("-----END PGP "+kind+"-----")){end=true;break;}if(!body){if(l.isEmpty())body=true;else check(l.contains(":"),"Invalid armor header");continue;}if(!l.startsWith("="))encoded.append(l.replaceAll("\\s",""));}
        check(end,"Truncated armor");return Base64.getDecoder().decode(encoded.toString());
    }
    static final class Reader {
        final byte[] data;int at;
        Reader(byte[] data){this.data=data;}
        int left(){return data.length-at;}
        byte[] take(int count)throws Exception{check(count>=0&&count<=left(),"Truncated OpenPGP data");byte[] result=slice(data,at,at+count);at+=count;return result;}
        int one()throws Exception{return take(1)[0]&255;}
        long number(int count)throws Exception{long v=0;for(byte c:take(count))v=v*256+(c&255);return v;}
        int length()throws Exception{int a=one();if(a<192)return a;if(a<224)return(a-192)*256+one()+192;if(a==255){long n=number(4);check(n<=LIMIT,"OpenPGP length exceeds limit");return(int)n;}return -(1<<(a&31));}
    }
    record Packet(int tag,byte[] body){}
    static List<Packet> packets(byte[] data)throws Exception {
        check(data.length<=LIMIT,"OpenPGP message exceeds limit");Reader r=new Reader(data);List<Packet> out=new ArrayList<>();
        while(r.left()>0){check(out.size()<64,"Too many OpenPGP packets");int header=r.one();check((header&0xc0)==0xc0,"Legacy OpenPGP packets are unsupported");int tag=header&63;var body=new Buffer();int count;
            do{count=r.length();check(count!=Integer.MIN_VALUE,"Invalid partial length");int len=Math.abs(count);check(len<=LIMIT-body.size()&&(count>=0||List.of(8,9,11,18).contains(tag)),"Invalid partial packet");body.put(r.take(len));}while(count<0);
            if(tag==21)continue;if(tag==10){check(Arrays.equals(body.toByteArray(),bytes("PGP")),"Invalid marker");continue;}out.add(new Packet(tag,body.toByteArray()));
        }return out;
    }
    static byte[] raw(PublicKey key){return SubjectPublicKeyInfo.getInstance(key.getEncoded()).getPublicKeyData().getOctets();}
    static PublicKey ec(byte[] point)throws Exception {
        check(point.length==97&&point[0]==4,"Expected P-384 uncompressed point");
        var curve=SECNamedCurves.getByName("secp384r1").getCurve();var q=curve.decodePoint(point);check(!q.isInfinity()&&q.isValid(),"Invalid EC point");
        return KeyFactory.getInstance("EC","BC").generatePublic(new X509EncodedKeySpec(new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,SECObjectIdentifiers.secp384r1),point).getEncoded()));
    }
    static PublicKey pq(byte[] raw,boolean signing)throws Exception {
        var oid=new ASN1ObjectIdentifier(signing?"2.16.840.1.101.3.4.3.18":"2.16.840.1.101.3.4.4.2");
        return KeyFactory.getInstance(signing?"ML-DSA":"ML-KEM","BC").generatePublic(new X509EncodedKeySpec(new SubjectPublicKeyInfo(new AlgorithmIdentifier(oid),raw).getEncoded()));
    }
    record Keys(PublicKey pq,PublicKey ec){}
    static boolean modern(Keys k){return !(k.ec instanceof java.security.interfaces.ECPublicKey);}
    static PublicKey curve25519(byte[] value,boolean signing)throws Exception {
        check(value.length==32,"Expected 32-byte 25519 public key");
        return KeyFactory.getInstance(signing?"Ed25519":"X25519","BC").generatePublic(new X509EncodedKeySpec(new SubjectPublicKeyInfo(new AlgorithmIdentifier(new ASN1ObjectIdentifier(signing?"1.3.101.112":"1.3.101.110")),value).getEncoded()));
    }
    static int algorithm(Keys k,boolean signing){return k.pq==null?(signing?19:18):modern(k)?(signing?(raw(k.ec).length==57?31:30):(raw(k.ec).length==56?36:35)):(signing?41:37);}
    public static boolean rfc9980(PublicIdentity own){return own.legacy==null&&modern(own.signing);}

    static final byte[] X25519_OID=b(10,0x2b,6,1,4,1,0x97,0x55,1,5,1);
    static final byte[] P384_OID=b(5,0x2b,0x81,4,0,0x22);
    static byte[] mpi(byte[] value){BigInteger v=new BigInteger(1,value);byte[] raw=v.toByteArray();if(raw.length>1&&raw[0]==0)raw=slice(raw,1,raw.length);return cat(n(v.bitLength(),2),raw);}
    static byte[] mpi(Reader r,int max)throws Exception{int bits=(int)r.number(2);check(bits>0&&bits<=max,"Invalid MPI length");byte[] out=r.take((bits+7)/8);check(new BigInteger(1,out).bitLength()==bits,"Noncanonical MPI");return out;}
    static Keys parseKey(byte[] data,boolean signing)throws Exception {
        Reader r=new Reader(data);check(r.one()==6,"OpenPGP v6 required");check(r.number(4)<=now()+300,"Future OpenPGP key");int alg=r.one();int size=(int)r.number(4);check(size==r.left(),"Invalid key size");
        if(alg==(signing?19:18)){check(Arrays.equals(r.take(6),P384_OID),"Expected NIST P-384");PublicKey ec=ec(mpi(r,776));if(!signing)check(Arrays.equals(r.take(4),b(3,1,9,8)),"P-384 requires SHA-384 / AES-192 KDF");check(r.left()==0,"Trailing EC key data");return new Keys(null,ec);}
        if(alg==(signing?31:36)){check(size==(signing?2649:1624),"Invalid Level 5 composite key size");int len=signing?57:56;PublicKey ec=KeyFactory.getInstance(signing?"Ed448":"X448","BC").generatePublic(new X509EncodedKeySpec(new SubjectPublicKeyInfo(new AlgorithmIdentifier(new ASN1ObjectIdentifier(signing?"1.3.101.113":"1.3.101.111")),r.take(len)).getEncoded()));PublicKey pq=KeyFactory.getInstance(signing?"ML-DSA":"ML-KEM","BC").generatePublic(new X509EncodedKeySpec(new SubjectPublicKeyInfo(new AlgorithmIdentifier(new ASN1ObjectIdentifier(signing?"2.16.840.1.101.3.4.3.19":"2.16.840.1.101.3.4.4.3")),r.take(r.left())).getEncoded()));return new Keys(pq,ec);}
        if(alg==(signing?30:35)){check(size==(signing?1984:1216),"Invalid RFC 9980 key size");PublicKey ec=curve25519(r.take(32),signing);return new Keys(pq(r.take(r.left()),signing),ec);}
        check(alg==(signing?41:37)&&size==(signing?2049:1281),"Unsupported OpenPGP key profile");PublicKey ec=ec(r.take(97));return new Keys(pq(r.take(r.left()),signing),ec);
    }
    static byte[] keyBody(Keys k,boolean signing,long created){byte[] material=k.pq==null?cat(P384_OID,mpi(raw(k.ec)),signing?b():b(3,1,9,8)):cat(raw(k.ec),raw(k.pq));return cat(b(6),n(created,4),b(algorithm(k,signing)),n(material.length,4),material);}
    public static boolean classical(Identity id){return id!=null&&Identity.HYBRID_87_SIGN.equals(id.signatureAlgorithm())&&id.encryptionCert()!=null&&Identity.HYBRID_1024_KEM.equals(id.encryptionCert().getPublicKey().getAlgorithm());}
    public static boolean supported(Identity id){return id!=null&&(id.softwareOpenPgp()!=null||id.level3Polyfill())||classical(id)||(id!=null&&Identity.HYBRID_65_P384_SIGN.equals(id.signatureAlgorithm())&&id.encryptionCert()!=null&&Identity.HYBRID_768_P384_KEM.equals(id.encryptionCert().getPublicKey().getAlgorithm()));}
    static Keys identityKeys(Identity id,boolean signing)throws Exception{Keys k=keys((signing?id.signingCert():id.encryptionCert()).getPublicKey());return classical(id)?new Keys(null,k.ec):k;}
    static String profile(Keys keys){return modern(keys)&&raw(keys.ec).length==57?"OpenPGP RFC 9980 Level 5 · ML-DSA-87 + Ed448 / ML-KEM-1024 + X448":modern(keys)?"OpenPGP RFC 9980 · ML-DSA-65 + Ed25519 / ML-KEM-768 + X25519":keys.pq==null?"OpenPGP classical P-384 (not post-quantum)":"OpenPGP Level 3 hybrid — experimental NIST/Brainpool draft-05";}
    static Keys keys(PublicKey key)throws Exception{check(key instanceof CompositePublicKey,"Composite key required");var list=((CompositePublicKey)key).getPublicKeys();check(list.size()==2,"Invalid composite key");return new Keys(list.get(0),list.get(1));}
    static byte[] fixed(byte[] der)throws Exception {
        ASN1Sequence seq=ASN1Sequence.getInstance(der);check(seq.size()==2,"Invalid ECDSA");byte[] out=new byte[96];
        for(int i=0;i<2;i++){BigInteger v=ASN1Integer.getInstance(seq.getObjectAt(i)).getValue();check(v.signum()>0&&v.bitLength()<=384,"Invalid ECDSA scalar");byte[] x=v.toByteArray();int start=x.length>48?1:0;System.arraycopy(x,start,out,48*i+48-(x.length-start),x.length-start);}return out;
    }
    static byte[] der(byte[] fixed)throws Exception{check(fixed.length==96,"Invalid ECDSA size");return new DERSequence(new ASN1Encodable[]{new ASN1Integer(new BigInteger(1,slice(fixed,0,48))),new ASN1Integer(new BigInteger(1,slice(fixed,48,96)))}).getEncoded();}
    static void verifyDigest(byte[] sig,byte[] digest,Keys keys)throws Exception {
        if(keys.pq==null){Reader r=new Reader(sig);BigInteger x=new BigInteger(1,mpi(r,384)),y=new BigInteger(1,mpi(r,384));check(r.left()==0,"Trailing ECDSA signature");Signature v=Signature.getInstance("NONEwithECDSA","BC");v.initVerify(keys.ec);v.update(digest);check(v.verify(new DERSequence(new ASN1Encodable[]{new ASN1Integer(x),new ASN1Integer(y)}).getEncoded()),"Invalid OpenPGP ECDSA signature");return;}
        if(modern(keys)){boolean strong=raw(keys.ec).length==57;int edSize=strong?114:64;check(sig.length==(strong?4741:3373),"Invalid RFC 9980 signature size");Signature ed=Signature.getInstance(strong?"Ed448":"Ed25519","BC");ed.initVerify(keys.ec);ed.update(digest);check(ed.verify(slice(sig,0,edSize)),"Invalid OpenPGP Ed25519 signature");Signature ml=Signature.getInstance(strong?"ML-DSA-87":"ML-DSA-65","BC");ml.initVerify(keys.pq);ml.update(digest);check(ml.verify(slice(sig,edSize,sig.length)),"Invalid OpenPGP ML-DSA signature");return;}
        check(sig.length==3405,"Invalid OpenPGP hybrid signature length");
        Signature ec=Signature.getInstance("NONEwithECDSA","BC");ec.initVerify(keys.ec);ec.update(digest);check(ec.verify(der(slice(sig,0,96))),"Invalid OpenPGP ECDSA signature");
        Signature ml=Signature.getInstance("ML-DSA-65","BC");ml.initVerify(keys.pq);ml.update(digest);check(ml.verify(slice(sig,96,sig.length)),"Invalid OpenPGP ML-DSA signature");
    }
    @FunctionalInterface interface Signer{byte[] sign(byte[] digest)throws Exception;}
    static Signer signer(Identity id,ExternalMu.Backend backend)throws Exception {
        return signer(id,backend,identityKeys(id,true));
    }
    static Signer signer(Identity id,ExternalMu.Backend backend,Keys keys)throws Exception {
        check(supported(id),"Select a Level 3 or Level 5 hybrid identity for OpenPGP");
        if(modern(keys)){check(backend!=null,"RFC 9980 extra keys require the YubiKey backend");return digest->{boolean strong=raw(keys.ec).length==57;Signature s=Signature.getInstance(strong?"ML-DSA-87":"ML-DSA-65",ExternalMu.PROVIDER);s.initSign(new ExternalMu.TokenKey(keys.pq,backend));s.update(digest);byte[] ml=s.sign(),ed=strong?backend.signEd448(keys.ec,digest):backend.signEd25519(keys.ec,digest),signature=cat(ed,ml);verifyDigest(signature,digest,keys);return signature;};}
        return digest->{
            if(keys.pq==null){byte[] sig;if(backend!=null)sig=backend.signEcdsa(keys.ec,digest);else{check(id.signingKey() instanceof CompositePrivateKey,"Unlock software identity or select token backend");Signature v=Signature.getInstance("NONEwithECDSA","BC");v.initSign(((CompositePrivateKey)id.signingKey()).getPrivateKeys().get(1),RANDOM);v.update(digest);sig=v.sign();}byte[] fixed=fixed(sig),encoded=cat(mpi(slice(fixed,0,48)),mpi(slice(fixed,48,96)));verifyDigest(encoded,digest,keys);return encoded;}
            byte[] ml,ec;
            if(backend!=null){Signature s=Signature.getInstance("ML-DSA-65",ExternalMu.PROVIDER);s.initSign(new ExternalMu.TokenKey(keys.pq,backend));s.update(digest);ml=s.sign();ec=backend.signEcdsa(keys.ec,digest);}
            else {check(id.signingKey() instanceof CompositePrivateKey,"Unlock software identity or select token backend");var privateKeys=((CompositePrivateKey)id.signingKey()).getPrivateKeys();Signature s=Signature.getInstance("ML-DSA-65","BC");s.initSign(privateKeys.get(0),RANDOM);s.update(digest);ml=s.sign();s=Signature.getInstance("NONEwithECDSA","BC");s.initSign(privateKeys.get(1),RANDOM);s.update(digest);ec=s.sign();}
            byte[] out=cat(fixed(ec),ml);verifyDigest(out,digest,keys);return out;
        };
    }
    record Request(byte[] header,byte[] salt,byte[] digest) {
        byte[] finish(byte[] signature){return cat(header,n(0,4),slice(digest,0,2),b(salt.length),salt,signature);}
    }
    static Request request(byte[] data,int type,byte[] fp,byte[] extra)throws Exception{return request(data,type,fp,extra,41);}
    static Request request(byte[] data,int type,byte[] fp,byte[] extra,int algorithm)throws Exception {
        boolean strong=algorithm==31;byte[] salt=random(strong?32:24),subs=cat(sub(2,n(now(),4)),sub(33,cat(b(6),fp)),extra),header=cat(b(6,type,algorithm,strong?10:9),n(subs.length,4),subs);
        return new Request(header,salt,hash(strong?"SHA-512":"SHA-384",cat(salt,data,header,b(6,255),n(header.length,4))));
    }
    record Checked(Map<Integer,byte[]> subs,byte[] salt,int hash){}
    static Checked verify(byte[] body,byte[] data,int type,byte[] key)throws Exception {
        Reader r=new Reader(body);check(Arrays.equals(r.take(3),b(6,type,key[5]&255)),"Unsupported signature profile");int h=r.one();
        String name=switch(h){case 8->"SHA-256";case 9->"SHA-384";case 10->"SHA-512";case 12->"SHA3-256";case 14->"SHA3-512";default->throw new GeneralSecurityException("Unsupported OpenPGP hash");};int saltSize=h==9?24:(h==10||h==14?32:16);
        int count=(int)r.number(4);check(count<=8192,"Signature metadata too large");byte[] hashed=r.take(count),header=slice(body,0,r.at);int un=(int)r.number(4);check(un<=8192,"Signature metadata too large");r.take(un);byte[] prefix=r.take(2);check(r.one()==saltSize,"Invalid salt length");byte[] salt=r.take(saltSize),sig=r.take(r.left()),digest=hash(name,cat(salt,data,header,b(6,255),n(header.length,4)));
        check(Arrays.equals(prefix,slice(digest,0,2)),"OpenPGP signature digest mismatch");Reader subs=new Reader(hashed);Map<Integer,byte[]> map=new HashMap<>();
        while(subs.left()>0){int len=subs.length();check(len>0,"Invalid subpacket");Reader s=new Reader(subs.take(len));int t=s.one(),tag=t&127;check((t&128)==0||List.of(2,3,9,11,21,22,27,30,33,39).contains(tag),"Unknown critical subpacket");check(!map.containsKey(tag),"Duplicate subpacket");map.put(tag,s.take(s.left()));}
        check(Arrays.equals(map.get(33),cat(b(6),fingerprint(key))),"Wrong issuer fingerprint");
        byte[] time=map.get(2);check(time!=null&&time.length==4,"Missing creation time");long created=new Reader(time).number(4);check(created<=now()+300,"Future signature");
        if(map.containsKey(3)){byte[] expiry=map.get(3);check(expiry.length==4,"Invalid expiry");long seconds=new Reader(expiry).number(4);check(seconds==0||created+seconds>=now(),"Expired signature");}
        verifyDigest(sig,digest,parseKey(key,true));return new Checked(map,salt,h);
    }
    public static final class PublicIdentity {
        PublicIdentity compatibility;
        final byte[] primary,subkey,encoded;final Keys signing,encryption;final String email;final int mode;final LegacyOpenPgp legacy; final LegacyOpenPgp v6;
        public PublicIdentity(byte[] input)throws Exception {
            encoded=unarmor(input,"PUBLIC KEY BLOCK");
            check(encoded.length<=128*1024,"Public certificate exceeds 128 KiB");
            Reader peek=new Reader(encoded);int header=peek.one();check((header&128)!=0,"Invalid public key packet");
            if((header&64)!=0){check((header&63)==6&&peek.length()>0,"Expected primary public key");}
            else{check(((header>>2)&15)==6&&(header&3)!=3,"Expected bounded primary key");peek.number(1<<(header&3));}
            // V5 is an explicit compatibility parser; its algorithms and KDF
            // are checked separately from the default RFC 9580/9980 v6 path.
            int packetVersion=peek.one();
            if(packetVersion==4||packetVersion==5){
                v6=null;legacy=new LegacyOpenPgp(encoded,packetVersion);primary=legacy.primary.getPublicKeyPacket().getEncodedContents();
                subkey=legacy.recipient==null?primary:legacy.recipient.getPublicKeyPacket().getEncodedContents();
                signing=null;encryption=null;email=legacy.emails.get(0);mode=0;return;
            }
            legacy=null;peek.number(4);int primaryAlgorithm=peek.one();
            if(primaryAlgorithm==30||primaryAlgorithm==31){
                v6=new LegacyOpenPgp(encoded,6);primary=v6.primary.getPublicKeyPacket().getEncodedContents();
                subkey=v6.recipient==null?primary:v6.recipient.getPublicKeyPacket().getEncodedContents();
                signing=parseKey(v6.signers.values().stream().max(Comparator.comparingInt((org.bouncycastle.openpgp.PGPPublicKey k)->(k.getAlgorithm()==30||k.getAlgorithm()==31)?1:0).thenComparing(org.bouncycastle.openpgp.PGPPublicKey::getCreationTime)).orElse(v6.primary).getPublicKeyPacket().getEncodedContents(),true);encryption=v6.recipient==null?null:parseKey(subkey,false);email=v6.emails.get(0);mode=v6.recipient==null?0:2;return;
            }
            v6=null;List<Packet> p=packets(encoded);check(p.stream().map(Packet::tag).toList().equals(List.of(6,2,13,2,14,2)),"Expected one v6 primary, direct signature, certified email and bound encryption subkey; unsupported/revoked keys are rejected");
            primary=p.get(0).body;subkey=p.get(4).body;signing=parseKey(primary,true);encryption=parseKey(subkey,false);check((signing.pq==null)==(encryption.pq==null)&&modern(signing)==modern(encryption),"Mixed OpenPGP key profiles");
            String uid=new String(p.get(2).body,StandardCharsets.UTF_8);int l=uid.lastIndexOf('<');email=l>=0&&uid.endsWith(">")?uid.substring(l+1,uid.length()-1):uid;validateEmail(email);
            Checked direct=verify(p.get(1).body,keyHash(primary),31,primary);
            verify(p.get(3).body,cat(keyHash(primary),b(0xb4),n(p.get(2).body.length,4),p.get(2).body),19,primary);
            Checked bind=verify(p.get(5).body,cat(keyHash(primary),keyHash(subkey)),24,primary);
            check((flag(direct,27)&3)==3&&(flag(bind,27)&12)!=0,"OpenPGP key flags reject use");
            expiration(primary,direct);expiration(subkey,bind);
            byte[] pref=direct.subs.getOrDefault(39,new byte[0]);check(pref.length%2==0,"Invalid cipher preferences");int mode=0;
            for(int i=0;i<pref.length;i+=2)if(pref[i]==9&&(pref[i+1]==2||pref[i+1]==3))mode=Math.max(mode,pref[i+1]);this.mode=mode;
        }
        byte[] signingBody()throws Exception{return v6==null?primary:v6.signers.values().stream().max(Comparator.comparingInt((org.bouncycastle.openpgp.PGPPublicKey k)->(k.getAlgorithm()==30||k.getAlgorithm()==31)?1:0).thenComparing(org.bouncycastle.openpgp.PGPPublicKey::getCreationTime)).orElse(v6.primary).getPublicKeyPacket().getEncodedContents();}
        byte[] classicalBody(boolean signing)throws Exception{
            if(v6==null)return null;var key=v6.boundKeys.values().stream().filter(k->k.getAlgorithm()==(signing?27:25)&&(signing?v6.signers.containsKey(k.getKeyID()):(v6.bindings.get(k.getKeyID()).getHashedSubPackets().getKeyFlags()&12)!=0)).max(Comparator.comparing(org.bouncycastle.openpgp.PGPPublicKey::getCreationTime));return key.isEmpty()?null:key.get().getPublicKeyPacket().getEncodedContents();
        }
        PublicKey classicalKey(boolean signing)throws Exception{byte[] key=classicalBody(signing);check(key!=null&&key.length==42,"Missing certified classical compatibility key");return curve25519(slice(key,10,42),signing);}
        boolean separated()throws Exception{return v6!=null&&!Arrays.equals(primary,signingBody());}
        public int version(){return primary[0]&255;}
        public String signingAlgorithms(){return v6!=null?v6.signingAlgorithms():legacy!=null?legacy.signingAlgorithms():signing.pq==null?"ECDSA P-384":modern(signing)?"ML-DSA-65 + Ed25519":"ML-DSA-65 + ECDSA P-384 (experimental)";}
        public String encryptionAlgorithm(){return v6!=null?v6.encryptionAlgorithm():legacy!=null?legacy.encryptionAlgorithm():encryption.pq==null?"ECDH P-384":modern(encryption)?"ML-KEM-768 + X25519":"ML-KEM-768 + ECDH P-384 (experimental)";}
        public boolean quantumEncryption(){return v6!=null?v6.recipient!=null&&(v6.recipient.getAlgorithm()==35||v6.recipient.getAlgorithm()==36):legacy==null?encryption.pq!=null:legacy.recipient!=null&&(legacy.recipient.getAlgorithm()==35||legacy.version==5&&legacy.recipient.getAlgorithm()==8);}
        public boolean canEncrypt(){try{if(v6!=null){var current=new LegacyOpenPgp(encoded,6);return current.recipient!=null;}if(legacy!=null){var current=new LegacyOpenPgp(encoded,version());return current.recipient!=null&&current.cipher!=0;}new PublicIdentity(encoded);return mode!=0;}catch(Exception e){return false;}}
        public String encryptionDescription(){
            if(v6!=null)return "v6 "+v6.encryptionAlgorithm();
            if(legacy!=null){var k=legacy.recipient;if(k==null)return "No usable encryption subkey";return "v"+version()+" "+(quantumEncryption()?"hybrid ":"classical ")+legacy.encryptionAlgorithm()+(quantumEncryption()?"":" (not PQ)");}
            return encryption.pq==null?"v6 ECDH P-384 (not PQ)":modern(encryption)?"v6 ML-KEM-768 + X25519":"v6 ML-KEM-768 + P-384 (experimental)";
        }
        @Override public String toString(){try{return encryptionDescription()+" · "+fingerprint();}catch(Exception e){return encryptionDescription();}}
        public byte[] export(){return armor(encoded,"PUBLIC KEY BLOCK");}
        public String fingerprint()throws Exception{return hex(OpenPgp.fingerprint(primary));}
        public java.util.List<String> certifiedEmails(){return (v6!=null?v6.emails:legacy==null?java.util.List.of(email):legacy.emails).stream().map(v->v.toLowerCase(Locale.ROOT)).distinct().toList();}
        public boolean matchesEmail(String address){return v6!=null?v6.matches(address):legacy==null?email.equalsIgnoreCase(address):legacy.matches(address);}
        public String profile(){return legacy==null?OpenPgp.profile(signing):"OpenPGP v"+version()+" classical signing — not post-quantum";}
        public String description()throws Exception{return email+" · "+profile()+"\nVersion: v"+version()+"\nSigning: "+signingAlgorithms()+"\nEncryption: "+encryptionAlgorithm()+"\nFingerprint: "+fingerprint()+"\nSelf-signatures verified. Trust is not established; confirm the fingerprint independently.";}
        static int flag(Checked c,int id){byte[] v=c.subs.get(id);return v==null||v.length==0?0:v[0]&255;}
        static void expiration(byte[] key,Checked c)throws Exception{if(c.subs.containsKey(9)){byte[] v=c.subs.get(9);check(v.length==4,"Invalid expiry");long seconds=new Reader(v).number(4),created=new Reader(slice(key,1,5)).number(4);check(seconds==0||created+seconds>=now(),"Expired key");}}
    }
    static void validateEmail(String s)throws Exception{check(s.length()<=254&&s.matches("[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}"),"Enter a plain email address");}
    static String email(Identity id)throws Exception{for(var san:id.signingCert().getSubjectAlternativeNames())if(Integer.valueOf(1).equals(san.get(0)))return(String)san.get(1);throw new GeneralSecurityException("Missing email SAN");}
    public static PublicIdentity create(Identity id,ExternalMu.Backend backend)throws Exception {
        return createWithKeys(id,backend,identityKeys(id,true),identityKeys(id,false));
    }
    public static PublicIdentity createRfc9980(Identity id,ExternalMu.Backend backend,PublicKey ed,PublicKey x)throws Exception {
        check(Identity.HYBRID_65_P384_SIGN.equals(id.signatureAlgorithm()),"RFC 9980 requires Level 3 ML-DSA-65 / ML-KEM-768");
        check(SubjectPublicKeyInfo.getInstance(ed.getEncoded()).getAlgorithm().getAlgorithm().getId().equals("1.3.101.112")&&SubjectPublicKeyInfo.getInstance(x.getEncoded()).getAlgorithm().getAlgorithm().getId().equals("1.3.101.110"),"Expected Ed25519 in 84 and X25519 in 85");
        return createWithKeys(id,backend,new Keys(identityKeys(id,true).pq,ed),new Keys(identityKeys(id,false).pq,x));
    }
    static PublicIdentity createWithKeys(Identity id,ExternalMu.Backend backend,Keys signKeys,Keys encKeys)throws Exception {
        check(supported(id),"OpenPGP supports Level 3 hybrid or Level 5 classical P-384");id.signingCert().checkValidity();id.encryptionCert().checkValidity();
        ExternalMu.Backend op=backend==null?null:backend.newOperation();
        try {
            Signer sign=signer(id,op,signKeys);byte[] primary=keyBody(signKeys,true,now()),subkey=keyBody(encKeys,false,now()),fp=fingerprint(primary),uid=bytes(email(id));
            byte[] prefs=cat(sub(27,b(3)),sub(11,b(9)),sub(21,b(9)),sub(22,modern(signKeys)?b(2,1,0):b(0)),sub(30,b(8)),sub(39,b(9,3,9,2)));
            Request direct=request(keyHash(primary),31,fp,prefs,primary[5]&255),cert=request(cat(keyHash(primary),b(0xb4),n(uid.length,4),uid),19,fp,b(),primary[5]&255),bind=request(cat(keyHash(primary),keyHash(subkey)),24,fp,sub(27,b(12)),primary[5]&255);
            return new PublicIdentity(cat(frame(6,primary),frame(2,direct.finish(sign.sign(direct.digest))),frame(13,uid),frame(2,cert.finish(sign.sign(cert.digest))),frame(14,subkey),frame(2,bind.finish(sign.sign(bind.digest)))));
        }finally{if(op!=null)op.clearSecrets();}
    }
    static PublicIdentity createSeparated(Identity id,PublicIdentity previous,Keys certification,ExternalMu.Backend certBackend,ExternalMu.Backend messageBackend,PublicKey classicalEd,PublicKey classicalX)throws Exception {
        match(previous,id);check(rfc9980(previous),"Migrate an RFC 9980 Level 3 identity first");
        check(modern(certification)&&!Arrays.equals(raw(certification.pq),raw(previous.signing.pq))&&!Arrays.equals(raw(certification.ec),raw(previous.signing.ec)),"Certification keys must be distinct");
        return createSeparatedKeys(id,previous.signing,previous.signingBody(),previous.subkey,previous.certifiedEmails(),certification,certBackend,messageBackend,classicalEd,classicalX);
    }
    static PublicIdentity createInitialSeparated(Identity id,Map<String,PublicKey> keys,ExternalMu.Backend certBackend,ExternalMu.Backend messageBackend)throws Exception {
        check(Identity.HYBRID_65_P384_SIGN.equals(id.signatureAlgorithm()),"Full OpenPGP setup requires a Level 3 hybrid identity");
        Keys signing=new Keys(identityKeys(id,true).pq,keys.get("84")),encryption=new Keys(identityKeys(id,false).pq,keys.get("85")),certification=new Keys(keys.get("86"),keys.get("87"));
        check(modern(signing)&&modern(certification),"Missing Level 3 signing/certification keys");
        check(!Arrays.equals(raw(signing.pq),raw(certification.pq))&&!Arrays.equals(raw(signing.ec),raw(certification.ec))&&!Arrays.equals(raw(keys.get("88")),raw(signing.ec))&&!Arrays.equals(raw(keys.get("88")),raw(certification.ec))&&!Arrays.equals(raw(keys.get("89")),raw(encryption.ec)),"OpenPGP key roles must use distinct keys");
        return createSeparatedKeys(id,signing,keyBody(signing,true,now()),keyBody(encryption,false,now()),CertificateBundle.emails(id.signingCert()),certification,certBackend,messageBackend,keys.get("88"),keys.get("89"));
    }
    private static PublicIdentity createSeparatedKeys(Identity id,Keys signingKeys,byte[] signingBody,byte[] encryptionBody,List<String> emails,Keys certification,ExternalMu.Backend certBackend,ExternalMu.Backend messageBackend,PublicKey classicalEd,PublicKey classicalX)throws Exception {
        var certOp=certBackend.newOperation();var signOp=messageBackend.newOperation();
        try {
            Signer certify=signer(id,certOp,certification),sign=signer(id,signOp,signingKeys);
            byte[] primary=keyBody(certification,true,now()),signing=signingBody,encryption=encryptionBody,fp=fingerprint(primary);
            var out=new Buffer();out.put(frame(6,primary));
            byte[] prefs=cat(sub(27,b(1)),sub(11,b(9)),sub(21,b(9)),sub(22,b(2,1,0)),sub(30,b(8)),sub(39,b(9,3,9,2)));
            Request direct=request(keyHash(primary),31,fp,prefs,30);out.put(frame(2,direct.finish(certify.sign(direct.digest))));
            for(String email:emails){byte[] uid=bytes(email);Request cert=request(cat(keyHash(primary),b(0xb4),n(uid.length,4),uid),19,fp,b(),30);out.put(frame(13,uid));out.put(frame(2,cert.finish(certify.sign(cert.digest))));}
            byte[] pair=cat(keyHash(primary),keyHash(signing));Request cross=request(pair,25,fingerprint(signing),b(),30);byte[] embedded=cross.finish(sign.sign(cross.digest));
            Request binding=request(pair,24,fp,cat(sub(27,b(2)),sub(32,embedded)),30);out.put(frame(14,signing));out.put(frame(2,binding.finish(certify.sign(binding.digest))));
            Request enc=request(cat(keyHash(primary),keyHash(encryption)),24,fp,sub(27,b(12)),30);out.put(frame(14,encryption));out.put(frame(2,enc.finish(certify.sign(enc.digest))));
            byte[] edBody=cat(b(6),n(now(),4),b(27),n(32,4),raw(classicalEd)),xBody=cat(b(6),n(now(),4),b(25),n(32,4),raw(classicalX));
            Request edCross=request(cat(keyHash(primary),keyHash(edBody)),25,fingerprint(edBody),b(),27);byte[] edProof=edCross.finish(signOp.signCompatibilityEd25519(classicalEd,edCross.digest));
            Request edBind=request(cat(keyHash(primary),keyHash(edBody)),24,fp,cat(sub(27,b(2)),sub(32,edProof)),30);out.put(frame(14,edBody));out.put(frame(2,edBind.finish(certify.sign(edBind.digest))));
            Request xBind=request(cat(keyHash(primary),keyHash(xBody)),24,fp,sub(27,b(12)),30);out.put(frame(14,xBody));out.put(frame(2,xBind.finish(certify.sign(xBind.digest))));
            var result=new PublicIdentity(out.toByteArray());match(result,id);check(result.separated(),"Separate signing subkey not validated");return result;
        }finally{certOp.clearSecrets();signOp.clearSecrets();}
    }
    static void match(PublicIdentity pgp,Identity id)throws Exception{
        if(id.softwareOpenPgp()!=null){id.softwareOpenPgp().match(pgp);return;}
        if(id.level3Polyfill()){check(pgp.legacy==null&&pgp.separated()&&algorithm(pgp.signing,true)==30&&algorithm(pgp.encryption,false)==35&&pgp.fingerprint().equalsIgnoreCase(Identity.polyfillFingerprint(id.signingCert()))&&pgp.matchesEmail(email(id)),"Polyfill certificate identity mismatch");Level5Companion.same(pgp.signing.pq(),id.signingCert().getPublicKey());Level5Companion.same(pgp.encryption.pq(),id.encryptionCert().getPublicKey());return;}
        check(pgp.legacy==null,"A v4 certificate is for recipients and incoming verification only");check(supported(id),"Select a Level 3 or Level 5 hybrid identity");Keys s=identityKeys(id,true),e=identityKeys(id,false);
        if(rfc9980(pgp)){s=keys(id.signingCert().getPublicKey());e=keys(id.encryptionCert().getPublicKey());check((Identity.HYBRID_65_P384_SIGN.equals(id.signatureAlgorithm())||Identity.HYBRID_87_SIGN.equals(id.signatureAlgorithm()))&&pgp.email.equals(email(id))&&Arrays.equals(raw(s.pq),raw(pgp.signing.pq))&&Arrays.equals(raw(e.pq),raw(pgp.encryption.pq)),"RFC 9980 identity does not match selected PQ keys/email");return;}
        check(pgp.email.equals(email(id))&&Arrays.equals(s.pq==null?null:raw(s.pq),pgp.signing.pq==null?null:raw(pgp.signing.pq))&&Arrays.equals(raw(s.ec),raw(pgp.signing.ec))&&Arrays.equals(e.pq==null?null:raw(e.pq),pgp.encryption.pq==null?null:raw(pgp.encryption.pq))&&Arrays.equals(raw(e.ec),raw(pgp.encryption.ec)),"OpenPGP identity does not match selected keys/email");
    }
    static Path ownPath(Path root,Identity id)throws Exception{check(supported(id),"OpenPGP supports Level 3 hybrid or Level 5 classical P-384");return root.resolve("openpgp").resolve(hex(hash("SHA-256",cat(id.signingCert().getEncoded(),id.encryptionCert().getEncoded())))+".asc");}
    public static PublicIdentity loadOwn(Path root,Identity id)throws Exception{
        if(id.level3Polyfill())return Level3PolyfillDesktop.own(root,id);
        if(id.softwareOpenPgp()!=null)return id.softwareOpenPgp().own();Path p=ownPath(root,id);PublicIdentity own;
        // A fresh on-key companion restore has its own validated public cache;
        // it must not depend on an unrelated older NIST .asc file being present.
        if(CompanionDesktop.selected(root,id))own=CompanionDesktop.own(root,id);
        else{check(Files.isRegularFile(p),"Create or import your OpenPGP public identity first");check(Files.size(p)<=128*1024,"Public identity too large");own=new PublicIdentity(Files.readAllBytes(p));}
        match(own,id);Path compat=p.resolveSibling(p.getFileName()+".v4");if(Files.exists(compat)){own.compatibility=new PublicIdentity(Files.readAllBytes(compat));checkCompatibility(own,own.compatibility);}return own;
    }
    public static PublicIdentity saveOwn(Path root,Identity id,byte[] input)throws Exception{PublicIdentity own=new PublicIdentity(input);match(own,id);Path p=ownPath(root,id);if(Files.exists(p)){var previous=loadOwn(root,id);check(Arrays.equals(fingerprint(previous.primary),fingerprint(own.signingBody()))&&Arrays.equals(fingerprint(previous.subkey),fingerprint(own.subkey)),"A different OpenPGP identity is already saved");}Files.createDirectories(p.getParent());Path tmp=Files.createTempFile(p.getParent(),"pgp-",".tmp");try{Files.write(tmp,own.export());Files.move(tmp,p,StandardCopyOption.REPLACE_EXISTING);}finally{Files.deleteIfExists(tmp);}return own;}
    public static PublicIdentity createOwn(Path root,Identity id,ExternalMu.Backend backend)throws Exception{if(id.level3Polyfill())return loadOwn(root,id);if(id.softwareOpenPgp()!=null)return id.softwareOpenPgp().own();Path p=ownPath(root,id);return Files.exists(p)?loadOwn(root,id):saveOwn(root,id,create(id,backend).export());}
    public static PublicIdentity replaceOwn(Path root,Identity id,PublicIdentity own)throws Exception{
        match(own,id);Path p=ownPath(root,id);Files.createDirectories(p.getParent());
        if(Files.exists(p)){var previous=loadOwn(root,id);Path backup=p.resolveSibling(p.getFileName()+"."+previous.fingerprint()+".backup");if(!Files.exists(backup))Files.copy(p,backup);}
        Path tmp=Files.createTempFile(p.getParent(),"pgp-",".tmp");try{Files.write(tmp,own.export());Files.move(tmp,p,StandardCopyOption.REPLACE_EXISTING);}finally{Files.deleteIfExists(tmp);}return own;
    }
    // RFC 9980 combines both shared secrets with the ephemeral and recipient
    // public keys plus an algorithm-specific domain separator. Component order
    // is protocol data; it is independent of the slots chosen by the manifest.
    static byte[] combine(byte[] pq,byte[] ec,byte[] point,byte[] recipient)throws Exception{boolean strong=point.length==56,x=point.length==32||strong;check(pq.length==32&&ec.length==(x?point.length:48)&&point.length==(x?(strong?56:32):97)&&recipient.length==point.length,"Invalid KEM components");check(!Arrays.equals(ec,new byte[ec.length]),"Invalid zero ECDH shared secret");return hash("SHA3-256",cat(pq,ec,point,recipient,b(x?(strong?36:35):37),bytes("OpenPGPCompositeKDFv1"),b(21)));}
    record Encapsulation(byte[] ciphertext,byte[] kek){}
    static Encapsulation encapsulate(PublicIdentity recipient)throws Exception{
        if(recipient.encryption.pq==null){KeyPairGenerator g=KeyPairGenerator.getInstance("EC","BC");g.initialize(new ECGenParameterSpec("secp384r1"),RANDOM);KeyPair pair=g.generateKeyPair();byte[] secret=derive(pair.getPrivate(),recipient.encryption.ec);try{return new Encapsulation(raw(pair.getPublic()),ecKdf(secret,recipient.subkey));}finally{wipe(secret);}}
        var pq=new MLKEMGenerator(RANDOM).generateEncapsulated((MLKEMPublicKeyParameters)PublicKeyFactory.createKey(recipient.encryption.pq.getEncoded()));
        KeyPairGenerator gen=KeyPairGenerator.getInstance(modern(recipient.encryption)?"X25519":"EC","BC");if(!modern(recipient.encryption))gen.initialize(new ECGenParameterSpec("secp384r1"),RANDOM);KeyPair ephemeral=gen.generateKeyPair();byte[] ec=derive(ephemeral.getPrivate(),recipient.encryption.ec),share=pq.getSecret(),point=raw(ephemeral.getPublic());
        try{return new Encapsulation(cat(point,pq.getEncapsulation()),combine(share,ec,point,raw(recipient.encryption.ec)));}finally{wipe(ec);wipe(share);pq.destroy();}
    }
    static byte[] derive(PrivateKey key,PublicKey peer)throws Exception{KeyAgreement ka=KeyAgreement.getInstance(peer instanceof java.security.interfaces.ECPublicKey?"ECDH":raw(peer).length==56?"X448":"X25519","BC");ka.init(key);ka.doPhase(peer,true);return ka.generateSecret();}
    static byte[] ecKdf(byte[] secret,byte[] subkey)throws Exception{check(secret.length==48,"Invalid P-384 shared secret");return slice(hash("SHA-384",cat(n(1,4),secret,P384_OID,b(18,3,1,9,8),bytes("Anonymous Sender    "),fingerprint(subkey))),0,24);}
    static byte[] recover(byte[] ct,Identity id,ExternalKem.Backend backend,PublicIdentity own)throws Exception {
        if(classical(id)&&!rfc9980(own)){check(ct.length==97,"Invalid P-384 ciphertext");PublicKey peer=ec(ct);ExternalKem.Backend op=backend==null?null:backend.newOperation();byte[] secret=null;try{secret=op!=null?op.derive(identityKeys(id,false).ec,peer):derive(((CompositePrivateKey)id.encryptionKey()).getPrivateKeys().get(1),peer);return ecKdf(secret,own.subkey);}finally{wipe(secret);if(op!=null)op.clearSecrets();}}
        boolean x=rfc9980(own),strong=algorithm(own.encryption,false)==36;int pointSize=strong?56:x?32:97;check(supported(id)&&ct.length==(strong?1568:1088)+pointSize,"Invalid OpenPGP recipient/ciphertext");Keys pub=own.encryption;byte[] point=slice(ct,0,pointSize);PublicKey peer=strong?Level5Companion.decodePublic(new SubjectPublicKeyInfo(new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.101.111")),point).getEncoded()):x?curve25519(point,false):ec(point);byte[] pq=null,ec=null;ExternalKem.Backend op=backend==null?null:backend.newOperation();
        try{if(op!=null){pq=op.decapsulate(pub.pq,slice(ct,pointSize,ct.length));ec=op.derive(pub.ec,peer);}else{check(!x,"RFC 9980 extra keys require the YubiKey backend");check(id.encryptionKey() instanceof CompositePrivateKey,"Unlock software identity or select token backend");var priv=((CompositePrivateKey)id.encryptionKey()).getPrivateKeys();pq=new MLKEMExtractor((MLKEMPrivateKeyParameters)PrivateKeyFactory.createKey(priv.get(0).getEncoded())).extractSecret(slice(ct,pointSize,ct.length));ec=derive(priv.get(1),peer);}return combine(pq,ec,point,raw(pub.ec));}finally{wipe(pq);wipe(ec);if(op!=null)op.clearSecrets();}
    }
    static byte[] wrap(boolean encrypt,byte[] key,byte[] input)throws Exception{Cipher c=Cipher.getInstance("AESWrap","BC");c.init(encrypt?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"));return c.doFinal(input);}
    static byte[] aead(boolean encrypt,int mode,byte[] key,byte[] nonce,byte[] aad,byte[] input)throws Exception{check((mode==2||mode==3)&&key.length==32&&nonce.length==(mode==2?15:12),"Invalid AEAD parameters");Cipher c=Cipher.getInstance(mode==2?"AES/OCB/NoPadding":"AES/GCM/NoPadding","BC");c.init(encrypt?Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE,new SecretKeySpec(key,"AES"),new AEADParameterSpec(nonce,128,aad));return c.doFinal(input);}
    static byte[] kdf(byte[] session,byte[] salt,byte[] info,int size){HKDFBytesGenerator k=new HKDFBytesGenerator(new SHA256Digest());k.init(new HKDFParameters(session,salt,info));byte[] out=new byte[size];k.generateBytes(out,0,size);return out;}
    static byte[] seipd(byte[] plain,byte[] session,int mode)throws Exception {
        byte[] salt=random(32),info=b(0xd2,2,9,mode,10),derived=kdf(session,salt,info,mode==2?39:36),key=slice(derived,0,32),iv=slice(derived,32,derived.length);var out=new Buffer();out.put(cat(b(2,9,mode,10),salt));int at=0,index=0;
        try{do{int end=Math.min(at+65536,plain.length);out.put(aead(true,mode,key,cat(iv,n(index++,8)),info,slice(plain,at,end)));at=end;}while(at<plain.length);out.put(aead(true,mode,key,cat(iv,n(index,8)),cat(info,n(plain.length,8)),b()));return frame(18,out.toByteArray());}finally{wipe(derived);wipe(key);}
    }
    static byte[] decryptSeipd(byte[] body,byte[] session)throws Exception {
        Reader r=new Reader(body);check(r.one()==2&&r.one()==9,"Expected v2 SEIPD AES-256");int mode=r.one(),chunk=r.one();check((mode==2||mode==3)&&chunk<=16,"Unsupported AEAD parameters");byte[] salt=r.take(32),info=b(0xd2,2,9,mode,chunk),derived=kdf(session,salt,info,mode==2?39:36),key=slice(derived,0,32),iv=slice(derived,32,derived.length);var out=new Buffer();int index=0,size=1<<(chunk+6);check(r.left()>=32,"Truncated ciphertext");
        try{while(r.left()>16){int len=Math.min(size+16,r.left()-16);check(len>=16,"Truncated chunk");out.put(aead(false,mode,key,cat(iv,n(index++,8)),info,r.take(len)));}aead(false,mode,key,cat(iv,n(index,8)),cat(info,n(out.size(),8)),r.take(16));return out.toByteArray();}finally{wipe(derived);wipe(key);}
    }
    static byte[] encrypt(byte[] signed,PublicIdentity recipient)throws Exception {
        if(recipient.v6!=null)return new LegacyOpenPgp(recipient.encoded,6).encrypt(signed);
        if(recipient.legacy!=null)return new LegacyOpenPgp(recipient.encoded,recipient.version()).encrypt(signed);
        check(recipient.mode!=0,"Recipient must advertise AES-256 OCB or GCM");byte[] session=random(32);Encapsulation kem=encapsulate(recipient);
        try{byte[] wrapped=wrap(true,kem.kek,recipient.encryption.pq==null?paddedSession(session):session),pkesk=cat(b(6,33,6),fingerprint(recipient.subkey),b(algorithm(recipient.encryption,false)),recipient.encryption.pq==null?mpi(kem.ciphertext):kem.ciphertext,b(wrapped.length),wrapped);return cat(frame(1,pkesk),seipd(signed,session,recipient.mode));}finally{wipe(session);wipe(kem.kek);}
    }
    static byte[] paddedSession(byte[] session){int sum=0;for(byte v:session)sum+=v&255;return cat(session,n(sum&65535,2),b(6,6,6,6,6,6));}
    record Envelope(byte[] ct,byte[] wrapped,byte[] encrypted) {
        byte[] open(byte[] kek)throws Exception{byte[] session=wrap(false,kek,wrapped);try{if(ct.length==97){check(session.length==40&&Arrays.equals(session,paddedSession(slice(session,0,32))),"Invalid ECDH session checksum/padding");byte[] key=slice(session,0,32);wipe(session);session=key;}check(session.length==32,"Invalid session key");return decryptSeipd(encrypted,session);}finally{wipe(session);}}
    }
    static Envelope envelope(byte[] data,PublicIdentity own)throws Exception {
        List<Packet> p=packets(data);check(p.stream().map(Packet::tag).toList().equals(List.of(1,18)),"Expected one recipient and v2 encrypted payload");Reader r=new Reader(p.get(0).body);check(Arrays.equals(r.take(3),b(6,33,6))&&Arrays.equals(r.take(32),fingerprint(own.subkey))&&r.one()==algorithm(own.encryption,false),"OpenPGP recipient does not match selected identity");byte[] ct=own.encryption.pq==null?mpi(r,776):r.take(algorithm(own.encryption,false)==36?1624:rfc9980(own)?1120:1185);if(algorithm(own.encryption,false)==36){check(ct.length==1624,"Invalid Level 5 ciphertext");}else if(rfc9980(own))curve25519(slice(ct,0,32),false);else ec(slice(ct,0,97));int wrapped=own.encryption.pq==null?48:40;check(r.one()==wrapped&&r.left()==wrapped,"Invalid wrapped session key");byte[] encrypted=p.get(1).body;check(encrypted.length>=68&&encrypted[0]==2&&encrypted[1]==9&&(encrypted[2]==2||encrypted[2]==3)&&(encrypted[3]&255)<=16,"Unsupported encrypted payload");return new Envelope(ct,r.take(wrapped),encrypted);
    }
    static byte[] signed(byte[] plain,PublicIdentity own,Signer signer)throws Exception {
        Request req=request(plain,0,fingerprint(own.signingBody()),b(),own.signingBody()[5]&255);byte[] sig=signer.sign(req.digest);
        return cat(frame(4,cat(b(6,0,req.header[3]&255,own.signingBody()[5]&255,req.salt.length),req.salt,fingerprint(own.signingBody()),b(1))),frame(11,cat(b(98,0),n(0,4),plain)),frame(2,req.finish(sig)));
    }
    static byte[] openSigned(byte[] data,PublicIdentity signer)throws Exception {
        if(signer.v6!=null)return new LegacyOpenPgp(signer.encoded,6).openSigned(data);
        if(signer.legacy!=null)return new LegacyOpenPgp(signer.encoded,signer.version()).openSigned(data);
        List<Packet> p=packets(data);check(p.stream().map(Packet::tag).toList().equals(List.of(4,11,2)),"Unsupported signed message; compression is not supported");Reader r=new Reader(p.get(1).body);check(List.of(98,116,117).contains(r.one()),"Invalid literal packet");r.take(r.one()+4);byte[] plain=r.take(r.left());Checked sig=verify(p.get(2).body,plain,0,signer.primary);check(Arrays.equals(p.get(0).body,cat(b(6,0,sig.hash,signer.primary[5]&255,sig.salt.length),sig.salt,fingerprint(signer.primary),b(1))),"One-pass signature mismatch");return plain;
    }
    record Mime(Map<String,String> headers,byte[] body){}
    static Mime mime(byte[] input)throws Exception {
        check(input.length<=LIMIT,"Message exceeds 20 MiB");String s=new String(input,StandardCharsets.UTF_8);int split=s.indexOf("\r\n\r\n");check(split>=0&&split<65536,"Invalid MIME headers");Map<String,String> h=new HashMap<>();
        String unfolded=s.substring(0,split).replaceAll("\r\n[ \t]+"," ");
        for(String line:unfolded.split("\r\n")){int colon=line.indexOf(':');check(colon>0,"Invalid MIME header");String key=line.substring(0,colon).toLowerCase(Locale.ROOT);check(!h.containsKey(key)||!List.of("content-type","content-transfer-encoding","from").contains(key),"Duplicate MIME header");h.put(key,line.substring(colon+1).trim());}return new Mime(h,bytes(s.substring(split+4)));
    }
    static byte[] decoded(Mime m)throws Exception{String encoding=m.headers.getOrDefault("content-transfer-encoding","7bit").toLowerCase(Locale.ROOT);if(encoding.equals("quoted-printable"))return LegacyOpenPgp.bounded(jakarta.mail.internet.MimeUtility.decode(new ByteArrayInputStream(m.body),encoding));if(encoding.equals("base64"))return Base64.getDecoder().decode(new String(m.body,StandardCharsets.US_ASCII).replaceAll("\\s",""));check(List.of("7bit","8bit","binary").contains(encoding),"Unsupported MIME transfer encoding");return m.body;}
    /** Recover only the exact two-leaf MIME rewrite observed on Gmail delivery.
     * The outer envelope is untrusted: never merge its text or extra attachments
     * into verified content. Cryptographic integrity/signature checks still run
     * through open() before any decrypted body is returned to the caller.
     */
    static byte[] transportMime(byte[] message)throws Exception {
        Mime root=mime(message);
        if(!new ContentType(root.headers.getOrDefault("content-type","text/plain")).getBaseType().equalsIgnoreCase("multipart/mixed"))return message;
        MimeMessage parsed=MailEngine.parse(message);
        Object content=parsed.getContent();
        if(!(content instanceof jakarta.mail.Multipart parts)||parts.getCount()!=2)return message;
        jakarta.mail.BodyPart control=null,cipher=null;
        for(int i=0;i<2;i++){
            var part=parts.getBodyPart(i);
            // Duplicate structural headers and nested MIME are ambiguous.
            for(String header:List.of("Content-Type","Content-Transfer-Encoding")){
                String[] values=part.getHeader(header);check(values==null||values.length==1,"Ambiguous rewritten PGP/MIME headers");
            }
            if(part.isMimeType("application/pgp-encrypted")&&control==null)control=part;
            else if((part.isMimeType("text/plain")||part.isMimeType("application/octet-stream"))&&cipher==null)cipher=part;
            else return message;
        }
        if(control==null||cipher==null)return message;
        byte[] version;try(var in=control.getInputStream()){version=in.readNBytes(65);}
        check(version.length<=64&&new String(version,StandardCharsets.US_ASCII).trim().equals("Version: 1"),"Invalid rewritten PGP/MIME version");
        byte[] encoded;try(var in=cipher.getInputStream()){encoded=in.readNBytes(LIMIT+1);}
        check(encoded.length<=LIMIT,"Rewritten ciphertext exceeds limit");
        for(byte value:encoded)check((value&255)<128,"Non-ASCII rewritten ciphertext");
        String armor=new String(encoded,StandardCharsets.US_ASCII).strip();
        String begin="-----BEGIN PGP MESSAGE-----",end="-----END PGP MESSAGE-----";
        check((armor.startsWith(begin+"\r\n")||armor.startsWith(begin+"\n"))&&armor.endsWith(end)&&armor.indexOf(begin)==armor.lastIndexOf(begin)&&armor.indexOf(end)==armor.lastIndexOf(end),"Ambiguous rewritten ciphertext");
        String boundary="pqmail-recovered-"+UUID.randomUUID();
        StringBuilder headers=new StringBuilder();
        for(var h:root.headers.entrySet())if(!Set.of("content-type","content-transfer-encoding","mime-version").contains(h.getKey()))headers.append(h.getKey()).append(": ").append(h.getValue()).append("\r\n");
        headers.append("MIME-Version: 1.0\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"").append(boundary).append("\"\r\n\r\n--").append(boundary).append("\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--").append(boundary).append("\r\nContent-Type: application/octet-stream\r\n\r\n");
        return cat(bytes(headers.toString()),bytes(armor),bytes("\r\n--"+boundary+"--\r\n"));
    }
    public static boolean isOpenPgp(byte[] message){try{String c=mime(transportMime(message)).headers.getOrDefault("content-type","").toLowerCase(Locale.ROOT);return c.contains("application/pgp-encrypted")||c.contains("application/pgp-signature");}catch(Exception e){return false;}}
    record Parts(Mime root,byte[] first,byte[] second,boolean encrypted){}
    static Parts parts(byte[] message)throws Exception {
        Mime root=mime(transportMime(message));String ct=root.headers.getOrDefault("content-type","");boolean encrypted=ct.toLowerCase(Locale.ROOT).contains("application/pgp-encrypted");check(ct.toLowerCase(Locale.ROOT).startsWith(encrypted?"multipart/encrypted;":"multipart/signed;"),"Invalid PGP/MIME type");
        String boundary=null;for(String parameter:ct.split(";")){String p=parameter.trim();if(p.toLowerCase(Locale.ROOT).startsWith("boundary=")){check(boundary==null,"Duplicate MIME boundary");boundary=p.substring(9);if(boundary.startsWith("\"")&&boundary.endsWith("\""))boundary=boundary.substring(1,boundary.length()-1);}}
        check(boundary!=null&&boundary.length()>0&&boundary.length()<=70,"Invalid MIME boundary");
        String[] fields=new String(root.body,StandardCharsets.UTF_8).split(java.util.regex.Pattern.quote("--"+boundary),-1);check(fields.length==4&&fields[3].startsWith("--"),"Expected two MIME parts");byte[][] bodies=new byte[2][];
        for(int i=0;i<2;i++){String s=fields[i+1];check(s.startsWith("\r\n")&&s.endsWith("\r\n"),"Invalid boundary");bodies[i]=bytes(s.substring(2,s.length()-2));}
        if(encrypted){Mime control=mime(bodies[0]);check(control.headers.getOrDefault("content-type","").equalsIgnoreCase("application/pgp-encrypted")&&new String(decoded(control),StandardCharsets.UTF_8).trim().equals("Version: 1"),"Invalid PGP/MIME version");check(mime(bodies[1]).headers.getOrDefault("content-type","").toLowerCase(Locale.ROOT).startsWith("application/octet-stream"),"Invalid encrypted MIME part");}
        else check(mime(bodies[1]).headers.getOrDefault("content-type","").toLowerCase(Locale.ROOT).startsWith("application/pgp-signature"),"Invalid signature part");
        return new Parts(root,bodies[0],bodies[1],encrypted);
    }
    static byte[] mimeWrap(byte[] first,byte[] second,boolean encrypted,String from,String to,String subject)throws Exception {
        validateEmail(from);validateEmail(to);check(subject.length()<=500&&!subject.contains("\r")&&!subject.contains("\n"),"Invalid subject");String boundary="pqmail-"+UUID.randomUUID(),type=encrypted?"encrypted":"signed",protocol=encrypted?"application/pgp-encrypted":"application/pgp-signature";
        return cat(bytes("From: "+from+"\r\nTo: "+to+"\r\nSubject: "+subject+"\r\nMIME-Version: 1.0\r\nContent-Type: multipart/"+type+"; protocol=\""+protocol+"\"; "+(encrypted?"":"micalg=pgp-sha384; ")+"boundary=\""+boundary+"\"\r\n\r\n--"+boundary+"\r\n"),first,bytes("\r\n--"+boundary+"\r\n"),second,bytes("\r\n--"+boundary+"--\r\n"));
    }
    /** v4 compatibility uses the existing RFC 9980 Ed25519 key, never an empty primary. */
    static byte[] v4KeyHash(byte[] body){return cat(b(0x99),n(body.length,2),body);}
    static byte[] v4Signature(byte[] data,int type,byte[] primary,byte[] extra,Signer signer)throws Exception {
        byte[] fp=fingerprint(primary),subs=cat(sub(2,n(now(),4)),sub(33,cat(b(4),fp)),extra);
        byte[] header=cat(b(4,type,22,10),n(subs.length,2),subs);
        byte[] digest=hash("SHA-512",cat(data,header,b(4,255),n(header.length,4))),sig=signer.sign(digest);
        check(sig.length==64,"Invalid Ed25519 signature length");
        byte[] unhashed=sub(16,slice(fp,12,20));
        return cat(header,n(unhashed.length,2),unhashed,slice(digest,0,2),mpi(slice(sig,0,32)),mpi(slice(sig,32,64)));
    }
    static PublicIdentity compatibilityCertificate(PublicIdentity own,Signer signer)throws Exception {
        check(rfc9980(own),"v4 compatibility requires an RFC 9980 identity with Ed25519 in slot 84 and X25519 in slot 85");
        // Reuse the v6 creation timestamps so primary/subkey fingerprints remain stable.
        byte[] compatBody=own.classicalBody(true);PublicKey compatEd=compatBody==null?own.signing.ec:own.classicalKey(true);
        byte[] primary=cat(b(4),slice(compatBody==null?own.signingBody():compatBody,1,5),b(22,9,0x2b,6,1,4,1,0xda,0x47,0xf,1),mpi(cat(b(0x40),raw(compatEd))));
        byte[] subkey=cat(b(4),slice(own.subkey,1,5),b(35),raw(own.encryption.ec),raw(own.encryption.pq));
        byte[] prefs=cat(sub(27,b(3)),sub(11,b(9,7)),sub(21,b(10,9,8)),sub(22,b(0)),sub(30,b(1)));
        var certifications=new Buffer();for(String email:own.certifiedEmails()){byte[] uid=bytes(email);byte[] cert=v4Signature(cat(v4KeyHash(primary),b(0xb4),n(uid.length,4),uid),19,primary,prefs,signer);certifications.put(frame(13,uid));certifications.put(frame(2,cert));}
        byte[] bind=v4Signature(cat(v4KeyHash(primary),v4KeyHash(subkey)),24,primary,sub(27,b(12)),signer);
        byte[] extra=b();if(own.classicalBody(false)!=null){byte[] x=cat(b(4),slice(own.classicalBody(false),1,5),b(18),X25519_OID,mpi(cat(b(0x40),raw(own.classicalKey(false)))),b(3,1,8,7));byte[] xb=v4Signature(cat(v4KeyHash(primary),v4KeyHash(x)),24,primary,sub(27,b(12)),signer);extra=cat(frame(14,x),frame(2,xb));}
        return new PublicIdentity(cat(frame(6,primary),certifications.toByteArray(),frame(14,subkey),frame(2,bind),extra));
    }
    static String oldCompatibilityFingerprint(PublicIdentity own)throws Exception{return hex(fingerprint(cat(b(4),slice(own.signingBody(),1,5),b(22,9,0x2b,6,1,4,1,0xda,0x47,0xf,1),mpi(cat(b(0x40),raw(own.signing.ec))))));}
    static void checkCompatibility(PublicIdentity own,PublicIdentity compat)throws Exception{
        if(Level5Compatibility.supports(own)){Level5Compatibility.checkPair(own,compat);return;}
        check(own.separated()&&compat.version()==4,"Expected migrated v6/v4 pair");byte[] primary=cat(b(4),slice(own.classicalBody(true),1,5),b(22,9,0x2b,6,1,4,1,0xda,0x47,0xf,1),mpi(cat(b(0x40),raw(own.classicalKey(true)))));
        check(Arrays.equals(primary,compat.primary)&&compat.certifiedEmails().contains(own.email.toLowerCase(Locale.ROOT))&&own.certifiedEmails().containsAll(compat.certifiedEmails()),"Compatibility primary/email mismatch");byte[] hybrid=cat(b(4),slice(own.subkey,1,5),b(35),raw(own.encryption.ec),raw(own.encryption.pq));check(Arrays.equals(compat.subkey,hybrid),"Compatibility hybrid encryption mismatch");var classical=classicalOnlyCompatibility(compat);check(classical.canEncrypt()&&Arrays.equals(classical.subkey,classicalV4Body(own)),"Compatibility classical encryption mismatch");
    }
    static PublicIdentity classicalOnlyCompatibility(PublicIdentity certificate)throws Exception{
        var ring=(org.bouncycastle.openpgp.PGPPublicKeyRing)LegacyOpenPgp.objects(certificate.encoded).nextObject();var keys=new ArrayList<org.bouncycastle.openpgp.PGPPublicKey>();for(var it=ring.getPublicKeys();it.hasNext();){var key=it.next();if(key.isMasterKey()||key.getAlgorithm()==18)keys.add(key);}return new PublicIdentity(new org.bouncycastle.openpgp.PGPPublicKeyRing(keys).getEncoded());
    }
    static PublicIdentity signingOnlyCompatibility(PublicIdentity certificate)throws Exception {
        check(certificate.version()==4,"Expected v4 compatibility certificate");var out=new Buffer();
        for(var packet:packets(certificate.encoded)){if(packet.tag==14)break;out.put(frame(packet.tag,packet.body));}
        var result=new PublicIdentity(out.toByteArray());check(result.fingerprint().equals(certificate.fingerprint())&&!result.canEncrypt(),"Invalid signing-only certificate view");return result;
    }
    static byte[] withPublicCertificate(byte[] plain,PublicIdentity certificate,PublicIdentity modern)throws Exception {
        String boundary="pqmail-key-"+UUID.randomUUID();
        return cat(bytes("Content-Type: multipart/mixed; boundary=\""+boundary+"\"\r\n\r\n--"+boundary+"\r\n"),plain,
            bytes("\r\n--"+boundary+"\r\nContent-Type: application/pgp-keys\r\nContent-Disposition: attachment; filename=\"public-key-v4.asc\"\r\n\r\n"),certificate.export(),modern.classicalBody(false)==null&&!Level5Compatibility.supports(modern)&&modern.primary[5]!=31?b():cat(bytes("\r\n--"+boundary+"\r\nContent-Type: application/pgp-keys\r\nContent-Disposition: attachment; filename=\"public-key-v4-classical.asc\"\r\n\r\n"),classicalOnlyCompatibility(certificate).export()),bytes("\r\n--"+boundary+"\r\nContent-Type: application/pgp-keys\r\nContent-Disposition: attachment; filename=\"public-key-v6.asc\"\r\n\r\n"),modern.export(),bytes("\r\n--"+boundary+"--\r\n"));
    }
    public static byte[] composeForRecipient(Identity id,PublicIdentity own,PublicIdentity selected,boolean encrypted,String from,String to,String subject,String text,ExternalMu.Backend backend)throws Exception {
        return composeForRecipient(id,own,selected,encrypted,from,to,subject,text,null,backend);
    }
    public static byte[] composeForRecipient(Identity id,PublicIdentity own,PublicIdentity selected,boolean encrypted,String from,String to,String subject,String text,String html,ExternalMu.Backend backend)throws Exception {
        if(id.softwareOpenPgp()!=null)return id.softwareOpenPgp().compose(own,selected,encrypted,from,to,subject,text,html);
        check(!encrypted||selected!=null,"Select a recipient certificate before encrypting");validateEmail(to);validateEmail(from);check(subject.length()<=500&&!subject.contains("\r")&&!subject.contains("\n"),"Invalid subject");
        if(selected==null||selected.version()!=4)return compose(id,own,encrypted?selected:null,from,to,subject,text,html,backend);
        check(!id.level3Polyfill(),"This Level 3 polyfill has no separate v4 compatibility keys; select a v6 recipient or another identity");
        match(own,id);check(selected.matchesEmail(to),"Recipient address mismatch");check(own.email.equalsIgnoreCase(from),"Sender address mismatch");
        if(classical(id))return Level5Compatibility.compose(id,own,selected,encrypted,from,to,subject,text,html,backend);
        check(rfc9980(own)&&backend!=null,"Ed25519 compatibility signing requires your RFC 9980 YubiKey identity (Ed25519 slot 84). Select that identity before sending to a v4 recipient.");
        check(text.length()<LIMIT/4,"Message too large");
        ExternalMu.Backend op=backend.newOperation();
        try {
            PublicKey compatKey=own.classicalBody(true)==null?own.signing.ec:own.classicalKey(true);
            Signer signer=digest->{byte[] sig=own.classicalBody(true)==null?op.signEd25519(compatKey,digest):op.signCompatibilityEd25519(compatKey,digest);Signature verify=Signature.getInstance("Ed25519","BC");verify.initVerify(compatKey);verify.update(digest);check(verify.verify(sig),"Invalid compatibility signature");return sig;};
            PublicIdentity compat=compatibilityCertificate(own,signer);
            byte[] plain=withPublicCertificate(MailEngine.messageBody(text,html),compat,own);
            byte[] sig=v4Signature(plain,0,compat.primary,b(),signer);compat.legacy.verify(frame(2,sig),plain);
            if(encrypted){byte[] fp=fingerprint(compat.primary),signed=cat(frame(4,cat(b(3,0,10,22),slice(fp,12,20),b(1))),frame(11,cat(b(98,0),n(0,4),plain)),frame(2,sig));
                return mimeWrap(bytes("Content-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n"),cat(bytes("Content-Type: application/octet-stream\r\n\r\n"),armor(encrypt(signed,selected),"MESSAGE")),true,from,to,subject);
            }
            return new String(mimeWrap(plain,cat(bytes("Content-Type: application/pgp-signature; name=\"signature.asc\"\r\nContent-Disposition: attachment; filename=\"signature.asc\"\r\nContent-Transfer-Encoding: 7bit\r\n\r\n"),armor(frame(2,sig),"SIGNATURE")),false,from,to,subject),StandardCharsets.UTF_8).replace("micalg=pgp-sha384;","micalg=pgp-sha512;").getBytes(StandardCharsets.UTF_8);
        }finally{op.clearSecrets();}
    }
    public static byte[] compose(Identity id,PublicIdentity own,PublicIdentity recipient,String from,String to,String subject,String text,ExternalMu.Backend backend)throws Exception {
        return compose(id,own,recipient,from,to,subject,text,null,backend);
    }
    public static byte[] compose(Identity id,PublicIdentity own,PublicIdentity recipient,String from,String to,String subject,String text,String html,ExternalMu.Backend backend)throws Exception {
        if(id.softwareOpenPgp()!=null)return id.softwareOpenPgp().compose(own,recipient,recipient!=null,from,to,subject,text,html);
        match(own,id);check(own.signing.pq!=null,"Outgoing OpenPGP signing requires a post-quantum hybrid profile");check(from.equalsIgnoreCase(own.email),"Sender address mismatch");validateEmail(to);check(subject.length()<=500&&!subject.contains("\r")&&!subject.contains("\n"),"Invalid subject");check(text.length()<LIMIT/4,"Message too large");if(recipient!=null)check(recipient.matchesEmail(to),"Recipient address mismatch");
        byte[] plain=MailEngine.messageBody(text,html);
        ExternalMu.Backend op=backend==null?null:backend.newOperation();
        try{Signer signer=signer(id,op,own.signing);if(recipient!=null)return mimeWrap(bytes("Content-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n"),cat(bytes("Content-Type: application/octet-stream\r\n\r\n"),armor(encrypt(signed(plain,own,signer),recipient),"MESSAGE")),true,from,to,subject);
            Request req=request(plain,0,fingerprint(own.signingBody()),b(),own.signingBody()[5]&255);return mimeWrap(plain,cat(bytes("Content-Type: application/pgp-signature; name=\"signature.asc\"\r\nContent-Disposition: attachment; filename=\"signature.asc\"\r\nContent-Transfer-Encoding: 7bit\r\n\r\n"),armor(frame(2,req.finish(signer.sign(req.digest))),"SIGNATURE")),false,from,to,subject);
        }finally{if(op!=null)op.clearSecrets();}
    }
    public record Opened(String text,String email,String fingerprint,boolean encrypted,boolean fromMatches,String profile,boolean postQuantum,String html) {
        public Opened(String text,String email,String fingerprint,boolean encrypted,boolean fromMatches,String profile,boolean postQuantum){this(text,email,fingerprint,encrypted,fromMatches,profile,postQuantum,null);}
        public String securityDisplay(){return (postQuantum?"":CryptoWarnings.SIGNATURE)+profile+"\nSignature valid; trust not established\nSigner: "+email+"\nFingerprint: "+fingerprint+"\nEncrypted: "+encrypted+"\nUnsigned From matches: "+fromMatches;}
        public String display(){return securityDisplay()+"\n\n"+text;}
    }
    static byte[] classicalV4Body(PublicIdentity own)throws Exception{return cat(b(4),slice(own.classicalBody(false),1,5),b(18),X25519_OID,mpi(cat(b(0x40),raw(own.classicalKey(false)))),b(3,1,8,7));}
    static boolean classicalEnvelope(byte[] encoded)throws Exception{
        var p=packets(encoded);if(p.isEmpty()||p.get(0).tag!=1)return false;byte[] b=p.get(0).body;
        // The algorithm is at offset 35 only for an addressed v6 recipient.
        // A v6 PKESK naming a v4 key has its algorithm at offset 23; reading
        // offset 35 there would mistake an arbitrary ciphertext byte for X25519.
        return b.length>10&&b[0]==3&&b[9]==18
            ||b.length>36&&b[0]==6&&b[1]==33&&b[2]==6&&b[35]==25;
    }
    static byte[] openClassicalEncrypted(byte[] encoded,PublicIdentity own,ExternalKem.Backend backend)throws Exception{
        check(backend!=null&&own.classicalBody(false)!=null,"Select the migrated X25519 compatibility identity");var packets=packets(encoded);check(packets.stream().map(Packet::tag).toList().equals(List.of(1,18)),"Expected one recipient and protected encrypted payload");Reader r=new Reader(packets.get(0).body);int version=r.one();byte[] point,wrapped;boolean legacy=version==3;
        if(legacy){byte[] fp=fingerprint(classicalV4Body(own));check(Arrays.equals(r.take(8),slice(fp,12,20))&&r.one()==18,"Wrong classical recipient");byte[] mpi=mpi(r,263);check(mpi.length==33&&mpi[0]==0x40,"Invalid X25519 point");point=slice(mpi,1,33);}else{check(version==6&&r.one()==33&&r.one()==6&&Arrays.equals(r.take(32),fingerprint(own.classicalBody(false)))&&r.one()==25,"Wrong v6 classical recipient");point=r.take(32);}
        wrapped=r.take(r.one());check(r.left()==0,"Trailing session data");var op=backend.newOperation();byte[] secret=null,kek=null,session=null;
        try{secret=op.deriveCompatibility(own.classicalKey(false),curve25519(point,false));check(secret.length==32&&!Arrays.equals(secret,new byte[32]),"Invalid X25519 shared secret");
            if(legacy)kek=slice(hash("SHA-256",cat(n(1,4),secret,X25519_OID,b(18,3,1,8,7),bytes("Anonymous Sender    "),fingerprint(classicalV4Body(own)))),0,16);
            else kek=kdf(cat(point,raw(own.classicalKey(false)),secret),null,bytes("OpenPGP X25519"),16);
            session=wrap(false,kek,wrapped);int cipher;
            if(legacy){int padding=session[session.length-1]&255;check(padding>0&&padding<=40&&session.length>padding+3,"Invalid session padding");for(int i=session.length-padding;i<session.length;i++)check((session[i]&255)==padding,"Invalid session padding");int end=session.length-padding;cipher=session[0]&255;int sum=0;for(int i=1;i<end-2;i++)sum+=session[i]&255;check((sum&65535)==((session[end-2]&255)*256+(session[end-1]&255)),"Invalid session checksum");byte[] key=slice(session,1,end-2);wipe(session);session=key;}else{check(packets.get(1).body[0]==2,"Expected v2 SEIPD");cipher=packets.get(1).body[1]&255;}
            check(List.of(7,8,9).contains(cipher)&&session.length==(cipher==7?16:cipher==8?24:32),"Invalid content cipher/key");
            var list=(org.bouncycastle.openpgp.PGPEncryptedDataList)LegacyOpenPgp.objects(encoded).nextObject();var data=list.extractSessionKeyEncryptedData();check(data.isIntegrityProtected(),"Unprotected data rejected");byte[] plain=LegacyOpenPgp.bounded(data.getDataStream(new org.bouncycastle.openpgp.operator.jcajce.JceSessionKeyDataDecryptorFactoryBuilder().setProvider("BC").build(new org.bouncycastle.openpgp.PGPSessionKey(cipher,session))));check(data.verify(),"Message integrity failed");return plain;
        }finally{wipe(secret);wipe(kek);wipe(session);op.clearSecrets();}
    }
    /** Packet version and recipient-key version are independent. A v6 PKESK
     * may name a v4 certificate by its complete 20-byte fingerprint. Anonymous
     * recipients remain unsupported: the user-selected credential must match
     * before any PIN prompt or private component operation. */
    record V4Recipient(int version,byte[] address,int algorithm,Reader data) {
        void requireKey(byte[] key,int expectedAlgorithm)throws Exception {
            check(key.length>5&&key[0]==4&&algorithm==expectedAlgorithm,"Unsupported v4 recipient algorithm");
            byte[] fp=fingerprint(key);
            // v3 transmits only a key ID; v6 transmits the complete fingerprint.
            // Never truncate the v6 value to a matching low 64-bit key ID.
            check(Arrays.equals(address,version==3?slice(fp,12,20):fp),"v4 recipient does not match selected identity");
        }
    }
    static V4Recipient v4Recipient(byte[] packet)throws Exception {
        Reader r=new Reader(packet);int version=r.one();byte[] address;
        if(version==3)address=r.take(8);
        else {
            // The length includes the key-version byte: 1 + SHA-1's 20 bytes.
            // In particular, reject zero/anonymous recipients, padded 32-byte
            // v4 fingerprints, and truncated bodies rather than guessing a key.
            check(version==6&&r.one()==21&&r.one()==4,"Expected addressed v4 recipient in v6 PKESK");
            address=r.take(20);
        }
        return new V4Recipient(version,address,r.one(),r);
    }
    static boolean v4Envelope(List<Packet> packets){
        if(packets.isEmpty()||packets.get(0).tag!=1)return false;
        byte[] body=packets.get(0).body;
        // This is only a dispatcher. v4Recipient performs complete length and
        // address validation, so a malformed header never reaches the backend.
        return body.length>0&&(body[0]==3||body.length>=3&&body[0]==6&&body[2]==4);
    }
    record HybridSession(byte[] ciphertext,byte[] wrapped,int cipher){}
    static HybridSession hybridSession(V4Recipient recipient)throws Exception {
        Reader r=recipient.data;byte[] ct=r.take(1120);int size=r.one();
        // Algorithm 35's v6 form omits the cipher octet and fixes AES-256.
        // Its v3 form includes that octet in the advertised wrapped-key size.
        int cipher=recipient.version==3?r.one():9;
        check(List.of(7,8,9).contains(cipher)&&size==r.left()+(recipient.version==3?1:0),"Invalid hybrid session key");
        int keyBytes=cipher==7?16:cipher==8?24:32;
        check(r.left()==keyBytes+8,"Invalid wrapped AES key length");
        return new HybridSession(ct,r.take(r.left()),cipher);
    }
    static byte[] openCompatibilityEncrypted(byte[] encoded,PublicIdentity own,Identity id,ExternalKem.Backend backend)throws Exception {
        check(rfc9980(own),"v4 hybrid decryption requires the matching RFC 9980 identity");
        var packets=packets(encoded);check(packets.stream().map(Packet::tag).toList().equals(List.of(1,18)),"Expected one recipient and integrity-protected encrypted data");
        byte[] subkey=cat(b(4),slice(own.subkey,1,5),b(35),raw(own.encryption.ec),raw(own.encryption.pq));
        V4Recipient recipient=v4Recipient(packets.get(0).body);recipient.requireKey(subkey,35);
        // Finish the public framing checks before recover can create a backend
        // operation or prompt for a PIN. The encrypted payload is authenticated
        // only after recovery; syntactically valid ciphertext is not yet trusted.
        HybridSession request=hybridSession(recipient);
        byte[] kek=recover(request.ciphertext,id,backend,own),session=null;
        try {
            session=wrap(false,kek,request.wrapped);int cipher=request.cipher;
            check(session.length==(cipher==7?16:cipher==8?24:32),"Invalid AES session key length");
            var factory=LegacyOpenPgp.objects(encoded);Object object=factory.nextObject();check(object instanceof org.bouncycastle.openpgp.PGPEncryptedDataList,"Expected encrypted data");
            var data=((org.bouncycastle.openpgp.PGPEncryptedDataList)object).extractSessionKeyEncryptedData();check(data.isIntegrityProtected(),"Unprotected encrypted data rejected");
            byte[] plain=LegacyOpenPgp.bounded(data.getDataStream(new org.bouncycastle.openpgp.operator.jcajce.JceSessionKeyDataDecryptorFactoryBuilder().setProvider("BC").build(new org.bouncycastle.openpgp.PGPSessionKey(cipher,session))));
            check(data.verify(),"Encrypted message integrity check failed");return plain;
        }finally{wipe(kek);wipe(session);}
    }
    static byte[] openSigned(byte[] data,PublicIdentity signer,boolean[] pq)throws Exception{
        byte[] plain=openSigned(data,signer);var factory=LegacyOpenPgp.objects(data);Object first=factory.nextObject();int depth=0;
        while(first instanceof org.bouncycastle.openpgp.PGPCompressedData compressed){check(++depth<=3,"Compression nesting");factory=LegacyOpenPgp.objects(LegacyOpenPgp.bounded(compressed.getDataStream()));first=factory.nextObject();}
        if(first instanceof org.bouncycastle.openpgp.PGPOnePassSignatureList list){int algorithm=list.get(0).getKeyAlgorithm();pq[0]=algorithm==30||algorithm==31||algorithm==41;}return plain;
    }
    // Authentication precedes MIME interpretation and HTML presentation. The
    // result reports cryptographic validity separately from contact trust and
    // the unprotected outer From header; no trust is granted during parsing.
    public static Opened open(byte[] message,PublicIdentity signer,PublicIdentity own,Identity id,ExternalKem.Backend backend)throws Exception {
        check(signer!=null,"Import the sender's OpenPGP public key");Parts p=parts(message);byte[] plain;boolean[] quantum={signer.legacy==null&&signer.signing.pq!=null};
        if(p.encrypted){check(own!=null&&id!=null,"Select the decryption identity");match(own,id);byte[] encoded=unarmor(decoded(mime(p.second)),"MESSAGE");var payload=id.softwareOpenPgp()!=null?List.<Packet>of():packets(encoded);if(id.softwareOpenPgp()!=null)plain=openSigned(id.softwareOpenPgp().decrypt(encoded),signer,quantum);else if(classical(id)&&own.compatibility!=null&&v4Envelope(payload))plain=openSigned(Level5Compatibility.decrypt(encoded,own,backend),signer,quantum);else if(classicalEnvelope(encoded))plain=openSigned(openClassicalEncrypted(encoded,own,backend),signer,quantum);else if(v4Envelope(payload))plain=openSigned(openCompatibilityEncrypted(encoded,own,id,backend),signer,quantum);else{Envelope env=envelope(encoded,own);byte[] kek=recover(env.ct,id,backend,own);try{plain=openSigned(env.open(kek),signer,quantum);}finally{wipe(kek);}}}
        else if(signer.v6!=null){byte[] signature=unarmor(decoded(mime(p.second)),"SIGNATURE");new LegacyOpenPgp(signer.encoded,6).verify(signature,p.first);int alg=((org.bouncycastle.openpgp.PGPSignatureList)LegacyOpenPgp.objects(signature).nextObject()).get(0).getKeyAlgorithm();quantum[0]=alg==30||alg==31;plain=p.first;}
        else if(signer.legacy!=null){new LegacyOpenPgp(signer.encoded,signer.version()).verify(unarmor(decoded(mime(p.second)),"SIGNATURE"),p.first);plain=p.first;}
        else{List<Packet> sig=packets(unarmor(decoded(mime(p.second)),"SIGNATURE"));check(sig.size()==1&&sig.get(0).tag==2,"Expected one detached signature");verify(sig.get(0).body,p.first,0,signer.primary);plain=p.first;}
        var body=VerifiedMime.body(plain);
        return new Opened(body.text(),signer.email,signer.fingerprint(),p.encrypted,signer.matchesEmail(p.root.headers.get("from")),signer.profile(),quantum[0],body.html());
    }
}
