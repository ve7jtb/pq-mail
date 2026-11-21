package dev.hybridmail;

import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JceKEMAuthEnvelopedRecipient;
import org.bouncycastle.jcajce.CompositePublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.compositekem.CompositeIndex;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.KdfUtil;
import org.bouncycastle.jcajce.spec.KTSParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** Fixed-profile CMS KEM recovery. Private operations are delegated; secrets are transient. */
public final class ExternalKem {
    public interface Backend {
        byte[] decapsulate(PublicKey key,byte[] ciphertext)throws Exception;
        byte[] derive(PublicKey key,PublicKey peer)throws Exception;
        default byte[] decapsulateLevel5Compatibility(PublicKey key,byte[] ct)throws Exception{throw new GeneralSecurityException("Level 5 compatibility backend required");}
        default byte[] deriveLevel5Compatibility(PublicKey key,PublicKey peer)throws Exception{throw new GeneralSecurityException("Level 5 compatibility backend required");}
        default byte[] deriveCompatibility(PublicKey key,PublicKey peer)throws Exception{throw new GeneralSecurityException("Dedicated X25519 backend required");}
        default Backend newOperation(){return this;}
        default void clearSecrets(){}
    }
    public static Backend executable(String path){return new ExecutableBackend(path);}
    private static final class ExecutableBackend implements Backend {
        private final String path;
        private final ExternalMu.OperationPinCache pin=new ExternalMu.OperationPinCache();
        ExecutableBackend(String path){this.path=path;}
        public Backend newOperation(){return new ExecutableBackend(path);}
        public void clearSecrets(){pin.clear();}
        private byte[] invoke(String algorithm,PublicKey key,byte[] input)throws Exception{return invoke(algorithm,key,input,java.util.Map.of());}
        private byte[] invoke(String algorithm,PublicKey key,byte[] input,java.util.Map<String,String> config)throws Exception{
            try{
                byte[] secret=ExternalMu.invoke(path,algorithm,key,input,pin.copy(()->{TokenPresence.require(path);return TokenPin.request(algorithm);}),true,config);
                if(secret.length!=(algorithm.equals("ECDH-P384")?48:32)){Arrays.fill(secret,(byte)0);throw new GeneralSecurityException("Invalid token shared-secret length");}
                return secret;
            }catch(Exception e){clearSecrets();throw e;}
        }
        public byte[] decapsulate(PublicKey key,byte[] ct)throws Exception{return invoke(key.getAlgorithm(),key,ct);}
        public byte[] decapsulateLevel5Compatibility(PublicKey key,byte[] ct)throws Exception{return invoke("ML-KEM-768",key,ct,java.util.Map.of("PQMAIL_LEVEL5_COMPATIBILITY","1"));}
        public byte[] deriveLevel5Compatibility(PublicKey key,PublicKey peer)throws Exception{return invoke(key instanceof java.security.interfaces.ECPublicKey?"ECDH-P384":"X25519",key,peer.getEncoded(),java.util.Map.of("PQMAIL_LEVEL5_COMPATIBILITY","1"));}
        public byte[] deriveCompatibility(PublicKey key,PublicKey peer)throws Exception{return invoke("X25519",key,peer.getEncoded(),java.util.Map.of("PQMAIL_COMPATIBILITY_SLOT","89"));}
        public byte[] derive(PublicKey key,PublicKey peer)throws Exception{if(!(key instanceof java.security.interfaces.ECPublicKey))return invoke("X25519",key,peer.getEncoded());return invoke(((java.security.interfaces.ECPublicKey)key).getParams().getCurve().getField().getFieldSize()==384?"ECDH-P384":"ECDH-P256",key,peer.getEncoded());}
    }
    public static void validatePublicKey(PublicKey key)throws Exception{
        if(key instanceof CompositePublicKey c){
            if(!c.getAlgorithmIdentifier().getAlgorithm().equals(IANAObjectIdentifiers.id_MLKEM768_ECDH_P256_SHA3_256)||c.getPublicKeys().size()!=2)
                throw new GeneralSecurityException("Only MLKEM768-ECDH-P256-SHA3-256 is supported");
            validatePublicKey(c.getPublicKeys().get(0));
            var spki=SubjectPublicKeyInfo.getInstance(c.getPublicKeys().get(1).getEncoded());
            if(!spki.getAlgorithm().getAlgorithm().equals(X9ObjectIdentifiers.id_ecPublicKey)
                ||!X9ObjectIdentifiers.prime256v1.equals(spki.getAlgorithm().getParameters()))throw new GeneralSecurityException("Expected named P-256 key");
            point(ECUtil.getUncompressedSubjectPublicKeyBytes(spki,BouncyCastleProvider.CONFIGURATION));
        }else if(!SubjectPublicKeyInfo.getInstance(key.getEncoded()).getAlgorithm().getAlgorithm().equals(NISTObjectIdentifiers.id_alg_ml_kem_768))
            throw new GeneralSecurityException("Expected ML-KEM-768 public key");
    }
    private static PublicKey point(byte[] raw)throws Exception{return point(raw,false);}
    private static PublicKey point(byte[] raw,boolean strong)throws Exception{
        if(raw.length!=(strong?97:65)||raw[0]!=4)throw new GeneralSecurityException("Expected uncompressed P-256 point");
        var curve=org.bouncycastle.asn1.sec.SECNamedCurves.getByName(strong?"secp384r1":"secp256r1").getCurve();
        var q=curve.decodePoint(raw);
        if(q.isInfinity()||!q.isValid())throw new GeneralSecurityException("Invalid P-256 point");
        var spki=new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,strong?org.bouncycastle.asn1.sec.SECObjectIdentifiers.secp384r1:X9ObjectIdentifiers.prime256v1),raw);
        return KeyFactory.getInstance("EC","BC").generatePublic(new X509EncodedKeySpec(spki.getEncoded()));
    }
    static byte[] recover(PublicKey pub,byte[] ciphertext,Backend backend)throws Exception{
        Identity.validateEncryptionKey(pub);
        boolean hybrid=pub instanceof CompositePublicKey;
        boolean strong=pub.getAlgorithm().equals(Identity.PURE_1024_KEM)||pub.getAlgorithm().equals(Identity.HYBRID_1024_KEM);
        boolean p384=strong||pub.getAlgorithm().equals(Identity.HYBRID_768_P384_KEM);
        int mlSize=strong?1568:1088, ecSize=p384?97:65;
        if(ciphertext.length!=mlSize+(hybrid?ecSize:0))throw new GeneralSecurityException("Invalid KEM ciphertext length");
        if(!hybrid)return requireSecret(backend.decapsulate(pub,ciphertext));
        var key=(CompositePublicKey)pub;
        byte[] ml=null,ec=null;
        byte[] traditionalCt=Arrays.copyOfRange(ciphertext,mlSize,mlSize+ecSize);
        // Reject malformed/off-curve peers before asking for the PIN. The
        // authenticated envelope is still checked after key recovery; successful
        // decapsulation alone does not authenticate the message content.
        PublicKey peer=point(traditionalCt,p384); // validate before any PIN/device operation
        try{
            ml=requireSecret(backend.decapsulate(key.getPublicKeys().get(0),Arrays.copyOf(ciphertext,mlSize)));
            ec=backend.derive(key.getPublicKeys().get(1),peer);
            if(ec==null||ec.length!=(p384?48:32))throw new GeneralSecurityException("Invalid ECDH shared-secret length");
            // CMS composite KEM ordering and label are profile-specific. Do not
            // reuse this concatenation for OpenPGP: its combiner has a different
            // transcript even when both use the same hardware component keys.
            MessageDigest combiner=MessageDigest.getInstance("SHA3-256");
            combiner.update(ml);combiner.update(ec);combiner.update(traditionalCt);
            combiner.update(ECUtil.getUncompressedSubjectPublicKeyBytes(SubjectPublicKeyInfo.getInstance(key.getPublicKeys().get(1).getEncoded()),BouncyCastleProvider.CONFIGURATION));
            combiner.update(CompositeIndex.getKEMLabel(key.getAlgorithmIdentifier().getAlgorithm()));
            return combiner.digest();
        }finally{wipe(ml);wipe(ec);}
    }
    private static byte[] requireSecret(byte[] secret)throws GeneralSecurityException{
        if(secret==null||secret.length!=32){wipe(secret);throw new GeneralSecurityException("Expected 32-byte shared secret");}return secret;
    }
    private static void wipe(byte[] value){if(value!=null)Arrays.fill(value,(byte)0);}
    public static JceKEMAuthEnvelopedRecipient recipient(X509Certificate certificate,Backend backend){
        var recipient=new JceKEMAuthEnvelopedRecipient(null){
            protected Key extractSecretKey(AlgorithmIdentifier kemAlgorithm,AlgorithmIdentifier contentAlgorithm,byte[] encryptedKey)throws CMSException{
                Backend operation=backend.newOperation();byte[] secret=null,kek=null,cek=null;
                try{
                    checkContentAlgorithm(contentAlgorithm);
                    if(!CMSAlgorithm.AES256_GCM.equals(contentAlgorithm.getAlgorithm()))throw new GeneralSecurityException("Expected AES-256-GCM");
                    KEMRecipientInfo info=KEMRecipientInfo.getInstance(kemAlgorithm.getParameters());
                    AlgorithmIdentifier expected=SubjectPublicKeyInfo.getInstance(certificate.getPublicKey().getEncoded()).getAlgorithm();
                    if(!expected.equals(info.getKem())||!CMSAlgorithm.AES256_WRAP.equals(info.getWrap().getAlgorithm())
                        ||info.getWrap().getParameters()!=null||info.getKekLength()!=32||!CMSAlgorithm.SHA256_HKDF.equals(info.getKdf())
                        ||info.getKdf().getParameters()!=null||encryptedKey.length!=40||!MessageDigest.isEqual(encryptedKey,info.getEncryptedKey().getOctets()))
                        throw new GeneralSecurityException("Unsupported or inconsistent CMS KEM parameters");
                    if(info.getUkm()!=null&&info.getUkm().length>1024)throw new GeneralSecurityException("KEM ukm too large");
                    secret=recover(certificate.getPublicKey(),info.getKemct().getOctets(),operation);
                    // CMS binds the wrapping algorithm, KEK length and optional
                    // user keying material into OtherInfo. Only this derived KEK
                    // unwraps the content key; raw component secrets do not.
                    byte[] otherInfo=new CMSORIforKEMOtherInfo(info.getWrap(),32,info.getUkm()).getEncoded();
                    var spec=new KTSParameterSpec.Builder("AES",256,otherInfo).withKdfAlgorithm(info.getKdf()).build();
                    kek=KdfUtil.makeKeyBytes(spec,secret);
                    Cipher unwrap=Cipher.getInstance("AESWrap","BC");unwrap.init(Cipher.DECRYPT_MODE,new SecretKeySpec(kek,"AES"));
                    cek=unwrap.doFinal(encryptedKey);
                    if(cek.length!=32)throw new GeneralSecurityException("Invalid content key length");
                    return new SecretKeySpec(cek,"AES");
                }catch(Exception e){throw new CMSException("Token KEM recovery failed",e);}
                finally{wipe(secret);wipe(kek);wipe(cek);operation.clearSecrets();}
            }
        };
        recipient.setProvider("BC");recipient.setAllowedContentAlgorithms(java.util.Set.of(CMSAlgorithm.AES256_GCM));recipient.setMinimumTagSize(128);
        return recipient;
    }
}
