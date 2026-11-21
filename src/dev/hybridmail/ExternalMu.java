package dev.hybridmail;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;
import java.util.concurrent.*;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;

/** Host computes FIPS 204 mu using the public key; backend never receives message bytes. */
public final class ExternalMu {
    @FunctionalInterface public interface Backend {
        byte[] sign(PublicKey publicKey, byte[] mu) throws Exception;
        default Backend newOperation() { return this; }
        default void clearSecrets() {}
        default byte[] signCompatibilityEcdsa(PublicKey key,byte[] digest)throws Exception{throw new GeneralSecurityException("Level 5 compatibility backend required");}
        default byte[] signCompatibilityEd25519(PublicKey key,byte[] digest)throws Exception{throw new GeneralSecurityException("Backend lacks dedicated compatibility signing");}
        default byte[] signEd448(PublicKey key,byte[] digest)throws Exception{throw new GeneralSecurityException("Ed448 companion/native backend required");}
        default byte[] signEd25519(PublicKey key,byte[] digest)throws Exception{throw new GeneralSecurityException("This backend does not support Ed25519");}
        default byte[] signRsa(PublicKey publicKey, byte[] digest) throws Exception {
            throw new GeneralSecurityException("This adapter does not support token RSA-PSS");
        }
        default byte[] signEcdsa(PublicKey publicKey, byte[] digest) throws Exception {
            throw new GeneralSecurityException("This adapter does not support token ECDSA");
        }
    }
    public record TokenKey(PublicKey publicKey, Backend backend) implements PrivateKey {
        public String getAlgorithm() { return publicKey.getAlgorithm(); }
        public String getFormat() { return null; }
        public byte[] getEncoded() { return null; }
    }
    public static final Provider PROVIDER = new Provider("ExternalMu", "1.0", "External mu ML-DSA adapter") {{
        put("Signature.ML-DSA-44", MuSignature.class.getName());
        put("Signature.ML-DSA-65", MuSignature.class.getName());
        put("Signature.ML-DSA-87", MuSignature.class.getName());
        put("Signature.SHA384withECDSA", Ec384Signature.class.getName());
        put("Signature.SHA256withECDSA", EcSignature.class.getName());
        put("Signature.RSASSA-PSS", PssSignature.class.getName());
    }};
    public static final class MuSignature extends SignatureSpi {
        private TokenKey key;
        private byte[] context = new byte[0];
        private MLDSASigner digest;
        private boolean started;
        private void resetDigest() throws InvalidKeyException {
            try {
                digest = new MLDSASigner();
                digest.init(false, new ParametersWithContext(PublicKeyFactory.createKey(key.publicKey().getEncoded()), context));
                started = false;
            } catch (Exception e) { throw new InvalidKeyException(e); }
        }
        protected void engineInitSign(PrivateKey k) throws InvalidKeyException {
            if (!(k instanceof TokenKey t)) throw new InvalidKeyException("Expected external token key");
            key = t; resetDigest();
        }
        protected void engineInitVerify(PublicKey k) throws InvalidKeyException { throw new InvalidKeyException("Use BC to verify"); }
        protected void engineUpdate(byte b) { started = true; digest.update(b); }
        protected void engineUpdate(byte[] b, int off, int len) { started = true; digest.update(b, off, len); }
        protected byte[] engineSign() throws SignatureException {
            try {
                // The ML-DSA public key and context participate in mu. Validate
                // the returned signature locally against that same mu so a
                // successful adapter exit cannot substitute a different key.
                byte[] mu = digest.generateMu();
                byte[] sig = key.backend().sign(key.publicKey(), mu.clone());
                if (sig == null || !digest.verifyMuSignature(mu, sig))
                    throw new SignatureException("External signer returned an invalid signature for this key/mu");
                return sig;
            } catch (Exception e) { throw new SignatureException("External mu signing failed", e); }
            finally { try { resetDigest(); } catch (Exception ignored) {} }
        }
        protected boolean engineVerify(byte[] s) { return false; }
        protected void engineSetParameter(AlgorithmParameterSpec p) throws InvalidAlgorithmParameterException {
            if (started || !(p instanceof ContextParameterSpec c) || c.getContext().length > 255)
                throw new InvalidAlgorithmParameterException("Expected context before message");
            context = c.getContext().clone();
            if (key != null) try { resetDigest(); } catch (Exception e) { throw new InvalidAlgorithmParameterException(e); }
        }
        @Deprecated protected void engineSetParameter(String n, Object v) { throw new UnsupportedOperationException(); }
        @Deprecated protected Object engineGetParameter(String n) { throw new UnsupportedOperationException(); }
    }
    public record EcTokenKey(PublicKey publicKey, Backend backend) implements PrivateKey {
        public String getAlgorithm() { return "EC"; }
        public String getFormat() { return null; }
        public byte[] getEncoded() { return null; }
    }
    /** BC supplies the composite representative; this component hashes it once with SHA-256. */
    public static class EcSignature extends SignatureSpi {
        private EcTokenKey key;
        protected String hash(){return "SHA-256";}
        private MessageDigest digest;
        protected void engineInitSign(PrivateKey k) throws InvalidKeyException {
            if (!(k instanceof EcTokenKey t)) throw new InvalidKeyException("Expected external EC key");
            key=t;
            try { digest=MessageDigest.getInstance(hash()); }
            catch (GeneralSecurityException e) { throw new InvalidKeyException(e); }
        }
        protected void engineInitVerify(PublicKey k) throws InvalidKeyException { throw new InvalidKeyException("Use BC to verify"); }
        protected void engineUpdate(byte b) { digest.update(b); }
        protected void engineUpdate(byte[] b,int off,int len) { digest.update(b,off,len); }
        protected byte[] engineSign() throws SignatureException {
            try {
                byte[] hash=digest.digest();
                byte[] signature=key.backend().signEcdsa(key.publicKey(),hash.clone());
                Signature verifier=Signature.getInstance("NONEwithECDSA","BC");
                verifier.initVerify(key.publicKey());verifier.update(hash);
                if(signature==null||!verifier.verify(signature)) throw new SignatureException("Invalid external ECDSA signature");
                return signature;
            } catch(Exception e) { throw new SignatureException("External ECDSA signing failed",e); }
            finally { digest.reset(); }
        }
        protected boolean engineVerify(byte[] s) { return false; }
        @Deprecated protected void engineSetParameter(String n,Object v) { throw new UnsupportedOperationException(); }
        @Deprecated protected Object engineGetParameter(String n) { throw new UnsupportedOperationException(); }
    }
    public static final class Ec384Signature extends EcSignature { protected String hash(){return "SHA-384";} }
    public record RsaTokenKey(PublicKey publicKey, Backend backend) implements PrivateKey {
        public String getAlgorithm() { return "RSA"; }
        public String getFormat() { return null; }
        public byte[] getEncoded() { return null; }
    }
    public static final java.security.spec.PSSParameterSpec PSS = new java.security.spec.PSSParameterSpec(
        "SHA-256","MGF1",java.security.spec.MGF1ParameterSpec.SHA256,32,1);
    public static final class PssSignature extends SignatureSpi {
        private RsaTokenKey key;
        private final ByteArrayOutputStream message=new ByteArrayOutputStream();
        protected void engineInitSign(PrivateKey k) throws InvalidKeyException {
            if(!(k instanceof RsaTokenKey t))throw new InvalidKeyException("Expected external RSA key");
            key=t;message.reset();
        }
        protected void engineInitVerify(PublicKey k)throws InvalidKeyException{throw new InvalidKeyException("Use BC to verify");}
        protected void engineUpdate(byte b)throws SignatureException{checkSize(1);message.write(b);}
        protected void engineUpdate(byte[] b,int off,int len)throws SignatureException{checkSize(len);message.write(b,off,len);}
        private void checkSize(int n)throws SignatureException{if(n>8192-message.size())throw new SignatureException("Composite representative too large");}
        protected byte[] engineSign()throws SignatureException{
            try{
                byte[] bytes=message.toByteArray();
                byte[] sig=key.backend().signRsa(key.publicKey(),MessageDigest.getInstance("SHA-256").digest(bytes));
                Signature verify=Signature.getInstance("RSASSA-PSS","BC");verify.setParameter(PSS);
                verify.initVerify(key.publicKey());verify.update(bytes);
                if(sig==null||!verify.verify(sig))throw new SignatureException("Invalid external RSA-PSS signature");
                return sig;
            }catch(Exception e){throw new SignatureException("External RSA-PSS signing failed",e);}
            finally{message.reset();}
        }
        protected boolean engineVerify(byte[] s){return false;}
        protected void engineSetParameter(AlgorithmParameterSpec params)throws InvalidAlgorithmParameterException{
            if(!(params instanceof java.security.spec.PSSParameterSpec p)||!p.getDigestAlgorithm().equalsIgnoreCase("SHA-256")
                ||!p.getMGFAlgorithm().equalsIgnoreCase("MGF1")||!(p.getMGFParameters() instanceof java.security.spec.MGF1ParameterSpec m)
                ||!m.getDigestAlgorithm().equalsIgnoreCase("SHA-256")||p.getSaltLength()!=32||p.getTrailerField()!=1)
                throw new InvalidAlgorithmParameterException("Expected SHA-256 / MGF1-SHA256 / 32-byte salt / trailer 1");
        }
        @Deprecated protected void engineSetParameter(String n,Object v){throw new UnsupportedOperationException();}
        @Deprecated protected Object engineGetParameter(String n){throw new UnsupportedOperationException();}
    }
    /** Executable protocol: 3 UTF-8 lines on stdin, one base64 signature on stdout. No shell. */
    public static Backend executable(String executable) { return new ExecutableBackend(executable); }
    static Backend certification(String executable){return new ExecutableBackend(executable,Map.of("PQMAIL_CERTIFICATION_SLOTS","86,87"));}
    @FunctionalInterface interface PinSource { char[] request()throws Exception; }
    // One logical operation may call two private components. Keep its PIN only
    // for that operation, return disposable copies to subprocesses, and require
    // callers to invoke clearSecrets() in their operation-level finally block.
    // A process/session cache here would accidentally extend authentication to
    // later messages; newOperation() is the boundary that prevents that reuse.
    static final class OperationPinCache {
        private char[] value;
        synchronized char[] copy(PinSource source)throws Exception {
            if(value==null)value=source.request();
            if(value==null)throw new SignatureException("PIN entry cancelled");
            return value.clone();
        }
        synchronized void clear(){if(value!=null){Arrays.fill(value,'\0');value=null;}}
    }
    private static final class ExecutableBackend implements Backend {
        private final String executable;
        private final Map<String,String> overrides;
        private final OperationPinCache pinCache=new OperationPinCache();
        ExecutableBackend(String executable){this(executable,Map.of());}
        ExecutableBackend(String executable,Map<String,String> overrides){this.executable=executable;this.overrides=Map.copyOf(overrides);}
        public Backend newOperation(){return new ExecutableBackend(executable,overrides);}
        public synchronized void clearSecrets(){pinCache.clear();}
        private synchronized byte[] call(String algorithm,PublicKey pub,byte[] input)throws Exception{return call(algorithm,pub,input,overrides);}
        private synchronized byte[] call(String algorithm,PublicKey pub,byte[] input,Map<String,String> config)throws Exception{
            boolean appPin=java.nio.file.Path.of(executable).getFileName().toString().equals("pkcs11-mu.py");
            try{
                return invoke(executable,algorithm,pub,input,appPin?pinCache.copy(()->{TokenPresence.require(executable);return TokenPin.request(algorithm);}):null,false,config);
            }catch(Exception e){clearSecrets();throw e;}
        }
        public byte[] sign(PublicKey pub,byte[] mu)throws Exception{return call(pub.getAlgorithm(),pub,mu);}
        public byte[] signEcdsa(PublicKey pub,byte[] digest)throws Exception{return call(((java.security.interfaces.ECPublicKey)pub).getParams().getCurve().getField().getFieldSize()==384?"ECDSA-P384-SHA384":"ECDSA-P256-SHA256",pub,digest);}
        public byte[] signCompatibilityEcdsa(PublicKey pub,byte[] digest)throws Exception{return call("ECDSA-P384-SHA384",pub,digest,Map.of("PQMAIL_LEVEL5_COMPATIBILITY","1"));}
        public byte[] signCompatibilityEd25519(PublicKey pub,byte[] digest)throws Exception{return call("Ed25519",pub,digest,Map.of("PQMAIL_COMPATIBILITY_SLOT","88"));}
        public byte[] signEd25519(PublicKey pub,byte[] digest)throws Exception{return call("Ed25519",pub,digest);}
        public byte[] signRsa(PublicKey pub,byte[] digest)throws Exception{return call("RSA3072-PSS-SHA256",pub,digest);}
    }
    private static byte[] invoke(String executable,String algorithm,PublicKey publicKey,byte[] mu,char[] pin)throws Exception{
        return invoke(executable,algorithm,publicKey,mu,pin,false);
    }
    static byte[] invoke(String executable,String algorithm,PublicKey publicKey,byte[] mu,char[] pin,boolean rawOutput) throws Exception {
            return invoke(executable,algorithm,publicKey,mu,pin,rawOutput,Map.of());
    }
    static byte[] invoke(String executable,String algorithm,PublicKey publicKey,byte[] mu,char[] pin,boolean rawOutput,Map<String,String> overrides)throws Exception{
            boolean pinDialog=pin!=null;
            // The helper protocol uses stdin for the PIN and request bytes;
            // credentials must never become argv entries or environment values.
            // Environment overrides select public slot/profile metadata only.
            ProcessBuilder builder=DesktopState.process(executable).redirectError(pinDialog?ProcessBuilder.Redirect.PIPE:ProcessBuilder.Redirect.DISCARD);
            builder.environment().putAll(overrides);
            if(pinDialog)builder.environment().put("HYBRID_MAIL_PIN_STDIN","1");
            Process p;
            try { p=builder.start(); } catch(Exception e){if(pin!=null)Arrays.fill(pin,'\0');throw e;}
            AutoCloseable progress=pinDialog?TokenPin.progress(algorithm):()->{};
            ExecutorService pool = Executors.newFixedThreadPool(2);
            try {
                // Collect both pipes concurrently: the child must not block on
                // stderr while the parent waits for its cryptographic output.
                // The byte caps bound retained diagnostics/results, while the
                // process deadline bounds a stalled card or helper operation.
                Future<byte[]> errors=pool.submit(()->p.getErrorStream().readNBytes(2048));
                Future<byte[]> output = pool.submit(() -> {
                    byte[] result = p.getInputStream().readNBytes(16385);
                    if (result.length > 16384) throw new IOException("Adapter output too large");
                    return result;
                });
                try (OutputStream out = p.getOutputStream()) {
                    out.write((algorithm + "\n" + Base64.getEncoder().encodeToString(publicKey.getEncoded()) + "\n"
                        + Base64.getEncoder().encodeToString(mu) + "\n").getBytes(StandardCharsets.US_ASCII));
                    if(pin!=null){for(char c:pin)out.write((byte)c);out.write('\n');Arrays.fill(pin,'\0');}
                }
                if (!p.waitFor(150, TimeUnit.SECONDS)) throw new IOException("Token adapter timed out");
                if (p.exitValue() != 0) {
                    String reason=pinDialog?new String(errors.get(1,TimeUnit.SECONDS),StandardCharsets.US_ASCII).trim():"";
                    throw new IOException("Token adapter failed (exit " + p.exitValue() + ")"+(reason.isEmpty()?"":": "+reason));
                }
                byte[] response=output.get(1,TimeUnit.SECONDS);
                return rawOutput?response:Base64.getDecoder().decode(new String(response,StandardCharsets.US_ASCII).trim());
            } finally {
                if(pin!=null)Arrays.fill(pin,'\0');
                progress.close();
                pool.shutdownNow();
                if (p.isAlive()) {
                    try { p.descendants().forEach(child -> child.destroyForcibly()); }
                    catch (RuntimeException ignored) { /* Process enumeration may be sandboxed. */ }
                    p.destroyForcibly();
                }
            }
    }
}
