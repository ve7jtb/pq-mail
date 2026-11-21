package dev.hybridmail;

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import javax.crypto.KeyAgreement;
import com.google.gson.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.crypto.kems.MLKEMExtractor;
import org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/** Disposable software test fixture, never a card or application backend.
 * The public fixed password deliberately makes these generated keys unsuitable
 * for real identities. This helper has no PKCS#11, account or transport access. */
public final class V5SoftwareFixture {
    static final String PASSWORD = "synthetic-fixture-password";
    static final String MARKER = "PQ Mail disposable v5 interop fixture; not a real identity\n";
    static final Map<String,String> ALGORITHMS = Map.of("84","Ed25519","85","X25519","9d","ML-KEM-768");

    /** Restrict generated material before writing it, even though it is only
     * synthetic. This regression harness is used on POSIX GnuPG test hosts. */
    static void file(Path path,byte[] bytes)throws IOException {
        Files.createFile(path,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        Files.write(path,bytes);
    }

    static void generate(Path root)throws Exception {
        // Refuse existing output, including symlinks, so a test invocation can
        // never replace a user's identity or silently reuse old fixture keys.
        if(Files.exists(root,LinkOption.NOFOLLOW_LINKS))throw new IOException("Fixture output already exists");
        Files.createDirectory(root,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        var pairs=new LinkedHashMap<String,KeyPair>();
        for(String alias:List.of("84","85","9d"))pairs.put(alias,KeyPairGenerator.getInstance(ALGORITHMS.get(alias),"BC").generateKeyPair());
        char[] password=PASSWORD.toCharArray();
        try {
            var store=KeyStore.getInstance("PKCS12","BC");store.load(null,password);
            var publicKeys=new JsonArray();var signer=pairs.get("84");
            for(var entry:pairs.entrySet()) {
                // PKCS#12 key entries require certificates. These locally
                // signed X.509 carriers merely index the synthetic SPKIs;
                // GnuPG creates the actual v5 public certificate separately.
                var subject=new X500Name("CN=Disposable v5 interoperability fixture");
                long now=System.currentTimeMillis();
                var builder=new JcaX509v3CertificateBuilder(subject,new BigInteger(120,new SecureRandom()),
                    new Date(now-60000),new Date(now+30L*86400000),subject,entry.getValue().getPublic());
                var certificate=new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(
                    new JcaContentSignerBuilder("Ed25519").setProvider("BC").build(signer.getPrivate())));
                store.setKeyEntry(entry.getKey(),entry.getValue().getPrivate(),password,new java.security.cert.Certificate[]{certificate});
                var key=new JsonObject();key.addProperty("spki",Base64.getEncoder().encodeToString(entry.getValue().getPublic().getEncoded()));
                key.addProperty("reference","PIV."+entry.getKey().toUpperCase(Locale.ROOT));
                key.addProperty("usage",entry.getKey().equals("84")?"s":"e");publicKeys.add(key);
            }
            var encoded=new ByteArrayOutputStream();store.store(encoded,password);byte[] p12=encoded.toByteArray();
            try{file(root.resolve("identity.p12"),p12);}finally{Arrays.fill(p12,(byte)0);}
            file(root.resolve("keys.json"),publicKeys.toString().getBytes(StandardCharsets.UTF_8));
            // Write the marker last: partial fixture creation must not be
            // mistaken for a usable, complete disposable component store.
            file(root.resolve("fixture-purpose.txt"),MARKER.getBytes(StandardCharsets.UTF_8));
        } finally {
            Arrays.fill(password,'\0');
            for(var pair:pairs.values())try{pair.getPrivate().destroy();}catch(Exception ignored){/* Best effort only; the JVM owns other copies. */}
        }
        System.out.println("Created disposable software fixture; no hardware accessed");
    }

    /** Read one strictly bounded protocol field. Do not echo malformed input
     * in errors: the final line is a test password and output can be shared. */
    static byte[] line(InputStream input,int limit)throws IOException {
        var output=new ByteArrayOutputStream();
        for(int value;(value=input.read())!=-1;) {
            if(value==10)return output.toByteArray();
            if(output.size()>=limit)throw new IOException("Oversized fixture field");
            output.write(value);
        }
        throw new IOException("Incomplete fixture request");
    }

    static void component(Path p12)throws Exception {
        byte[] password=null,result=null;char[] chars=null;PrivateKey privateKey=null;
        try {
            Path marker=p12.resolveSibling("fixture-purpose.txt");
            if(Files.isSymbolicLink(p12)||Files.isSymbolicLink(marker)||!Files.isRegularFile(p12)||Files.size(p12)>65536
                ||!Files.isRegularFile(marker)||Files.size(marker)>256||!Files.readString(marker).equals(MARKER))
                throw new IOException("Expected complete disposable fixture");
            String algorithm=new String(line(System.in,32),StandardCharsets.US_ASCII);
            byte[] spki=Base64.getDecoder().decode(line(System.in,6000));
            byte[] incoming=Base64.getDecoder().decode(line(System.in,8000));
            password=line(System.in,256);
            if(System.in.read()!=-1||!MessageDigest.isEqual(password,PASSWORD.getBytes(StandardCharsets.US_ASCII)))
                throw new IOException("Expected synthetic fixture password");
            chars=PASSWORD.toCharArray();var store=KeyStore.getInstance("PKCS12","BC");
            try(var input=Files.newInputStream(p12)){store.load(input,chars);}
            if(store.size()!=3)throw new IOException("Unexpected fixture entries");
            for(String alias:List.of("84","85","9d")) {
                var certificate=store.getCertificate(alias);
                if(certificate!=null&&Arrays.equals(spki,certificate.getPublicKey().getEncoded())) {
                    if(privateKey!=null||!algorithm.equals(ALGORITHMS.get(alias)))throw new IOException("Ambiguous fixture binding");
                    privateKey=(PrivateKey)store.getKey(alias,chars);
                }
            }
            if(privateKey==null)throw new IOException("Unknown fixture public key");
            if(algorithm.equals("Ed25519")) {
                if(!List.of(32,48,64).contains(incoming.length))throw new IOException("Invalid fixture digest");
                // GnuPG already hashed the OpenPGP signature framing. Apply
                // pure Ed25519 to those digest bytes, with no extra prehash.
                var signature=Signature.getInstance("Ed25519","BC");signature.initSign(privateKey);signature.update(incoming);result=signature.sign();
            } else if(algorithm.equals("X25519")) {
                if(incoming.length!=32)throw new IOException("Invalid fixture peer");
                byte[] encoded=new byte[44];System.arraycopy(HexFormat.of().parseHex("302a300506032b656e032100"),0,encoded,0,12);System.arraycopy(incoming,0,encoded,12,32);
                var peer=KeyFactory.getInstance("X25519","BC").generatePublic(new X509EncodedKeySpec(encoded));
                var agreement=KeyAgreement.getInstance("X25519","BC");agreement.init(privateKey);agreement.doPhase(peer,true);result=agreement.generateSecret();
            } else if(algorithm.equals("ML-KEM-768")) {
                if(incoming.length!=1088)throw new IOException("Invalid fixture ciphertext");
                byte[] encoded=privateKey.getEncoded();
                try{result=new MLKEMExtractor((MLKEMPrivateKeyParameters)PrivateKeyFactory.createKey(encoded)).extractSecret(incoming);}
                finally{Arrays.fill(encoded,(byte)0);}
            } else throw new IOException("Unsupported fixture operation");
            // The Assuan bridge expects Base64 for every component. The
            // production PKCS#11 adapters are intentionally never loaded here.
            System.out.println(Base64.getEncoder().encodeToString(result));
        } finally {
            if(password!=null)Arrays.fill(password,(byte)0);
            if(chars!=null)Arrays.fill(chars,'\0');
            if(result!=null)Arrays.fill(result,(byte)0);
            if(privateKey!=null)try{privateKey.destroy();}catch(Exception ignored){/* Best effort only. */}
        }
    }

    public static void main(String[] args) {
        try {
            if(args.length!=2)throw new IOException("Expected --generate DIRECTORY or --component P12");
            Security.addProvider(new BouncyCastleProvider());
            if(args[0].equals("--generate"))generate(Path.of(args[1]));
            else if(args[0].equals("--component"))component(Path.of(args[1]));
            else throw new IOException("Unsupported fixture mode");
        } catch(Exception error) {
            System.err.println("Disposable v5 fixture operation failed; no retry");System.exit(1);
        }
    }
}
