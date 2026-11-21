package dev.hybridmail;

import static dev.hybridmail.OpenPgp.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Arrays;

/** Public-only v5 compatibility fixtures for the existing-key hardware runner.
 * These methods cannot request a PIN, access a card, or send a message. */
public final class V5HardwareInterop {
    static final byte[] MESSAGE="Synthetic GnuPG v5 YubiKey compatibility test.\r\n".getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args)throws Exception{
        check(args.length==4,"Usage: prepare|verify CERTIFICATE OUT APP-CONTENTS-APP");
        check(args[0].equals("prepare")||args[0].equals("verify"),"Expected prepare or verify");
        V5InstalledReceive.app(Path.of(args[3]));MailEngine.init();
        var cert=new PublicIdentity(V5InstalledReceive.read(Path.of(args[1]),131072));
        check(cert.version()==5,"Explicit v5 compatibility certificate required");
        // Resolve both public components now, before any hardware test. An
        // unsupported or classical-only recipient must not become a fallback.
        LibreOpenPgp.signingKey(cert);LibreOpenPgp.encryptionKeys(cert);
        Path out=Path.of(args[2]);check(Files.isDirectory(out),"Expected new test output directory");
        Path message=out.resolve("v5-message.txt");
        if(Files.exists(message))check(Arrays.equals(V5InstalledReceive.read(message,16384),MESSAGE),"Unexpected synthetic message bytes");
        else Files.write(message,MESSAGE,StandardOpenOption.CREATE_NEW);
        if(args[0].equals("prepare")){
            Path encrypted=out.resolve("pqmail-v5-encrypted.pgp");check(!Files.exists(encrypted),"Encryption fixture already exists");
            byte[] literal=frame(11,cat(b(98,0),n(0,4),MESSAGE));
            Files.write(encrypted,LibreOpenPgp.encrypt(literal,cert),StandardOpenOption.CREATE_NEW);
            System.out.println("PASS PQ Mail v5 LibrePGP hybrid encryption; unsigned synthetic literal fixture");
        }else{
            LibreOpenPgp.verifyDetached(V5InstalledReceive.read(out.resolve("v5-signature.pgp"),16384),MESSAGE,cert);
            System.out.println("PASS PQ Mail verifies GnuPG v5 Ed25519 detached signature");
        }
    }
}
