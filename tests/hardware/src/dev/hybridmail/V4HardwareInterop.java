package dev.hybridmail;

import static dev.hybridmail.OpenPgp.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Arrays;

/** Public-key-only half of the v4 hardware interoperability harness. It uses
 * the selected installed PQ Mail jar, but cannot sign, request a PIN, access
 * a card, change trust, or alter account/application settings. */
public final class V4HardwareInterop {
    static final byte[] MESSAGE=("Synthetic PQ Mail v4 hybrid GnuPG hardware "
        +"interoperability test.\r\n").getBytes(StandardCharsets.UTF_8);

    public static void main(String[] args)throws Exception{
        check(args.length==4,"Usage: prepare|verify CERTIFICATE OUT APP-CONTENTS-APP");
        check(args[0].equals("prepare")||args[0].equals("verify"),"Expected prepare or verify");
        // An explicit app directory prevents an old development jar earlier on
        // the classpath from silently standing in for the installed application.
        V4InstalledReceive.installedApp(Path.of(args[3]));MailEngine.init();
        var cert=new PublicIdentity(V4InstalledReceive.read(Path.of(args[1]),131072));
        Path out=Path.of(args[2]);check(Files.isDirectory(out),"Create the dedicated result directory first");
        check(cert.version()==4&&cert.legacy!=null&&cert.legacy.recipient!=null
            &&cert.legacy.recipient.getAlgorithm()==35,"Expected v4 RFC 9980 hybrid recipient");
        if(args[0].equals("prepare")){
            // Use PQ Mail's normal validated algorithm-35 recipient selector.
            // This is an unsigned literal fixture: encryption/integrity and a
            // separate detached-signature check must not be described as one
            // inline-signed encrypted message.
            byte[] literal=frame(11,cat(b(98,0),n(0,4),MESSAGE));
            byte[] encrypted=cert.legacy.encrypt(literal);
            // Refuse to overwrite an earlier run. The outer harness creates a
            // fresh result directory and stops after any partial failure.
            check(!Files.exists(out.resolve("message.txt"))&&!Files.exists(out.resolve("pqmail-v4-encrypted.pgp")),
                "Public fixture output already exists; use a fresh test directory");
            Files.write(out.resolve("message.txt"),MESSAGE,StandardOpenOption.CREATE_NEW);
            Files.write(out.resolve("pqmail-v4-encrypted.pgp"),encrypted,StandardOpenOption.CREATE_NEW);
            System.out.println("PASS installed PQ Mail encryption selects algorithm 35, without a classical fallback recipient");
        }else{
            // Verify the bytes actually passed to GnuPG, and require this
            // harness's fixed synthetic text rather than any mailbox content.
            byte[] message=V4InstalledReceive.read(out.resolve("message.txt"),16384);
            check(Arrays.equals(message,MESSAGE),"Unexpected synthetic message bytes");
            cert.legacy.verify(V4InstalledReceive.read(out.resolve("v4-signature.pgp"),16384),message);
            System.out.println("PASS installed PQ Mail verifies the v4 Ed25519 detached signature");
        }
    }
}
