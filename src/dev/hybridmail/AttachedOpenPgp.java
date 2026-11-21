package dev.hybridmail;
import jakarta.mail.*;
import java.io.*;
import java.util.*;
/** Untrusted candidate discovery only. No persistence or trust changes. */
final class AttachedOpenPgp {
 private int parts, attachments;
 private final Map<String,OpenPgp.PublicIdentity> keys=new LinkedHashMap<>();
 // Discovery deliberately returns untrusted candidates rather than adding
 // them to a contact store. The caller must verify the message with a candidate
 // before offering separate save/trust actions to the user.
 static List<OpenPgp.PublicIdentity> find(Part message)throws Exception{var scan=new AttachedOpenPgp();scan.visit(message,0);return List.copyOf(scan.keys.values());}
 private void visit(Part part,int depth)throws Exception{
  if(depth>12||++parts>100)throw new IOException("OpenPGP attachment scan exceeds MIME limits");
  if(part.isMimeType("multipart/*")){Multipart m=(Multipart)part.getContent();if(m.getCount()>100)throw new IOException("Too many MIME parts");for(int i=0;i<m.getCount();i++)visit(m.getBodyPart(i),depth+1);return;}
  String name=part.getFileName();boolean candidate=part.isMimeType("application/pgp-keys")||(name!=null&&(name.toLowerCase(Locale.ROOT).endsWith(".asc")||name.toLowerCase(Locale.ROOT).endsWith(".pgp")));
  if(!candidate)return;if(++attachments>8)throw new IOException("Too many attached OpenPGP certificate candidates");
  byte[] bytes;try(InputStream in=part.getInputStream()){bytes=in.readNBytes(128*1024+1);}if(bytes.length>128*1024)return;
  // Invalid, expired or unrelated attachment data cannot become a verification key.
  try{var key=new OpenPgp.PublicIdentity(bytes);keys.putIfAbsent(key.fingerprint(),key);}catch(Exception invalid){}
 }
}
