package dev.hybridmail;
import com.google.gson.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
/** Local envelope-encrypted vault. Public metadata includes display labels, never account settings or PRF outputs. */
final class PrfVault implements AutoCloseable {
 static final String RP="ve7jtb.github.io";
 private final Path path;private JsonObject envelope,data;private byte[] key;
 PrfVault(Path path)throws Exception{this.path=path;if(Files.exists(path)){if(Files.size(path)>1024*1024)throw new SecurityException("Vault too large");envelope=JsonParser.parseString(new String(Files.readAllBytes(path),StandardCharsets.UTF_8)).getAsJsonObject();if(envelope.get("version").getAsInt()!=1||!RP.equals(envelope.get("rp").getAsString()))throw new SecurityException("Unsupported vault");}}
 static byte[] random(int n){byte[] b=new byte[n];new SecureRandom().nextBytes(b);return b;}
 static String b64(byte[] b){return Base64.getUrlEncoder().withoutPadding().encodeToString(b);}
 static byte[] decode(String s){if(s.length()>1024*1024)throw new SecurityException("Oversized vault field");return Base64.getUrlDecoder().decode(s);}
 synchronized boolean exists(){return envelope!=null;}
 synchronized boolean unlocked(){return key!=null;}
 synchronized List<JsonObject> wrappers(){var result=new ArrayList<JsonObject>();if(envelope!=null)for(var w:envelope.getAsJsonArray("wrappers"))result.add(w.getAsJsonObject().deepCopy());return result;}
 private String context(){return "PQ Mail vault v1|"+RP+"|"+envelope.get("id").getAsString();}
 // Expand the 32-byte PRF output with HKDF-SHA256. The per-wrapper context
 // includes the RP, vault identifier, credential ID and PRF salt, preventing
 // wrappers from being silently transplanted between vaults or credentials.
 static byte[] derive(byte[] prf,String info)throws Exception{if(prf.length!=32)throw new SecurityException("PRF must return 32 bytes");Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(new byte[32],"HmacSHA256"));byte[] prk=mac.doFinal(prf);try{mac.init(new SecretKeySpec(prk,"HmacSHA256"));mac.update(info.getBytes(StandardCharsets.UTF_8));return mac.doFinal(new byte[]{1});}finally{Arrays.fill(prk,(byte)0);}}
 static JsonObject seal(byte[] k,byte[] plain,String aad)throws Exception{byte[] nonce=random(12);Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(k,"AES"),new GCMParameterSpec(128,nonce));c.updateAAD(aad.getBytes(StandardCharsets.UTF_8));var j=new JsonObject();j.addProperty("nonce",b64(nonce));j.addProperty("ciphertext",b64(c.doFinal(plain)));return j;}
 static byte[] open(byte[] k,JsonObject sealed,String aad)throws Exception{byte[] nonce=decode(sealed.get("nonce").getAsString());if(nonce.length!=12)throw new SecurityException("Invalid nonce");Cipher c=Cipher.getInstance("AES/GCM/NoPadding");c.init(Cipher.DECRYPT_MODE,new SecretKeySpec(k,"AES"),new GCMParameterSpec(128,nonce));c.updateAAD(aad.getBytes(StandardCharsets.UTF_8));return c.doFinal(decode(sealed.get("ciphertext").getAsString()));}
 synchronized void create(String credential,byte[] salt,byte[] prf)throws Exception{if(exists())throw new SecurityException("Vault exists");envelope=new JsonObject();envelope.addProperty("version",1);envelope.addProperty("rp",RP);envelope.addProperty("id",b64(random(32)));envelope.add("wrappers",new JsonArray());key=random(32);data=new JsonObject();try{addPasskey(credential,salt,prf);}catch(Exception e){close();envelope=null;throw e;}}
 // Each enrolled credential wraps the same random vault content key using its
 // own PRF-derived key. Enrollment requires an already unlocked vault; it does
 // not derive the content key directly from a passkey or change existing keys.
 synchronized void addPasskey(String credential,byte[] salt,byte[] prf)throws Exception{requireUnlocked();if(salt.length!=32||credential.isBlank()||decode(credential).length>2048)throw new SecurityException("Invalid passkey metadata");for(var w:wrappers())if(w.get("credential").getAsString().equals(credential))throw new SecurityException("Passkey already enrolled");if(wrappers().size()>=8)throw new SecurityException("Maximum eight passkeys");var old=envelope.deepCopy();String aad=context()+"|wrap|"+credential+"|"+b64(salt);byte[] wrapping=derive(prf,aad);try{var w=new JsonObject();w.addProperty("credential",credential);w.addProperty("salt",b64(salt));w.add("wrapped",seal(wrapping,key,aad));envelope.getAsJsonArray("wrappers").add(w);save();}catch(Exception e){envelope=old;throw e;}finally{Arrays.fill(wrapping,(byte)0);}}
 // Authenticate both envelopes before publishing unlocked state: first recover
 // a candidate content key, then verify the payload's GCM tag and parse it.
 // Failure keeps candidate/plaintext arrays out of the persistent object state.
 synchronized void unlock(String credential,byte[] prf)throws Exception{close();for(var w:wrappers()){if(!credential.equals(w.get("credential").getAsString()))continue;String aad=context()+"|wrap|"+credential+"|"+w.get("salt").getAsString();byte[] wrapping=derive(prf,aad),candidate=null,plain=null;try{candidate=open(wrapping,w.getAsJsonObject("wrapped"),aad);if(candidate.length!=32)throw new SecurityException("Invalid vault key");plain=open(candidate,envelope.getAsJsonObject("payload"),context()+"|payload");var decoded=JsonParser.parseString(new String(plain,StandardCharsets.UTF_8)).getAsJsonObject();key=candidate;candidate=null;data=decoded;try{if(syncDisplayNames())save();}catch(Exception e){close();throw e;}return;}finally{Arrays.fill(wrapping,(byte)0);if(candidate!=null)Arrays.fill(candidate,(byte)0);if(plain!=null)Arrays.fill(plain,(byte)0);}}throw new SecurityException("Passkey is not enrolled");}
 synchronized String passkeyName(String credential){String name="";if(unlocked())name=get("passkey.name."+credential);else for(var w:wrappers())if(credential.equals(w.get("credential").getAsString())&&w.has("displayName"))name=w.get("displayName").getAsString();return name.isBlank()||name.length()>80||name.codePoints().anyMatch(Character::isISOControl)?"Passkey · "+credential.substring(0,Math.min(8,credential.length())):name;}
 // Labels are only chooser hints; authenticated encrypted names remain authoritative.
 private boolean syncDisplayNames(){boolean changed=false;for(var item:envelope.getAsJsonArray("wrappers")){var w=item.getAsJsonObject();String name=get("passkey.name."+w.get("credential").getAsString());if(!name.isEmpty()&&(!w.has("displayName")||!name.equals(w.get("displayName").getAsString()))){w.addProperty("displayName",name);changed=true;}}return changed;}
 synchronized void renamePasskey(String credential,String name)throws Exception{requireUnlocked();if(wrappers().stream().noneMatch(w->credential.equals(w.get("credential").getAsString())))throw new SecurityException("Passkey is not enrolled");name=name.trim();if(name.isEmpty()||name.length()>80||name.codePoints().anyMatch(Character::isISOControl))throw new IllegalArgumentException("Use a name of 1–80 characters without control characters");var old=envelope.deepCopy();var oldData=data.deepCopy();try{data.addProperty("passkey.name."+credential,name);syncDisplayNames();save();}catch(Exception e){envelope=old;data=oldData;throw e;}}
 // Removal deletes this credential's wrapper from the current vault file.
 // It is not retroactive revocation of previously copied vault files and does
 // not delete the authenticator's discoverable credential.
 synchronized void removePasskey(String credential)throws Exception{requireUnlocked();if(wrappers().size()<=1)throw new SecurityException("Add a backup passkey before removing the last passkey");var old=envelope.deepCopy();var oldData=data.deepCopy();var kept=new JsonArray();boolean found=false;for(var w:wrappers())if(credential.equals(w.get("credential").getAsString()))found=true;else kept.add(w);if(!found)throw new SecurityException("Passkey is not enrolled");envelope.add("wrappers",kept);data.remove("passkey.name."+credential);data.remove("passkey.user."+credential);try{save();}catch(Exception e){envelope=old;data=oldData;throw e;}}
 synchronized String get(String name){requireUnlocked();return data.has(name)?data.get(name).getAsString():"";}
 synchronized void put(String name,String value)throws Exception{requireUnlocked();var old=data.deepCopy();if(value==null)data.remove(name);else data.addProperty(name,value);try{save();}catch(Exception e){data=old;throw e;}}
 private void requireUnlocked(){if(key==null)throw new IllegalStateException("Unlock the passkey vault first");}
 // Serialize and authenticate a fresh payload, fsync the replacement file,
 // then atomically replace the previous envelope. The caller rolls back its
 // in-memory mutation on failure; no plaintext vault file is written here.
 private void save()throws Exception{requireUnlocked();byte[] plain=data.toString().getBytes(StandardCharsets.UTF_8);try{var next=envelope.deepCopy();next.add("payload",seal(key,plain,context()+"|payload"));Files.createDirectories(path.getParent());Path tmp=path.resolveSibling(path.getFileName()+".tmp");try{Files.write(tmp,next.toString().getBytes(StandardCharsets.UTF_8));try(var channel=java.nio.channels.FileChannel.open(tmp,StandardOpenOption.WRITE)){channel.force(true);}Files.move(tmp,path,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);envelope=next;}finally{Files.deleteIfExists(tmp);}}finally{Arrays.fill(plain,(byte)0);}}
 // Best-effort key erasure and reference release. Java Strings and provider
 // internals are not guaranteed zeroizable, so this is not a claim that every
 // historical plaintext copy disappears immediately from the managed heap.
 public synchronized void close(){if(key!=null)Arrays.fill(key,(byte)0);key=null;data=null;}
}
