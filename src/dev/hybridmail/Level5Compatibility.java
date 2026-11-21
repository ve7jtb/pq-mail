package dev.hybridmail;
import static dev.hybridmail.OpenPgp.*;
import java.security.*;import java.util.*;import java.nio.file.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyConverter;
/** Level 5 account's lower-strength v4 interoperability profile; no Level 5 claim for its KEM. */
final class Level5Compatibility {
 static boolean supports(PublicIdentity own){return own.legacy==null&&(own.signing.pq()==null||(own.primary[5]&255)==31);}
 static PublicKey key(org.bouncycastle.openpgp.PGPPublicKey k)throws Exception{return new JcaPGPKeyConverter().setProvider("BC").getPublicKey(k);}
 static PublicIdentity classical(PublicIdentity full)throws Exception{return classicalOnlyCompatibility(full);}
 static byte[] signature(byte[] data,int type,byte[] primary,byte[] extra,OpenPgp.Signer signer)throws Exception{
  byte[] subs=cat(sub(2,n(now(),4)),sub(33,cat(b(4),fingerprint(primary))),extra),header=cat(b(4,type,19,9),n(subs.length,2),subs);
  byte[] digest=hash("SHA-384",cat(data,header,b(4,255),n(header.length,4))),fixed=fixed(signer.sign(digest));
  return cat(header,n(0,2),slice(digest,0,2),mpi(slice(fixed,0,48)),mpi(slice(fixed,48,96)));
 }
 static PublicIdentity create(String email,PublicKey signing,PublicKey ml,PublicKey x,PublicKey fallback,OpenPgp.Signer signer)throws Exception{
  validateEmail(email);check(raw(signing).length==97&&raw(fallback).length==97&&raw(ml).length==1184&&raw(x).length==32,"Invalid Level 5 compatibility keys");long created=now();
  byte[] primary=cat(b(4),n(created,4),b(19),P384_OID,mpi(raw(signing))),hybrid=cat(b(4),n(created,4),b(35),raw(x),raw(ml)),ec=cat(b(4),n(created,4),b(18),P384_OID,mpi(raw(fallback)),b(3,1,9,8)),uid=bytes(email);
  byte[] prefs=cat(sub(27,b(3)),sub(11,b(9,8,7)),sub(21,b(9,10,8)),sub(22,b(0)),sub(30,b(1)));
  byte[] cert=signature(cat(v4KeyHash(primary),b(0xb4),n(uid.length,4),uid),19,primary,prefs,signer);
  byte[] h=signature(cat(v4KeyHash(primary),v4KeyHash(hybrid)),24,primary,sub(27,b(12)),signer),c=signature(cat(v4KeyHash(primary),v4KeyHash(ec)),24,primary,sub(27,b(12)),signer);
  return new PublicIdentity(cat(frame(6,primary),frame(13,uid),frame(2,cert),frame(14,hybrid),frame(2,h),frame(14,ec),frame(2,c)));
 }
 static void checkPair(PublicIdentity own,PublicIdentity full)throws Exception{
  check(supports(own)&&full.version()==4&&full.primary[5]==19&&full.matchesEmail(own.email)&&full.certifiedEmails().equals(List.of(own.email.toLowerCase(Locale.ROOT))),"Invalid Level 5 compatibility primary/email");
  var classic=classical(full);check(full.quantumEncryption()&&full.subkey.length==1222&&classic.subkey[5]==18,"Expected hybrid and P-384 fallback subkeys");
  check(key(full.legacy.primary) instanceof java.security.interfaces.ECPublicKey ec&&ec.getParams().getCurve().getField().getFieldSize()==384,"Expected P-384 signing key");
  check(key(classic.legacy.recipient) instanceof java.security.interfaces.ECPublicKey ec&&ec.getParams().getCurve().getField().getFieldSize()==384,"Expected P-384 fallback key");
 }
 static void checkCard(OnKeyBundle.Card card,PublicIdentity full)throws Exception{
  var classic=classical(full);check(Arrays.equals(key(full.legacy.primary).getEncoded(),card.publicKey("88")),"P-384 compatibility signing key mismatch in 88");
  check(Arrays.equals(key(classic.legacy.recipient).getEncoded(),card.publicKey("89")),"P-384 compatibility encryption key mismatch in 89");
  check(Arrays.equals(pq(slice(full.subkey,38,full.subkey.length),false).getEncoded(),card.publicKey("84")),"ML-KEM-768 compatibility key mismatch in 84");
  check(Arrays.equals(curve25519(slice(full.subkey,6,38),false).getEncoded(),card.publicKey("85")),"X25519 compatibility key mismatch in 85");
 }
 static PublicIdentity issue(Path root,Identity id,Map<String,PublicKey> keys,ExternalMu.Backend backend)throws Exception{
  check(OpenPgp.classical(id),"Select Level 5");var own=createOwn(root,id,backend);var op=backend.newOperation();try{
   var full=create(email(id),keys.get("88"),keys.get("84"),keys.get("85"),keys.get("89"),d->op.signCompatibilityEcdsa(keys.get("88"),d));checkPair(own,full);
   Path path=ownPath(root,id);OnKeyBundle.saveCompatibility(path.resolveSibling(path.getFileName()+".v4"),full.encoded);return full;
  }finally{op.clearSecrets();}
 }
 static byte[] compose(Identity id,PublicIdentity own,PublicIdentity recipient,boolean encrypted,String from,String to,String subject,String text,ExternalMu.Backend backend)throws Exception{
        return compose(id,own,recipient,encrypted,from,to,subject,text,null,backend);
    }
    static byte[] compose(Identity id,PublicIdentity own,PublicIdentity recipient,boolean encrypted,String from,String to,String subject,String text,String html,ExternalMu.Backend backend)throws Exception{
  check(own.compatibility!=null&&backend!=null,"Create the Level 5 v4 compatibility certificates first");var full=own.compatibility;checkPair(own,full);var op=backend.newOperation();try{
   byte[] plain=withPublicCertificate(MailEngine.messageBody(text,html),full,own);
   byte[] sig=signature(plain,0,full.primary,b(),d->op.signCompatibilityEcdsa(key(full.legacy.primary),d));full.legacy.verify(frame(2,sig),plain);
   if(encrypted){byte[] fp=fingerprint(full.primary),signed=cat(frame(4,cat(b(3,0,9,19),slice(fp,12,20),b(1))),frame(11,cat(b(98,0),n(0,4),plain)),frame(2,sig));return mimeWrap(bytes("Content-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n"),cat(bytes("Content-Type: application/octet-stream\r\n\r\n"),armor(encrypt(signed,recipient),"MESSAGE")),true,from,to,subject);}
   return mimeWrap(plain,cat(bytes("Content-Type: application/pgp-signature; name=\"signature.asc\"\r\nContent-Disposition: attachment; filename=\"signature.asc\"\r\n\r\n"),armor(frame(2,sig),"SIGNATURE")),false,from,to,subject);
  }finally{op.clearSecrets();}
 }
 static byte[] decrypt(byte[] encoded,PublicIdentity own,ExternalKem.Backend backend)throws Exception{
  check(own.compatibility!=null&&backend!=null,"Restore Level 5 compatibility certificates and select its YubiKey");var full=own.compatibility;checkPair(own,full);var packets=packets(encoded);check(packets.stream().map(Packet::tag).toList().equals(List.of(1,18)),"Expected one recipient and protected payload");
  // Parse and match the complete v6 fingerprint (or v3 key ID) before
  // starting an operation. Level 5 compatibility uses its dedicated ML-KEM-768
  // and X25519 slots, not the account's main Level 5 KEM components.
  var recipient=v4Recipient(packets.get(0).body());int alg=recipient.algorithm();
  check(alg==35||alg==18&&recipient.version()==3,"Unsupported compatibility encryption");
  var selected=alg==35?full:classical(full);recipient.requireKey(selected.subkey,alg);var r=recipient.data();
  HybridSession hybrid=alg==35?hybridSession(recipient):null;
  var op=backend.newOperation();byte[] secret=null,ml=null,kek=null,session=null;try{int cipher;
   if(alg==35){byte[] point=slice(hybrid.ciphertext(),0,32),ct=slice(hybrid.ciphertext(),32,1120);cipher=hybrid.cipher();byte[] wrapped=hybrid.wrapped();var x=curve25519(slice(full.subkey,6,38),false);secret=op.deriveLevel5Compatibility(x,curve25519(point,false));ml=op.decapsulateLevel5Compatibility(pq(slice(full.subkey,38,full.subkey.length),false),ct);kek=combine(ml,secret,point,raw(x));session=wrap(false,kek,wrapped);
   }else{byte[] point=mpi(r,776),wrapped=r.take(r.one());check(r.left()==0,"Trailing ECDH data");var pub=key(selected.legacy.recipient);secret=op.deriveLevel5Compatibility(pub,ec(point));kek=ecKdf(secret,selected.subkey);session=wrap(false,kek,wrapped);check(session.length>3,"Short session key");int pad=session[session.length-1]&255;check(pad>0&&pad<=40&&session.length>pad+3,"Invalid padding");for(int i=session.length-pad;i<session.length;i++)check((session[i]&255)==pad,"Invalid padding");int end=session.length-pad;cipher=session[0]&255;int sum=0;for(int i=1;i<end-2;i++)sum+=session[i]&255;check((sum&65535)==((session[end-2]&255)*256+(session[end-1]&255)),"Session checksum mismatch");byte[] raw=slice(session,1,end-2);wipe(session);session=raw;}
   check(List.of(7,8,9).contains(cipher)&&session.length==(cipher==7?16:cipher==8?24:32),"Invalid session key");var list=(org.bouncycastle.openpgp.PGPEncryptedDataList)LegacyOpenPgp.objects(encoded).nextObject();var data=list.extractSessionKeyEncryptedData();check(data.isIntegrityProtected(),"Unprotected message");byte[] plain=LegacyOpenPgp.bounded(data.getDataStream(new org.bouncycastle.openpgp.operator.jcajce.JceSessionKeyDataDecryptorFactoryBuilder().setProvider("BC").build(new org.bouncycastle.openpgp.PGPSessionKey(cipher,session))));check(data.verify(),"Message integrity failed");return plain;
  }finally{wipe(secret);wipe(ml);wipe(kek);wipe(session);op.clearSecrets();}
 }
}
