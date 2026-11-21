/* Single-process PKCS#11 public-key check + signature. No persistent session or PIN cache.
 * Usage: helper ALGORITHM pkcs11:serial=...;id=%XX;type= expected.der input.bin signature.bin
 * PIN is a single stdin line, read only after checking the live public key.
 * OPENSSL_CONF selects the existing OpenSSL provider and Yubico module. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif
#include <openssl/evp.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <openssl/err.h>

/* Opt-in phase durations only: never PINs, keys, messages, or APDU data. */
static void timing(const char *phase) {
    static double previous;
    if(!getenv("PQMAIL_SIGN_TIMINGS"))return;
#ifdef _WIN32
    LARGE_INTEGER counter,frequency;
    if(!QueryPerformanceFrequency(&frequency)||!QueryPerformanceCounter(&counter))return;
    double now=(double)counter.QuadPart/frequency.QuadPart;
#else
    struct timespec ts;if(clock_gettime(CLOCK_MONOTONIC,&ts))return;
    double now=ts.tv_sec+ts.tv_nsec/1e9;
#endif
    if(previous)fprintf(stderr,"PQMAIL_PHASE %s %.3f ms\n",phase,(now-previous)*1000);
    previous=now;
}
static int use_pin_callback(void) {
    /* Our patched provider otherwise opens its own terminal PIN prompt.
       This is a mode flag only; the PIN remains in this process/anonymous pipe. */
#ifdef _WIN32
    return _putenv_s("HYBRID_MAIL_PIN_STDIN","1")==0;
#else
    return setenv("HYBRID_MAIL_PIN_STDIN","1",1)==0;
#endif
}
struct secret { char pin[10]; int ready; unsigned int callbacks; };
static int pin_reader(UI *ui, UI_STRING *s) {
    struct secret *p = UI_get0_user_data(ui);
    if (!p || !p->ready || UI_get_string_type(s) != UIT_PROMPT) return 0;
    p->callbacks++;
    return UI_set_result(ui, s, p->pin) >= 0 ? 1 : 0;
}
static size_t read_file(const char *name, unsigned char *out, size_t cap) {
    FILE *f=fopen(name,"rb"); if(!f)return 0;
    size_t n=fread(out,1,cap,f); int extra=fgetc(f); int bad=ferror(f); fclose(f);
    return extra==EOF && !bad ? n : 0;
}
static EVP_PKEY *load_key(const char *uri, int type, UI_METHOD *ui, struct secret *pin) {
    OSSL_STORE_CTX *s=OSSL_STORE_open_ex(uri,NULL,"provider=pkcs11",ui,pin,NULL,NULL,NULL);
    EVP_PKEY *key=NULL; if(!s)return NULL;
    if(OSSL_STORE_expect(s,type)!=1)goto done;
    while(!OSSL_STORE_eof(s)) {
        OSSL_STORE_INFO *info=OSSL_STORE_load(s);
        if(!info)break;
        if(OSSL_STORE_INFO_get_type(info)==type) {
            key=type==OSSL_STORE_INFO_PUBKEY?OSSL_STORE_INFO_get1_PUBKEY(info):OSSL_STORE_INFO_get1_PKEY(info);
            OSSL_STORE_INFO_free(info);break;
        }
        OSSL_STORE_INFO_free(info);
    }
 done: OSSL_STORE_close(s);return key;
}
static int matches(EVP_PKEY *token, EVP_PKEY *expected) {
    /* Export only public material, then compare with the default provider.
       This also tolerates equivalent RSA AlgorithmIdentifier encodings. */
    unsigned char *der=NULL;int n=i2d_PUBKEY(token,&der);if(n<=0)return 0;
    const unsigned char *cursor=der;EVP_PKEY *plain=d2i_PUBKEY_ex(NULL,&cursor,n,NULL,"provider=default");
    int ok=plain && EVP_PKEY_eq(plain,expected)==1;EVP_PKEY_free(plain);OPENSSL_free(der);return ok;
}
static int configure(EVP_PKEY_CTX *ctx,const char *alg) {
    if(!strncmp(alg,"ML-DSA-",7))return EVP_PKEY_CTX_ctrl_str(ctx,"mu","1")>0;
    if(!strcmp(alg,"ECDSA-P384-SHA384"))return EVP_PKEY_CTX_ctrl_str(ctx,"digest","sha384")>0;
    if(!strcmp(alg,"ECDSA-P256-SHA256"))return EVP_PKEY_CTX_ctrl_str(ctx,"digest","sha256")>0;
    if(!strcmp(alg,"RSA3072-PSS-SHA256"))return EVP_PKEY_CTX_ctrl_str(ctx,"digest","sha256")>0 && EVP_PKEY_CTX_ctrl_str(ctx,"rsa_padding_mode","pss")>0 && EVP_PKEY_CTX_ctrl_str(ctx,"rsa_pss_saltlen","32")>0 && EVP_PKEY_CTX_ctrl_str(ctx,"rsa_mgf1_md","sha256")>0;
    return 0;
}
/* ML-DSA's default provider uses the message/digest entry points, unlike
 * pkcs11-provider's raw external-mu signing entry point. mu=1 prevents hashing
 * the already-computed 64-byte representative a second time. */
static int verify_signature(EVP_PKEY *key, const char *alg,
        const unsigned char *input, size_t inlen,
        const unsigned char *sig, size_t siglen) {
    int ok=0;
    if(!strcmp(alg,"Ed25519") || !strncmp(alg,"ML-DSA-",7)) {
        EVP_MD_CTX *md=EVP_MD_CTX_new();
        int mu=1;
        OSSL_PARAM params[]={OSSL_PARAM_construct_int("mu",&mu),OSSL_PARAM_construct_end()};
        if(md && EVP_DigestVerifyInit_ex(md,NULL,NULL,NULL,"provider=default",key,
                !strncmp(alg,"ML-DSA-",7)?params:NULL)==1)
            ok=EVP_DigestVerify(md,sig,siglen,input,inlen)==1;
        EVP_MD_CTX_free(md);
    } else {
        EVP_PKEY_CTX *ctx=EVP_PKEY_CTX_new_from_pkey(NULL,key,"provider=default");
        if(ctx && EVP_PKEY_verify_init(ctx)>0 && configure(ctx,alg))
            ok=EVP_PKEY_verify(ctx,sig,siglen,input,inlen)>0;
        EVP_PKEY_CTX_free(ctx);
    }
    return ok;
}
/* Validate the protocol input before any PIN or provider operation. Ed25519
 * signs the supplied OpenPGP digest as a raw message, so SHA-256/SHA-384/SHA-512
 * lengths are all valid. ML-DSA retains its fixed 64-byte external-mu input. */
static int valid_input_length(const char *alg, size_t length) {
    if(!strcmp(alg,"Ed25519"))return length==32 || length==48 || length==64;
    if(!strncmp(alg,"ML-DSA-",7))return length==64;
    if(!strcmp(alg,"ECDSA-P384-SHA384"))return length==48;
    return length==32;
}
int main(int argc,char **argv) {
    timing("start");
    int rc=1,ed=0;const char *stage="arguments";struct secret pin={{0},0,0};
    unsigned char der[8192],input[64],signature[8192];size_t n=0,len=sizeof(signature);
    EVP_PKEY *expected=NULL,*pub=NULL,*priv=NULL;EVP_PKEY_CTX *ctx=NULL;
    EVP_MD_CTX *md=NULL;UI_METHOD *ui=NULL;OSSL_PROVIDER *def=NULL,*p11=NULL;
    char public_uri[256],private_uri[256];
    if(argc!=6 || strncmp(argv[2],"pkcs11:serial=",14) || strlen(argv[2])>220)goto done;
    const char *alg=argv[1];
    if(strcmp(alg,"ML-DSA-44") && strcmp(alg,"ML-DSA-65") && strcmp(alg,"ML-DSA-87") && strcmp(alg,"Ed25519") && strcmp(alg,"ECDSA-P256-SHA256") && strcmp(alg,"ECDSA-P384-SHA384") && strcmp(alg,"RSA3072-PSS-SHA256"))goto done;
    snprintf(public_uri,sizeof(public_uri),"%spublic",argv[2]);snprintf(private_uri,sizeof(private_uri),"%sprivate",argv[2]);
    stage="input";n=read_file(argv[3],der,sizeof(der));size_t inlen=read_file(argv[4],input,sizeof(input));if(!n || !inlen)goto done;
    ed=!strcmp(alg,"Ed25519");
    if(!valid_input_length(alg,inlen))goto done;
    timing("input");
    stage="PIN callback setup";if(!use_pin_callback())goto done;
    stage="providers";def=OSSL_PROVIDER_load(NULL,"default");p11=OSSL_PROVIDER_load(NULL,"pkcs11");if(!def||!p11)goto done;
    timing("provider-load");
    const unsigned char *cursor=der;expected=d2i_PUBKEY_ex(NULL,&cursor,n,NULL,"provider=default");if(!expected||cursor!=der+n)goto done;
    const char *type=ed?"ED25519":!strncmp(alg,"ML-DSA-",7)?alg:!strncmp(alg,"ECDSA-",6)?"EC":"RSA";
    if(!EVP_PKEY_is_a(expected,type))goto done;
    if(!strncmp(alg,"ECDSA-",6) && EVP_PKEY_get_bits(expected)!=(!strcmp(alg,"ECDSA-P384-SHA384")?384:256))goto done;
    if(!strcmp(type,"RSA") && EVP_PKEY_get_bits(expected)!=3072)goto done;
    ui=UI_create_method("PQ Mail private PIN pipe");if(!ui||UI_method_set_reader(ui,pin_reader)!=0)goto done;
    timing("expected-key-decode");
    stage="public key check";pub=load_key(public_uri,OSSL_STORE_INFO_PUBKEY,ui,&pin);if(!pub||!matches(pub,expected))goto done;
    timing("public-key-check");
    stage="PIN input";if(!fgets(pin.pin,sizeof(pin.pin),stdin))goto done;
    n=strlen(pin.pin);if(n<7||n>9||pin.pin[n-1]!='\n')goto done;pin.pin[--n]=0;
    for(size_t i=0;i<n;i++)if((unsigned char)pin.pin[i]<32||(unsigned char)pin.pin[i]>126)goto done;
    pin.ready=1;
    timing("pin-input");
    stage="private key check";priv=load_key(private_uri,OSSL_STORE_INFO_PKEY,ui,&pin);if(!priv||!matches(priv,expected))goto done;
    timing("private-key-check");
    ERR_clear_error();stage="sign initialization";
    if(ed) {
        md=EVP_MD_CTX_new();if(!md||EVP_DigestSignInit_ex(md,NULL,NULL,NULL,"provider=pkcs11",priv,NULL)!=1||EVP_DigestSign(md,signature,&len,input,inlen)!=1)goto done;
    } else {
        ctx=EVP_PKEY_CTX_new_from_pkey(NULL,priv,"provider=pkcs11");if(!ctx||EVP_PKEY_sign_init(ctx)<=0)goto done;
        stage="sign parameters";if(!configure(ctx,alg))goto done;
        stage="sign";if(EVP_PKEY_sign(ctx,signature,&len,input,inlen)<=0)goto done;
    }
    timing("sign");
    stage="verify";
    if(!verify_signature(expected,alg,input,inlen,signature,len))goto done;
    timing("verify");
    stage="output";FILE *f=fopen(argv[5],"wb");if(!f)goto done;size_t written=fwrite(signature,1,len,f);int closed=fclose(f);if(written!=len||closed)goto done;
    timing("output");
    rc=0;
 done:
    timing("before-cleanup");
    if(rc){
        fprintf(stderr,"PQ Mail single-session signer failed at %s; no retry\n",stage);
        /* Only public error codes and fixed library reason strings; never error data. */
        unsigned long error;unsigned count=0;
        while((error=ERR_get_error()) && count++<8){
            const char *reason=ERR_reason_error_string(error);
            fprintf(stderr,"PQMAIL_ERROR %08lX %s\n",error,reason?reason:"unknown");
        }
        fprintf(stderr,"PQMAIL_PIN_CALLBACKS %u\n",pin.callbacks);
    }
    if(getenv("PQMAIL_SIGN_TIMINGS"))fprintf(stderr,"PQMAIL_PIN_CALLBACKS %u\n",pin.callbacks);
    OPENSSL_cleanse(&pin,sizeof(pin));EVP_MD_CTX_free(md);EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pub);EVP_PKEY_free(priv);EVP_PKEY_free(expected);UI_destroy_method(ui);OSSL_PROVIDER_unload(p11);OSSL_PROVIDER_unload(def);OPENSSL_cleanup();timing("cleanup");return rc;
}
