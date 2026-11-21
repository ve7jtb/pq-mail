/* Exercise the exact production verifier with software keys only. */
#define main helper_main
#include "../native-src/pkcs11-sign.c"
#undef main
#include <assert.h>
#include <openssl/err.h>
static EVP_PKEY *generate(const char *type, const char *group) {
 EVP_PKEY_CTX *c=EVP_PKEY_CTX_new_from_name(NULL,type,"provider=default");EVP_PKEY *k=NULL;
 assert(c && EVP_PKEY_keygen_init(c)>0);
 if(group)assert(EVP_PKEY_CTX_set_group_name(c,group)>0);
 if(!strcmp(type,"RSA"))assert(EVP_PKEY_CTX_set_rsa_keygen_bits(c,3072)>0);
 assert(EVP_PKEY_generate(c,&k)>0);EVP_PKEY_CTX_free(c);return k;
}
static void test(const char *alg,const char *type,const char *group,size_t inlen) {
 EVP_PKEY *key=generate(type,group),*wrong=generate(type,group);
 unsigned char input[64],sig[8192];size_t n=sizeof(sig);for(size_t i=0;i<sizeof(input);i++)input[i]=(unsigned char)i;
 if(!strncmp(alg,"ML-DSA-",7)||!strcmp(alg,"Ed25519")) {
  EVP_MD_CTX *m=EVP_MD_CTX_new();int mu=1;
  OSSL_PARAM params[]={OSSL_PARAM_construct_int("mu",&mu),OSSL_PARAM_construct_end()};
  assert(EVP_DigestSignInit_ex(m,NULL,NULL,NULL,"provider=default",key,!strncmp(alg,"ML-DSA-",7)?params:NULL)==1);
  assert(EVP_DigestSign(m,sig,&n,input,inlen)==1);EVP_MD_CTX_free(m);
 } else {
  EVP_PKEY_CTX *c=EVP_PKEY_CTX_new_from_pkey(NULL,key,"provider=default");assert(c && EVP_PKEY_sign_init(c)>0 && configure(c,alg));assert(EVP_PKEY_sign(c,sig,&n,input,inlen)>0);EVP_PKEY_CTX_free(c);
 }
 if(!strncmp(alg,"ML-DSA-",7)) {
  EVP_PKEY_CTX *old=EVP_PKEY_CTX_new_from_pkey(NULL,key,"provider=default");int result=EVP_PKEY_verify_init(old);
  printf("%s original verify_init result: %d\n",alg,result);assert(result<=0);EVP_PKEY_CTX_free(old);ERR_clear_error();
 }
 assert(verify_signature(key,alg,input,inlen,sig,n));
 sig[0]^=1;assert(!verify_signature(key,alg,input,inlen,sig,n));sig[0]^=1;
 input[0]^=1;assert(!verify_signature(key,alg,input,inlen,sig,n));input[0]^=1;
 assert(!verify_signature(wrong,alg,input,inlen,sig,n));
 assert(!verify_signature(key,alg,input,inlen,sig,n-1));
 printf("PASS %s: valid signature; altered signature/input, wrong key and truncation rejected\n",alg);
 EVP_PKEY_free(key);EVP_PKEY_free(wrong);ERR_clear_error();
}
static void test_pin_callback(void) {
#ifdef _WIN32
 _putenv_s("HYBRID_MAIL_PIN_STDIN","");
#else
 unsetenv("HYBRID_MAIL_PIN_STDIN");
#endif
 assert(use_pin_callback());
 assert(!strcmp(getenv("HYBRID_MAIL_PIN_STDIN"),"1"));
#ifdef _WIN32
 _putenv_s("HYBRID_MAIL_PIN_STDIN","0");
#else
 setenv("HYBRID_MAIL_PIN_STDIN","0",1);
#endif
 assert(use_pin_callback());
 assert(!strcmp(getenv("HYBRID_MAIL_PIN_STDIN"),"1"));
 UI_METHOD *method=UI_create_method("Test private callback");assert(method);
 assert(UI_method_set_reader(method,pin_reader)==0);
 struct secret data={{0},0,0};char received[10]={0};
 UI *ui=UI_new_method(method);assert(ui);UI_add_user_data(ui,&data);
 assert(UI_add_input_string(ui,"PIN",0,received,6,8)>0);
 assert(UI_process(ui)!=0);assert(data.callbacks==0);UI_free(ui);
 /* Synthetic PIN used only with OpenSSL UI; no provider/token involved. */
 memcpy(data.pin,"123456",7);data.ready=1;
 ui=UI_new_method(method);assert(ui);UI_add_user_data(ui,&data);
 assert(UI_add_input_string(ui,"PIN",0,received,6,8)>0);
 assert(UI_process(ui)==0);assert(data.callbacks==1);assert(!strcmp(received,data.pin));
 UI_free(ui);UI_destroy_method(method);OPENSSL_cleanse(&data,sizeof(data));OPENSSL_cleanse(received,sizeof(received));
 puts("PASS PIN callback mode, inherited-mode override, fail-closed readiness and UI delivery; no hardware used.");
}
int main(void) {
 /* Exercise the production request gate as well as software signatures. */
 assert(valid_input_length("Ed25519",32));assert(valid_input_length("Ed25519",48));assert(valid_input_length("Ed25519",64));
 assert(!valid_input_length("Ed25519",31));assert(!valid_input_length("Ed25519",65));
 assert(!valid_input_length("ML-DSA-65",32));assert(valid_input_length("ML-DSA-65",64));
 test_pin_callback();
 assert(OSSL_PROVIDER_load(NULL,"default"));
 test("ML-DSA-44","ML-DSA-44",NULL,64);test("ML-DSA-65","ML-DSA-65",NULL,64);test("ML-DSA-87","ML-DSA-87",NULL,64);
 test("Ed25519","ED25519",NULL,32);test("Ed25519","ED25519",NULL,48);test("Ed25519","ED25519",NULL,64);
 test("ECDSA-P256-SHA256","EC","prime256v1",32);test("ECDSA-P384-SHA384","EC","secp384r1",48);
 test("RSA3072-PSS-SHA256","RSA",NULL,32);
 puts("PASS 45 verification assertions and 7 request-length checks; no hardware used.");return 0;
}
