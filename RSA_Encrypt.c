#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

void Error()
{
  ERR_print_errors_fp(stderr);
  exit(1);
}

int main()
{
  const char *public_key_path = “publickey.pem”;

  FILE* public_key_file = fopen(public_key_path,”r”);
  if(!public_key_file)
  {
    Error();
  }
  
  RSA* rsa_public_key = PEM_read_RSA_PUBKEY(public_key_file,NULL,NULL,NULL);
  if(!rsa_public_key)
  {
    Error();
  }
  
  fclose(public_key_file);
  
  FILE* message;
  message = fopen(“plaintext.txt”,”r”);
  if(!message)
  {
    Error();
  }
  
  fseek(message,0,SEEK_END);
  size_t file_size = ftell(message);
  fseek(message,0,SEEK_SET);
  
  unsigned char *plaintext = (unsigned char *)malloc(file_size);
  if(!plaintext)
  {
    Error();
  }
  fread(plaintext,1,file_size,message);
  
  fclose(message);
  
  unsigned char *ciphertext = (unsigned char *)malloc(RSA_size(rsa_public_key));
  if(!ciphertext)
  {
    Error();
  }
  
  int encypt_len = RSA_public_encrypt(file_size,plaintext,ciphertext,rsa_public_key,RSA_PKCS1_PADDING);
  if(!encrypt_len == -1)
  {
    Error();
  }
  
  FILE* out = fopen(“ciphertext.txt”,”wb”);
  if(!out)
  {
    Error();
  }
  fwrite(ciphertext,1,encrypt_len,out);
  fclose(out);
  
  free(plaintext);
  free(ciphertext);
  RSA_free(rsa_public_key);
  return 0;
}
