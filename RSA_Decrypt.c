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
  const char *private_key_path = “privatekey.pem”;
  
  FILE* private_key_file = fopen(private_key_path,”r”);
  if(!private_key_file)
  {
    Error();
  }
  
  RSA* rsa_private_key = PEM_read_RSAPrivateKey(private_key_file,NULL,NULL,NULL);
  if(!rsa_private_key)
  {
    Error();
  }
  
  fclose(private_key_file);
  
  FILE* cipher = fopen(“ciphertext.txt”,”r”);
  if(!cipher)
  {
    Error();
  }
  
  fseek(cipher,0,SEEK_END);
  size_t file_size = ftell(cipher);
  fseek(cipher,0,SEEK_SET);
  
  unsigned char *ciphertext = (unsigned char *)malloc(file_size);
  if(!ciphertext)
  {
    Error();
  }
  fread(ciphertext,1,file_size,cipher);
  
  fclose(cipher);
  
  unsigned char *plaintext = (unsigned char *)malloc(RSA_size(rsa_private_key));
  if(!plaintext)
  {
    Error();
  }
  
  int decypt_len = RSA_private_decrypt(file_size,ciphertext,plaintext,rsa_private_key,RSA_PKCS1_PADDING);
  if(!decrypt_len == -1)
  {
    Error();
  }
  
  FILE* out = fopen(“final_plaintext.txt”,”wb”);
  if(!out)
  {
    Error();
  }
  fwrite(plaintext,1,decrypt_len,out);
  fclose(out);
  
  free(ciphertext);
  free(plaintext);
  RSA_free(rsa_private_key);
  return 0;
}
