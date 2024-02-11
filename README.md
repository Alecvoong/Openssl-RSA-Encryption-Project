Created 3 blank text files (1 for plaintext, 1 for ciphertext, 1 for output plaintext)

- Used (openssl genrsa -out privatekey.pem 2048) to create private key into privatekey.pem file
- Used (openssl rsa -in privatekey.pem -outform PEM -pubout -out publickey.pem) to create public key into privatekey.pem file

After creating the 2 C programs,
1. run the command gcc -o rsa_encrypt RSA_Encrypt.c -lssl -lcrypto then ./rsa_encrypt to encrypt the file. 
2. Run the command gcc -o rsa_decrypt RSA_Decrypt.c -lssl -lcrypto then ./rsa_decrypt to decrypt the file.
