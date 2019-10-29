#pragma once

#define rc4_decrypt_ALL rc4_crypt_ALL
#define rc4_encrypt_ALL rc4_crypt_ALL

void rc4_crypt_ALL(unsigned char *key, unsigned int keylen, const unsigned char *src, unsigned char* dest, unsigned int bufsize);