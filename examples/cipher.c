#include "../wrapper.h"
#include <stdio.h>

int main() {
    char* key = "b058d2931f46abb2a6062abcddf61d75";
    char* nonce = "ed77b0e43daccec06c41f472";
    char* aad = "a7e0f8";
    char* plain_text = "6162";

    char* encrypted;
    char* decrypted_plain_text;

    rust_encrypt(key, nonce, aad, plain_text, &encrypted);
    rust_decrypt(key, nonce, aad, encrypted, &decrypted_plain_text);

    printf("encrypted: %s\n", encrypted);
    printf("decrypted_plain_text: %s\n", decrypted_plain_text);

    dealloc_rust_cstring(encrypted);
    dealloc_rust_cstring(decrypted_plain_text);
}