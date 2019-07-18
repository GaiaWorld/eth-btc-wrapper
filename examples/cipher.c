#include "../wrapper.h"

int main() {
    char key[16] = {1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
    char plain_text[8] = {2,2,2,2,2,2,2,2};

    char* cipher_text = encrypt(key, plain_text, 8);
    // 8 bytes nonce, 16 bytes key
    char* decrypted = decrypt(key, cipher_text, 8 + 16 + 8);

    // plain text length is equal to cipher text
    for(int i = 0; i < 8; i++) {
        printf("%d", decrypted[i]);
    }
    printf("\n");

    // deallocate memroy alloced from rust
    dealloc_rust_buffer(decrypted, 8 + 16 + 8);
    dealloc_rust_buffer(cipher_text, 8 + 16 + 8);
}