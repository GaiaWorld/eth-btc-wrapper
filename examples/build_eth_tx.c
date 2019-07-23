#include "../wrapper.h"
#include <stdio.h>

int main() {
    // all strings are hex string
    char* nonce = "c9";
    char* to = "14571A8f98301DB5dC5c7640A9C7f6CA5BEaB338";
    char* value = "6666";
    char* gas = "6208";
    char* gas_price = "14a817c800";
    char* priv_key = "abd952e991fb40a146291e6c537fc0db0d1b6de0a815df11efb7e73e1e50daf8";
    char* data = "12345678";

    int chain_id = 3;

    // 接收交易哈希的指針
    char *tx_hash;
    // 接收原始交易的指針
    char *raw_tx;

    int res = eth_sign_raw_transaction(chain_id, nonce, to, value, gas, gas_price, data, priv_key, &tx_hash, &raw_tx);
    printf("tx_hash: %s\n", tx_hash);
    printf("raw_tx: %s\n", raw_tx);

    // 釋放 rust 分配的内存
    dealloc_rust_cstring(tx_hash);
    dealloc_rust_cstring(raw_tx);
}