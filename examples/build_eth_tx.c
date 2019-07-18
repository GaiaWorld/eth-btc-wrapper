#include "../wrapper.h"
#include <stdio.h>

int main() {
    // all strings are hex string
    char* nonce = "c7";
    char* to = "14571A8f98301DB5dC5c7640A9C7f6CA5BEaB338";
    char* value = "6666";
    char* gas = "6208";
    char* gas_price = "14a817c800";
    char* priv_key = "abd952e991fb40a146291e6c537fc0db0d1b6de0a815df11efb7e73e1e50daf8";

    eth_tx_meta tx;
    tx.nonce = nonce;
    tx.to = to;
    tx.value = value;
    tx.gas = gas;
    tx.gas_price = gas_price;
    tx.priv_key = priv_key;
    tx.chain_id = 3;

    char* sig = build_signed_eth_tx(&tx);
    printf("sig: %s\n", sig);
    free_cstring(sig);
}