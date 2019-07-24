#include "../wrapper.h"
#include <stdio.h>

int main() {
    char* address = "moDaczM8zMvxvM2GEQ5PC4o8S2iYhN1zZC";
    char* priv_key = "cRVuQd8qSuSRifRverDNAKmBGgDNDu55mV2gtyoBFT4gwHeuJFQ4";
    char* input = "b59e6f24e6fcf4d8a396a8b9f92ccf83d242cc6ce3295ae024f8d58627f30cc5:0";
    char* output = "76a91402245e1265ca65f5ab6d70289f7bcfed6204810588ac:1000000;76a9145477d7bfe9bdf17cea9f5b2ecacc7a2577723c7488ac:80233807";

    char* tx_hash;
    char* raw_tx;

    btc_build_raw_transaction_from_single_address(address, priv_key, input, output, &raw_tx, &tx_hash);

    printf("tx_hash: %s\n", tx_hash);
    printf("raw_tx: %s\n", raw_tx);

    dealloc_rust_cstring(tx_hash);
    dealloc_rust_cstring(raw_tx);
}