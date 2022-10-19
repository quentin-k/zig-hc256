#include <stdio.h>
#include <time.h>
#include "hc256_opt32.h"

int main() {
    HC256_State state;
    uint8 key[32], iv[32];
    for (int i = 0; i < 32; ++i) {
        key[i] = 0;
        iv[i] = 0;
    }
    Initialization(&state, key, iv);
    clock_t start = clock();
    for (unsigned long i = 0; i < (0x4000000 * 2); ++i) {
        SixteenSteps(&state);
    }
    clock_t end = clock();

    printf("Time to generate words: %4.4fs\nWords: ", (double)(end - start)/CLOCKS_PER_SEC);

    uint8* keystream = (uint8 *)state.keystream;
    for (int i = 0; i < 64; ++i)
        printf("%02x", keystream[i]);
    printf("\n");
    return 0;
}
