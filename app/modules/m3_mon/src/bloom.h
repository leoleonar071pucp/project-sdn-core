#ifndef BLOOM_H
#define BLOOM_H

#include <stdint.h>

#define BLOOM_BITS 2048
#define BLOOM_BYTES (BLOOM_BITS / 8)

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint8_t data[BLOOM_BYTES];
} bloom_filter_t;

void bloom_init(bloom_filter_t *bf);
void bloom_insert(bloom_filter_t *bf, uint16_t port);
int bloom_test(const bloom_filter_t *bf, uint16_t port);
int bloom_count_bits(const bloom_filter_t *bf);

#ifdef __cplusplus
}
#endif

#endif // BLOOM_H
