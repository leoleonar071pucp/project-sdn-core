#include <string.h>
#include <stdint.h>
#include "bloom.h"

static uint32_t fnv1a_hash(const uint8_t *data, size_t len, uint32_t seed)
{
    uint32_t hash = seed;
    for (size_t i = 0; i < len; i++) {
        hash ^= data[i];
        hash *= 16777619U;
    }
    return hash;
}

void bloom_init(bloom_filter_t *bf)
{
    memset(bf->data, 0, BLOOM_BYTES);
}

void bloom_insert(bloom_filter_t *bf, uint16_t port)
{
    uint8_t data[2];
    data[0] = (uint8_t)(port >> 8);
    data[1] = (uint8_t)(port & 0xff);

    for (uint32_t seed = 0; seed < 4; seed++) {
        uint32_t hash = fnv1a_hash(data, sizeof(data), seed);
        uint32_t bit = hash % BLOOM_BITS;
        bf->data[bit >> 3] |= (uint8_t)(1u << (bit & 7));
    }
}

int bloom_test(const bloom_filter_t *bf, uint16_t port)
{
    uint8_t data[2];
    data[0] = (uint8_t)(port >> 8);
    data[1] = (uint8_t)(port & 0xff);

    for (uint32_t seed = 0; seed < 4; seed++) {
        uint32_t hash = fnv1a_hash(data, sizeof(data), seed);
        uint32_t bit = hash % BLOOM_BITS;
        if (!(bf->data[bit >> 3] & (uint8_t)(1u << (bit & 7)))) {
            return 0;
        }
    }
    return 1;
}

int bloom_count_bits(const bloom_filter_t *bf)
{
    int count = 0;
    for (size_t i = 0; i < BLOOM_BYTES; i++) {
        uint8_t v = bf->data[i];
        for (int b = 0; b < 8; b++) {
            count += (v >> b) & 1;
        }
    }
    return count;
}
