/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright 2026 the ScarletNX contributors */
/* What the RomFS format fixes, for the code that makes an image: the hash of its tables and their bucket count */
#ifndef SNX_ROMFS_H
#define SNX_ROMFS_H

#include <stddef.h>
#include <stdint.h>

/* the bucket hash of an entry named name in the directory at table offset parent. The format fixes both the seed (the
   parent's offset xor 123456789) and the step (rotate right by 5, then xor in the next byte): the game's own tables
   were built with it. The name's bytes count unsigned */
static inline uint32_t snx_romfs_hash(uint32_t parent, const char* name, size_t size) {
    uint32_t h = parent ^ 123456789u;
    for (size_t i = 0; i < size; i++) h = ((h >> 5) | (h << 27)) ^ (unsigned char)name[i];
    return h;
}
/* the buckets of a hash table for n entries */
static inline uint32_t snx_romfs_buckets(uint32_t n) {
    uint32_t c = n;
    if (n < 3) return 3;
    if (n < 19) return n | 1;
    while (c % 2 == 0 || c % 3 == 0 || c % 5 == 0 || c % 7 == 0 || c % 11 == 0 || c % 13 == 0 || c % 17 == 0) c++;
    return c;
}

#endif
