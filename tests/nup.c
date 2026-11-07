/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright 2026 the ScarletNX contributors */
/* The NUP reader (src/nx/runtime/driver/nup.c) on containers this test builds: how updates layer over a base, in one
   file and in two, the RomFS image it makes up as the game's own code walks one, reads of files raw, cached and
   streamed, and that each kind of damage is refused before anything is trusted. No game's files */
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zstd.h>
#include "common/utilities/common.h"
#include "common/utilities/endian.h"
#include "common/utilities/romfs.h"
#include "nx/runtime/driver/container.h"
#include "nx/runtime/driver/nup.h"

#define TITLE 0x0400000000AB0000ull
#define DLC_TITLE 0x0400000000AB1001ull
#define DLC_OTHER 0x0400000000AB1002ull
#define FOLDER "nup_test_files"
#define EXEFS FOLDER "/exefs"
#define ROMFS FOLDER "/romfs"
#define BIG_SIZE ((size_t)3 << 20) /* over the reader's chunks, so zstd has output waiting when its input ends */
#define BYTES_MAX (1 << 16)
enum { CHILDREN_MAX = 8, NODES_MAX = 32, PACKAGES_MAX = 4, KIND_BASE = 0, KIND_UPDATE = 1, KIND_ADDON = 2 };

static void check(int good, const char* expression, int line) {
    if (good) return;
    fprintf(stderr, "nup.c:%d: check failed: %s\n", line, expression);
    exit(90);
}
#define CHECK(value) check((value) != 0, #value, __LINE__)

/* a tree as the test writes it: a directory's children are node numbers, added sorted by name */
typedef struct {
    const char* name;
    int dir, zstd;
    const void* content;
    size_t size;
    int children[CHILDREN_MAX], count;
    SnxU32 id; /* its node ID in the built file */
} Node;
typedef struct {
    int root, exefs, romfs; /* -1 for none, but root */
    unsigned version, kind;
    SnxU64 title; /* 0 for TITLE */
    const char* name; /* its title name record, NULL for no meta block */
} Package;
typedef struct {
    Node nodes[NODES_MAX];
    int count;
    Package packages[PACKAGES_MAX];
    unsigned npackages;
} Spec;
/* the built file, and where its parts are for the tests that damage them */
typedef struct {
    unsigned char bytes[BYTES_MAX];
    size_t size, toc, toc_size, dirs, files, slots, pool;
    SnxU32 ndirs;
} Built;

static void sha(unsigned char* out, const void* data, size_t size) {
    unsigned n = 0;
    CHECK(EVP_Digest(data, size, out, &n, EVP_sha256(), NULL) && n == 32);
}
static int node_add(Spec* spec, const char* name, int dir, const void* content, size_t size, int zstd) {
    Node* node = &spec->nodes[spec->count];
    CHECK(spec->count < NODES_MAX);
    *node = (Node){0};
    node->name = name;
    node->dir = dir;
    node->content = content;
    node->size = size;
    node->zstd = zstd;
    return spec->count++;
}
static int dir_add(Spec* spec, int parent, const char* name) {
    int node = node_add(spec, name, 1, NULL, 0, 0);
    if (parent >= 0) spec->nodes[parent].children[spec->nodes[parent].count++] = node;
    return node;
}
static void file_add(Spec* spec, int parent, const char* name, const void* content, size_t size, int zstd) {
    int node = node_add(spec, name, 0, content, size, zstd);
    spec->nodes[parent].children[spec->nodes[parent].count++] = node;
}
static void text_add(Spec* spec, int parent, const char* name, const char* text, int zstd) {
    file_add(spec, parent, name, text, strlen(text), zstd);
}
/* a package's root, with its exefs and romfs folders as given */
static Package* package_add(Spec* spec, unsigned kind, unsigned version) {
    Package* package = &spec->packages[spec->npackages++];
    package->kind = kind;
    package->version = version;
    package->root = dir_add(spec, -1, "");
    package->exefs = dir_add(spec, package->root, "exefs");
    package->romfs = dir_add(spec, package->root, "romfs");
    return package;
}

static void toc_seal(Built* built) { sha(built->bytes + 0x18, built->bytes + built->toc, built->toc_size); }

/* spec as SPEC.md lays it out */
static void build(const Spec* source, Built* built) {
    static Spec spec;
    size_t ndirs = 0, nfiles = 0, nslots = 0, pool_size = 0, at;
    spec = *source;
    memset(built, 0, sizeof *built);
    for (int i = 0; i < spec.count; ++i)
        if (spec.nodes[i].dir) {
            spec.nodes[i].id = (SnxU32)ndirs++;
            nslots += (size_t)spec.nodes[i].count;
        }
    for (int i = 0; i < spec.count; ++i) {
        if (!spec.nodes[i].dir) spec.nodes[i].id = (SnxU32)(ndirs + nfiles++);
        pool_size += strlen(spec.nodes[i].name);
    }
    built->ndirs = (SnxU32)ndirs;
    built->toc = 0x80;
    built->dirs = 0x30 + spec.npackages * 0x40;
    built->files = built->dirs + ndirs * 0x18;
    built->slots = built->files + nfiles * 0x50;
    built->pool = built->slots + nslots * 4;
    built->toc_size = built->pool + pool_size;
    at = (built->toc + built->toc_size + 15) & ~(size_t)15;
    unsigned char* toc = built->bytes + built->toc;
    memcpy(built->bytes, "NUP\x01", 4);
    snx_st_le16(built->bytes + 4, 0x80);
    snx_st_le16(built->bytes + 6, 1);
    snx_st_le64(built->bytes + 8, 0x80);
    snx_st_le64(built->bytes + 0x10, built->toc_size);
    snx_st_le64(built->bytes + 0x38, at);
    snx_st_le32(built->bytes + 0x48, spec.npackages);
    memcpy(toc, "TOC\x01", 4);
    snx_st_le32(toc + 4, spec.npackages);
    snx_st_le64(toc + 8, ndirs);
    snx_st_le64(toc + 0x10, nfiles);
    snx_st_le64(toc + 0x18, built->pool);
    snx_st_le64(toc + 0x20, pool_size);
    for (unsigned i = 0; i < spec.npackages; ++i) {
        unsigned char* record = toc + 0x30 + i * 0x40;
        const Package* package = &spec.packages[i];
        snx_st_le64(record, package->title ? package->title : TITLE);
        snx_st_le32(record + 8, spec.nodes[package->root].id);
        snx_st_le32(record + 0xc, package->exefs < 0 ? 0xffffffffu : spec.nodes[package->exefs].id);
        snx_st_le32(record + 0x10, package->romfs < 0 ? 0xffffffffu : spec.nodes[package->romfs].id);
        snx_st_le32(record + 0x14, package->version);
        record[0x18] = (unsigned char)package->kind;
    }
    size_t name_at = 0, slot = 0;
    for (int i = 0; i < spec.count; ++i) {
        const Node* node = &spec.nodes[i];
        size_t name_size = strlen(node->name);
        unsigned char* record = node->dir ? toc + built->dirs + node->id * 0x18
                                          : toc + built->files + (node->id - ndirs) * 0x50;
        memcpy(toc + built->pool + name_at, node->name, name_size);
        snx_st_le32(record, (SnxU32)name_at);
        snx_st_le32(record + 4, (SnxU32)name_size);
        name_at += name_size;
        if (node->dir) {
            snx_st_le32(record + 8, (SnxU32)slot);
            snx_st_le32(record + 12, (SnxU32)node->count);
            for (int c = 0; c < node->count; ++c, ++slot)
                snx_st_le32(toc + built->slots + slot * 4, spec.nodes[node->children[c]].id);
            continue;
        }
        size_t stored = node->size;
        snx_st_le64(record + 8, node->size);
        sha(record + 0x20, node->content, node->size);
        if (!node->size) continue; /* no extent, as SPEC.md 3.6 says */
        snx_st_le64(record + 0x10, at);
        if (node->zstd) {
            stored = ZSTD_compress(built->bytes + at, BYTES_MAX - at, node->content, node->size, 3);
            CHECK(!ZSTD_isError(stored));
            record[0x40] = 1;
        } else {
            CHECK(at + stored <= BYTES_MAX);
            memcpy(built->bytes + at, node->content, stored);
        }
        snx_st_le64(record + 0x18, stored);
        at = (at + stored + 15) & ~(size_t)15;
    }
    for (unsigned i = 0; i < spec.npackages; ++i) { /* the meta blocks, after the extents as a producer puts them */
        const char* name = spec.packages[i].name;
        if (!name) continue;
        size_t size = strlen(name);
        unsigned char* record = toc + 0x30 + i * 0x40;
        CHECK(at + 8 + size <= BYTES_MAX);
        snx_st_le16(built->bytes + at, 5);
        snx_st_le32(built->bytes + at + 4, (SnxU32)size);
        memcpy(built->bytes + at + 8, name, size);
        snx_st_le64(record + 0x20, at);
        snx_st_le32(record + 0x28, (SnxU32)(8 + size));
        at = (at + 8 + size + 15) & ~(size_t)15;
    }
    built->size = at;
    snx_st_le64(built->bytes + 0x40, at);
    toc_seal(built);
}

static void put_at(const Built* built, const char* path) {
    CHECK(!snx_write_file(path, built->bytes, built->size));
    CHECK(snx_nup_is(path));
}
static void put(const Built* built) { put_at(built, FOLDER ".nup"); }
static void clean(void) {
    if (snx_path_exists(FOLDER)) CHECK(!snx_remove_tree(FOLDER));
}
static int same(const char* path, const void* content, size_t size) {
    size_t got = 0;
    unsigned char* bytes = snx_read_file(path, &got);
    int equal = bytes && got == size && !memcmp(bytes, content, size);
    free(bytes);
    return equal;
}
static int text_is(const char* path, const char* text) { return same(path, text, strlen(text)); }

/* the file as damage left it, its hash made good: the checks past the hash must stop it */
static void refused(Built* built) {
    toc_seal(built);
    put(built);
    CHECK(!snx_nup_open(FOLDER ".nup"));
}
/* opened, for its table is good, and refused when the bad content is reached */
static void extract_refused(const Built* built) {
    SnxNup* nup;
    SnxNupView* view;
    put(built);
    nup = snx_nup_open(FOLDER ".nup");
    CHECK(nup);
    view = snx_nup_game(nup, NULL);
    CHECK(view);
    clean();
    CHECK(snx_nup_extract(view, EXEFS, ROMFS, NULL, NULL));
    snx_nup_view_free(view);
    snx_nup_close(nup);
}

/* a base, and two updates listed newest first: the versions decide, and each case below has its own file */
static void layered(Spec* spec, const unsigned char* big) {
    Package* base = package_add(spec, KIND_BASE, 0);
    text_add(spec, base->exefs, "main", "base main", 0);
    text_add(spec, base->exefs, "subsdk9", "a module the update dropped", 0);
    text_add(spec, base->romfs, "a.bin", "base a", 1);
    text_add(spec, base->romfs, "empty", "", 0);
    int keep = dir_add(spec, base->romfs, "keep");
    text_add(spec, keep, "x.bin", "only in the base", 1);
    text_add(spec, base->romfs, "was_file", "a file the update made a folder", 0);
    int was_dir = dir_add(spec, base->romfs, "was_folder");
    text_add(spec, was_dir, "gone.bin", "a folder the update made a file", 0);
    Package* newest = package_add(spec, KIND_UPDATE, 0x20000);
    text_add(spec, newest->exefs, "main", "newest main", 0);
    text_add(spec, newest->romfs, "a.bin", "newest a", 0);
    file_add(spec, newest->romfs, "big.bin", big, BIG_SIZE, 1);
    int now_dir = dir_add(spec, newest->romfs, "was_file");
    text_add(spec, now_dir, "inner", "now in a folder", 1);
    text_add(spec, newest->romfs, "was_folder", "now a file", 0);
    Package* older = package_add(spec, KIND_UPDATE, 0x10000);
    text_add(spec, older->exefs, "main", "older main", 0);
    text_add(spec, older->romfs, "a.bin", "older a", 0);
    text_add(spec, older->romfs, "older.bin", "only in the older update", 0);
    Package* dlc = package_add(spec, KIND_ADDON, 0);
    dlc->title = DLC_TITLE;
    text_add(spec, dlc->romfs, "dlc.bin", "not extracted", 0);
}

/* path in the image as a game's RomFS code finds it: each part through the table's hash buckets, from the root. Its
   data's offset and size into *offset and *size, 1 when found */
static int image_find(SnxNupView* view, const char* path, SnxU64* offset, SnxU64* size) {
    unsigned char head[0x50], entry[0x20 + 256];
    CHECK(!snx_nup_image_read(view, 0, head, sizeof head));
    CHECK(snx_ld_le64(head) == 0x50);
    SnxU64 dhash = snx_ld_le64(head + 8), dbuckets = snx_ld_le64(head + 0x10) / 4, dirs = snx_ld_le64(head + 0x18);
    SnxU64 fhash = snx_ld_le64(head + 0x28), fbuckets = snx_ld_le64(head + 0x30) / 4, files = snx_ld_le64(head + 0x38);
    SnxU64 data = snx_ld_le64(head + 0x48);
    SnxU32 dir = 0;
    for (;;) {
        const char* slash = strchr(path, '/');
        size_t part = slash ? (size_t)(slash - path) : strlen(path);
        SnxU32 hash = snx_romfs_hash(dir, path, part);
        unsigned char link[4];
        CHECK(!snx_nup_image_read(view, (slash ? dhash + hash % dbuckets * 4 : fhash + hash % fbuckets * 4), link, 4));
        SnxU32 at = snx_ld_le32(link);
        size_t fixed = slash ? 0x18 : 0x20;
        for (;;) {
            if (at == 0xffffffffu) return 0;
            CHECK(!snx_nup_image_read(view, (slash ? dirs : files) + at, entry, fixed));
            SnxU32 length = snx_ld_le32(entry + fixed - 4);
            CHECK(length <= 256);
            CHECK(!snx_nup_image_read(view, (slash ? dirs : files) + at + fixed, entry + fixed, length));
            if (snx_ld_le32(entry) == dir && length == part && !memcmp(entry + fixed, path, part)) break;
            at = snx_ld_le32(entry + fixed - 8);
        }
        if (!slash) {
            *offset = data + snx_ld_le64(entry + 8);
            *size = snx_ld_le64(entry + 16);
            return 1;
        }
        dir = at;
        path = slash + 1;
    }
}
static int image_is(SnxNupView* view, const char* path, const void* content, size_t size) {
    SnxU64 offset = 0, got = 0;
    unsigned char* bytes;
    int equal;
    if (!image_find(view, path, &offset, &got) || got != size) return 0;
    bytes = (unsigned char*)snx_alloc(size ? size : 1);
    CHECK(!snx_nup_image_read(view, offset, bytes, size));
    equal = !memcmp(bytes, content, size);
    free(bytes);
    return equal;
}
static int image_text(SnxNupView* view, const char* path, const char* text) {
    return image_is(view, path, text, strlen(text));
}

/* the streamed file by pieces, forward, then behind what was read, across the decoder's chunks */
static void test_stream(SnxNupView* view, const unsigned char* big) {
    SnxU64 offset = 0, size = 0;
    static unsigned char piece[100000];
    CHECK(image_find(view, "big.bin", &offset, &size) && size == BIG_SIZE);
    for (size_t at = 0; at < BIG_SIZE; at += sizeof piece) {
        size_t n = BIG_SIZE - at < sizeof piece ? BIG_SIZE - at : sizeof piece;
        CHECK(!snx_nup_image_read(view, offset + at, piece, n));
        CHECK(!memcmp(piece, big + at, n));
    }
    CHECK(!snx_nup_image_read(view, offset + 5, piece, 1000));
    CHECK(!memcmp(piece, big + 5, 1000));
    CHECK(!snx_nup_image_read(view, offset + BIG_SIZE - 1000, piece, 1000));
    CHECK(!memcmp(piece, big + BIG_SIZE - 1000, 1000));
    /* another zstd file between two reads of it: the cache shares the decoder the stream is in */
    CHECK(image_text(view, "was_file/inner", "now in a folder"));
    CHECK(!snx_nup_image_read(view, offset + BIG_SIZE / 2, piece, 1000));
    CHECK(!memcmp(piece, big + BIG_SIZE / 2, 1000));
}

static void test_layers(const Built* built, const unsigned char* big) {
    SnxU64 title = 0, game = 0, version = 0, dlc = 0, size = 0, offset = 0;
    size_t icon_size;
    const char* name;
    char main_text[6];
    put(built);
    SnxNup* nup = snx_nup_open(FOLDER ".nup");
    CHECK(nup);
    CHECK(snx_nup_has_game(nup));
    CHECK(!snx_nup_title(nup, &title, &game, &version));
    CHECK(title == TITLE && game == TITLE && version == SNX_NO_VERSION);
    CHECK(snx_nup_updates(nup) == 2 && snx_nup_dlcs(nup) == 1);
    snx_nup_dlc(nup, 0, &dlc, &version);
    CHECK(dlc == DLC_TITLE);
    CHECK(!snx_nup_meta(nup, SNX_NUP_META_ICON, &icon_size));
    SnxNupView* view = snx_nup_game(nup, NULL);
    CHECK(view);
    CHECK(snx_nup_version(view) == 0x20000);
    SnxU64 expected = strlen("newest main") + strlen("newest a") + BIG_SIZE + strlen("now in a folder") +
                      strlen("now a file") + strlen("only in the base");
    CHECK(snx_nup_bytes(view) == expected);
    /* read in place: the newest ExeFS whole, as a module of the base must not load beside a newer main */
    CHECK(snx_nup_exefs_count(view) == 1);
    snx_nup_exefs_file(view, 0, &name, &size);
    CHECK(!strcmp(name, "main") && size == strlen("newest main"));
    CHECK(!snx_nup_exefs_read(view, 0, 7, main_text, 4));
    CHECK(!memcmp(main_text, "main", 4));
    CHECK(snx_nup_exefs_read(view, 0, 8, main_text, 4)); /* past its end */
    CHECK(image_text(view, "a.bin", "newest a"));
    CHECK(image_is(view, "big.bin", big, BIG_SIZE));
    /* an update is made against the base: what the newest took away does not come back from an older one */
    CHECK(!image_find(view, "older.bin", &offset, &size));
    CHECK(image_text(view, "keep/x.bin", "only in the base"));
    CHECK(image_is(view, "empty", "", 0));
    CHECK(image_text(view, "was_file/inner", "now in a folder"));
    CHECK(image_text(view, "was_folder", "now a file"));
    CHECK(!image_find(view, "was_folder/gone.bin", &offset, &size));
    CHECK(!image_find(view, "dlc.bin", &offset, &size));
    CHECK(snx_nup_image_read(view, snx_nup_image_size(view) - 1, main_text, 2)); /* past its end */
    test_stream(view, big);
    /* and written out, the same */
    clean();
    CHECK(!snx_nup_extract(view, EXEFS, ROMFS, NULL, NULL));
    CHECK(text_is(EXEFS "/main", "newest main"));
    CHECK(!snx_path_exists(EXEFS "/subsdk9"));
    CHECK(text_is(ROMFS "/a.bin", "newest a"));
    CHECK(same(ROMFS "/big.bin", big, BIG_SIZE));
    CHECK(!snx_path_exists(ROMFS "/older.bin"));
    CHECK(text_is(ROMFS "/keep/x.bin", "only in the base"));
    CHECK(same(ROMFS "/empty", "", 0));
    CHECK(text_is(ROMFS "/was_file/inner", "now in a folder"));
    CHECK(text_is(ROMFS "/was_folder", "now a file"));
    CHECK(!snx_path_exists(ROMFS "/dlc.bin"));
    /* reads go on after an extraction took the decoder */
    test_stream(view, big);
    snx_nup_view_free(view);
    /* a DLC by its title, and one it does not hold */
    view = snx_nup_aoc(nup, DLC_TITLE);
    CHECK(view);
    CHECK(image_text(view, "dlc.bin", "not extracted"));
    CHECK(!image_find(view, "a.bin", &offset, &size));
    CHECK(snx_nup_exefs_count(view) == 0 && snx_nup_version(view) == SNX_NO_VERSION);
    snx_nup_view_free(view);
    CHECK(!snx_nup_aoc(nup, DLC_OTHER));
    snx_nup_close(nup);
}

/* a game and its update in two files, the update numbered as the game, as a package may be */
static void test_two_files(void) {
    static Spec game_spec, update_spec, dlc_spec;
    static Built built;
    SnxU64 title, game, version;
    Package* base = package_add(&game_spec, KIND_BASE, 0);
    text_add(&game_spec, base->exefs, "main", "base main", 0);
    text_add(&game_spec, base->romfs, "a.bin", "base a", 0);
    text_add(&game_spec, base->romfs, "b.bin", "base b", 1);
    build(&game_spec, &built);
    put(&built);
    Package* update = package_add(&update_spec, KIND_UPDATE, 0x30000);
    text_add(&update_spec, update->exefs, "main", "update main", 0);
    text_add(&update_spec, update->romfs, "a.bin", "update a", 1);
    build(&update_spec, &built);
    put_at(&built, FOLDER "_update.nup");
    SnxNup* base_nup = snx_nup_open(FOLDER ".nup");
    SnxNup* update_nup = snx_nup_open(FOLDER "_update.nup");
    CHECK(base_nup && update_nup);
    CHECK(!snx_nup_has_game(update_nup));
    CHECK(!snx_nup_title(update_nup, &title, &game, &version));
    CHECK(title == (TITLE | 0x800) && game == TITLE && version == 0x30000);
    SnxNupView* view = snx_nup_game(base_nup, update_nup);
    CHECK(view);
    CHECK(snx_nup_version(view) == 0x30000);
    CHECK(image_text(view, "a.bin", "update a"));
    CHECK(image_text(view, "b.bin", "base b"));
    snx_nup_view_free(view);
    /* alone: its ExeFS, and no RomFS, which may be only what it changes */
    view = snx_nup_game(NULL, update_nup);
    CHECK(view);
    CHECK(snx_nup_exefs_count(view) == 1 && snx_nup_image_size(view) == 0);
    snx_nup_view_free(view);
    CHECK(!snx_nup_game(update_nup, NULL)); /* not a game */
    snx_nup_close(base_nup);
    snx_nup_close(update_nup);
    /* the update of another game is refused */
    Package* other = package_add(&dlc_spec, KIND_UPDATE, 1);
    other->title = TITLE + 0x10000;
    text_add(&dlc_spec, other->exefs, "main", "other main", 0);
    build(&dlc_spec, &built);
    put_at(&built, FOLDER "_update.nup");
    base_nup = snx_nup_open(FOLDER ".nup");
    update_nup = snx_nup_open(FOLDER "_update.nup");
    CHECK(base_nup && update_nup);
    CHECK(!snx_nup_game(base_nup, update_nup));
    snx_nup_close(base_nup);
    snx_nup_close(update_nup);
    CHECK(!snx_remove_tree(FOLDER "_update.nup"));
}

static void test_table_damage(const Built* good) {
    static Built built;
    unsigned char* toc;
    /* each starts from the good file: toc points into the copy */
#define FRESH() (built = *good, toc = built.bytes + built.toc)
    FRESH(); /* the hash itself, left as it was */
    toc[built.pool] ^= 1;
    put(&built);
    CHECK(!snx_nup_open(FOLDER ".nup"));
    FRESH(); /* cut short */
    built.size -= 16;
    put(&built);
    CHECK(!snx_nup_open(FOLDER ".nup"));
    FRESH(); /* a flag this reader does not know */
    built.bytes[0x4c] = 1;
    put(&built);
    CHECK(!snx_nup_open(FOLDER ".nup"));
    FRESH(); /* a name that climbs out of the folder */
    memcpy(toc + built.pool + snx_ld_le32(toc + built.files), "..", 2);
    snx_st_le32(toc + built.files + 4, 2);
    refused(&built);
    FRESH(); /* a name with a path in it */
    memcpy(toc + built.pool + snx_ld_le32(toc + built.files), "a/b", 3);
    refused(&built);
    FRESH(); /* children out of order, which the search of covered files relies on */
    {
        SnxU32 first = snx_ld_le32(toc + built.slots), second = snx_ld_le32(toc + built.slots + 4);
        snx_st_le32(toc + built.slots, second);
        snx_st_le32(toc + built.slots + 4, first);
    }
    refused(&built);
    FRESH(); /* a child that does not exist */
    snx_st_le32(toc + built.slots, 0x7fffffff);
    refused(&built);
    FRESH(); /* a directory in two places: the second package's exefs slot names the first's */
    {
        size_t second_root = 0;
        for (SnxU32 d = 1; d < built.ndirs; ++d) /* the next root is the next directory with no name */
            if (!snx_ld_le32(toc + built.dirs + d * 0x18 + 4)) {
                second_root = built.dirs + d * 0x18;
                break;
            }
        CHECK(second_root);
        snx_st_le32(toc + built.slots + snx_ld_le32(toc + second_root + 8) * 4, snx_ld_le32(toc + built.slots));
    }
    refused(&built);
    FRESH(); /* a directory whose children lie past the table */
    snx_st_le32(toc + built.dirs + 12, 0x10000);
    refused(&built);
    FRESH(); /* a circle: the first package's exefs (dir 1) back to its root (dir 0), named as the slot's old child */
    {
        size_t exefs = built.dirs + 0x18, slot = built.slots + snx_ld_le32(toc + exefs + 8) * 4;
        SnxU32 child = snx_ld_le32(toc + slot);
        const unsigned char* old = toc + built.files + (child - built.ndirs) * 0x50;
        snx_st_le32(toc + slot, 0);
        snx_st_le32(toc + built.dirs, snx_ld_le32(old));
        snx_st_le32(toc + built.dirs + 4, snx_ld_le32(old + 4));
    }
    refused(&built);
    FRESH(); /* an extent past the end, and one inside the table */
    snx_st_le64(toc + built.files + 0x10, built.size);
    refused(&built);
    FRESH();
    snx_st_le64(toc + built.files + 0x10, built.toc);
    refused(&built);
    FRESH(); /* a raw file that says it is larger than what is stored */
    snx_st_le64(toc + built.files + 8, snx_ld_le64(toc + built.files + 8) + 1);
    refused(&built);
    FRESH(); /* a codec of a later version */
    toc[built.files + 0x40] = 2;
    refused(&built);
    FRESH(); /* codec flags of a later version */
    toc[built.files + 0x41] = 1;
    refused(&built);
    FRESH(); /* a file with bytes and no extent */
    snx_st_le64(toc + built.files + 8, 1);
    snx_st_le64(toc + built.files + 0x18, 0);
    toc[built.files + 0x40] = 1;
    refused(&built);
    FRESH(); /* a package kind of a later version */
    toc[0x30 + 0x18] = 5;
    refused(&built);
    FRESH(); /* two bases */
    toc[0x30 + 0x40 + 0x18] = KIND_BASE;
    refused(&built);
    FRESH(); /* a package whose tree does not exist */
    snx_st_le32(toc + 0x30 + 0x10, 0x7fffffff);
    refused(&built);
    FRESH(); /* a package count that disagrees */
    snx_st_le32(toc + 4, 3);
    refused(&built);
#undef FRESH
}

/* the file record of name in the built file */
static unsigned char* file_named(Built* built, const char* name) {
    unsigned char* toc = built->bytes + built->toc;
    size_t size = strlen(name);
    for (size_t at = built->files; at < built->slots; at += 0x50)
        if (snx_ld_le32(toc + at + 4) == size && !memcmp(toc + built->pool + snx_ld_le32(toc + at), name, size))
            return toc + at;
    CHECK(0);
    return NULL;
}

static void test_content_damage(const Built* good) {
    static Built built;
    unsigned char* file;
    built = *good; /* a raw file's byte, which only its hash shows */
    file = file_named(&built, "was_folder");
    built.bytes[snx_ld_le64(file + 0x10)] ^= 1;
    extract_refused(&built);
    built = *good; /* a zstd file's hash */
    file = file_named(&built, "big.bin");
    file[0x20] ^= 1;
    toc_seal(&built);
    extract_refused(&built);
    built = *good; /* a zstd frame cut short */
    file = file_named(&built, "big.bin");
    snx_st_le64(file + 0x18, snx_ld_le64(file + 0x18) - 4);
    toc_seal(&built);
    extract_refused(&built);
    built = *good; /* a frame that makes more than the file says */
    file = file_named(&built, "big.bin");
    snx_st_le64(file + 8, BIG_SIZE - 1);
    toc_seal(&built);
    extract_refused(&built);
    built = *good; /* and less */
    file = file_named(&built, "big.bin");
    snx_st_le64(file + 8, BIG_SIZE + 1);
    toc_seal(&built);
    extract_refused(&built);
}

/* a game's name without a control.nacp: taken when it is fit to show, and the game gets no NACP from it */
static void test_name(void) {
    static Spec spec;
    static Built built;
    SnxDump dump;
    const char* why = NULL;
    size_t size = 0;
    Package* base = package_add(&spec, KIND_BASE, 0);
    base->name = "A Game \xe3\x82\xb2";
    text_add(&spec, base->exefs, "main", "main", 0);
    build(&spec, &built);
    put(&built);
    CHECK(!snx_dump_open(&dump, FOLDER ".nup", NULL, 0, NULL, NULL, FOLDER, 0));
    char* shown = snx_dump_shown(&dump);
    CHECK(shown && !strcmp(shown, "A Game \xe3\x82\xb2"));
    free(shown);
    CHECK(!snx_dump_nacp(&dump, &size, &why));
    snx_dump_close(&dump);
    /* a line break would reach the log and the launcher's rows, and bytes that are not UTF-8 its text */
    base->name = "two\nlines";
    build(&spec, &built);
    put(&built);
    CHECK(!snx_dump_open(&dump, FOLDER ".nup", NULL, 0, NULL, NULL, FOLDER, 0));
    CHECK(!snx_dump_shown(&dump));
    snx_dump_close(&dump);
    base->name = "not \xff UTF-8";
    build(&spec, &built);
    put(&built);
    CHECK(!snx_dump_open(&dump, FOLDER ".nup", NULL, 0, NULL, NULL, FOLDER, 0));
    CHECK(!snx_dump_shown(&dump));
    snx_dump_close(&dump);
    /* the file that keeps it */
    clean();
    CHECK(!snx_mkdirs(FOLDER));
    CHECK(!snx_shown_read(FOLDER));
    CHECK(!snx_write_file(FOLDER "/" SNX_SHOWN_FILE, "A Game", 6));
    shown = snx_shown_read(FOLDER);
    CHECK(shown && !strcmp(shown, "A Game"));
    free(shown);
    CHECK(!snx_write_file(FOLDER "/" SNX_SHOWN_FILE, "two\nlines", 9));
    CHECK(!snx_shown_read(FOLDER));
    CHECK(!snx_write_file(FOLDER "/" SNX_SHOWN_FILE, "", 0));
    CHECK(!snx_shown_read(FOLDER));
}

/* a file of DLCs alone names the first, and its game by the usual numbering */
static void test_dlc_alone(void) {
    static Spec spec;
    static Built built;
    SnxU64 title, game, version;
    Package* dlc = package_add(&spec, KIND_ADDON, 3);
    dlc->title = DLC_TITLE;
    text_add(&spec, dlc->romfs, "dlc.bin", "a DLC", 1);
    build(&spec, &built);
    put(&built);
    SnxNup* nup = snx_nup_open(FOLDER ".nup");
    CHECK(nup);
    CHECK(!snx_nup_title(nup, &title, &game, &version));
    CHECK(title == DLC_TITLE && game == snx_addon_guess(DLC_TITLE) && version == 3);
    CHECK(!snx_nup_game(nup, NULL));
    snx_nup_close(nup);
}

/* as what reads a dump reads it: the recompiler's ExeFS, the runtime's RomFS and DLCs, all through SnxDump */
static void test_dump(const Built* built) {
    SnxDump dump;
    SnxU64 title = 0, game = 0, version = 0;
    const SnxHacEntry* files;
    const char* why = NULL;
    char text[6];
    size_t size = 0;
    unsigned char* bytes;
    put(built);
    CHECK(snx_is_dump(FOLDER ".nup"));
    CHECK(!snx_dump_title(&dump, FOLDER ".nup", NULL, NULL, FOLDER, 0, &title, &game, &version));
    CHECK(title == TITLE && game == TITLE && version == SNX_NO_VERSION && dump.programs == 1);
    snx_dump_close(&dump);
    CHECK(!snx_dump_open(&dump, FOLDER ".nup", NULL, 0, NULL, NULL, FOLDER, 0));
    CHECK(dump.program.found && dump.patch.found && dump.version == 0x20000);
    CHECK(!snx_nca_keys(&dump, &dump.program, "program") && !snx_nca_keys(&dump, &dump.patch, "patch"));
    CHECK(!snx_dump_nacp(&dump, &size, &why) && why);
    CHECK(!snx_dump_icon(&dump, &size, &why) && why);
    SnxHacFs* fs = snx_dump_fs(&dump);
    CHECK(fs);
    CHECK(snx_hac_fs_files(fs, &files) == 1 && !strcmp(files[0].name, "main"));
    CHECK(!snx_hac_fs_read(fs, 0, 7, text, 4) && !memcmp(text, "main", 4));
    bytes = snx_romfs_file(fs, "keep/x.bin", &size); /* the code that walks an NCA's RomFS */
    CHECK(bytes && size == strlen("only in the base") && !memcmp(bytes, "only in the base", size));
    free(bytes);
    snx_hac_fs_free(fs);
    snx_dump_close(&dump);
    /* its DLC, as fs.c opens one: the file as the add-on, then the DLC by its title */
    CHECK(!snx_dump_open(&dump, NULL, FOLDER ".nup", 0, NULL, NULL, FOLDER, 0));
    CHECK(dump.aoc.found && dump.aoc.title_id == DLC_TITLE);
    CHECK(snx_dump_pick_aoc(&dump, DLC_OTHER));
    CHECK(!snx_dump_pick_aoc(&dump, DLC_TITLE));
    fs = snx_dump_aoc_fs(&dump);
    CHECK(fs);
    bytes = snx_romfs_file(fs, "dlc.bin", &size);
    CHECK(bytes && size == strlen("not extracted") && !memcmp(bytes, "not extracted", size));
    free(bytes);
    snx_hac_fs_free(fs);
    snx_dump_close(&dump);
    CHECK(snx_dump_open(&dump, FOLDER ".nup", NULL, 1, NULL, NULL, FOLDER, 0)); /* a NUP holds one program */
    snx_dump_close(&dump);
}

int main(void) {
    static Spec spec;
    static Built built;
    unsigned char* big = (unsigned char*)snx_alloc(BIG_SIZE);
    for (size_t i = 0; i < BIG_SIZE; ++i) big[i] = (unsigned char)(i / 4096);
    layered(&spec, big);
    build(&spec, &built);
    test_layers(&built, big);
    test_dump(&built);
    test_table_damage(&built);
    test_content_damage(&built);
    test_two_files();
    test_dlc_alone();
    test_name();
    clean();
    CHECK(!snx_remove_tree(FOLDER ".nup"));
    CHECK(!snx_nup_is(FOLDER ".nup"));
    free(big);
    puts("nup: ok");
    return 0;
}
