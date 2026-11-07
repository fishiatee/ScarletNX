/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright 2026 the ScarletNX contributors */
/* The NUP container (nup.h), written from its SPEC.md (MIT, a55uka). The table of contents is kept in memory as it lies
   in the file, and read through the offsets below. A file is untrusted until snx_nup_open has checked it: every bound,
   every name that becomes a path, and that the directories form trees.

   A view's raw files are read where they lie. A zstd frame has no way in but its start, so a small file is decoded
   whole into a cache, and one too large for it is decoded as a stream, which a read further on continues */
#include "nx/runtime/driver/nup.h"
#include "common/utilities/endian.h"
#include "common/utilities/romfs.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zstd.h>

enum {
    SUPERBLOCK_SIZE = 0x80,
    TOC_HEADER_SIZE = 0x30,
    PACKAGE_SIZE = 0x40,
    DIR_SIZE = 0x18,
    FILE_SIZE = 0x50,
    HASH_SIZE = 32,
    NAME_MAX_SIZE = 255,
    DEPTH_MAX = 64,          /* a RomFS is far shallower, and each level is a frame of the walk */
    CHUNK_SIZE = 1 << 20,
    KIND_BASE = 0,
    KIND_UPDATE = 1,
    KIND_ADDON = 2,
    KIND_RESERVED = 5,       /* this and above are refused, as SPEC.md 6.1 says */
    CODEC_RAW = 0,
    CODEC_ZSTD = 1,
    NODE_NONE = 0,
    NODE_DIR = 1,
    NODE_FILE = 2
};
#define NO_DIR 0xffffffffu
#define PATCH_BIT 0x800ull /* what the console adds to a game's ID for its update */
#define ROM_NONE 0xffffffffu
#define ROM_DIR_ENTRY 0x18
#define ROM_FILE_ENTRY 0x20
/* the zstd files kept decoded: what a read of a file too large for this streams instead */
#define CACHE_BYTES ((SnxU64)256 << 20)
#ifndef NUP_CACHE_FILE_MAX /* a test gives a small one */
#define NUP_CACHE_FILE_MAX ((SnxU64)128 << 20)
#endif
#define CACHE_SLOTS 256

struct SnxNup {
    FILE* file;
    char* path;
    unsigned char* toc;
    SnxU64 toc_size, blob_offset, file_size;
    SnxU64 dirs, files, slots; /* counts */
    SnxU64 dirs_at, files_at, slots_at, pool_at, pool_size; /* offsets in toc */
    unsigned packages;
    unsigned* order;   /* by index: the base, when it has one, then the updates from oldest to newest */
    unsigned* dlcs;    /* by index, in the block order starts */
    unsigned layers, ndlcs;
    int has_game;
};

typedef struct {
    SnxNup* nup;
    unsigned package;
} Layer;

/* a file of the image, where its data lies in it: a layer's file */
typedef struct {
    SnxU64 offset, size;
    unsigned layer;
    SnxU32 file;
} ImageFile;

typedef struct {
    const SnxNup* nup;
    SnxU64 extent, size, used;
    unsigned char* data;
} Cached;

struct SnxNupView {
    Layer* layers; /* the base, then the update over it */
    unsigned count;
    int no_romfs; /* an update alone: its RomFS may be only what it changes */
    unsigned exefs_layer;
    SnxU32* exefs;     /* the ExeFS's files in that layer */
    char (*exefs_names)[NAME_MAX_SIZE + 1];
    size_t nexefs;
    unsigned char* meta; /* the image's header and tables */
    SnxU64 meta_size, data_at, total;
    ImageFile* files; /* those with bytes, by offset */
    size_t nfiles;
    unsigned char *in, *out; /* CHUNK_SIZE each, one allocation */
    ZSTD_DCtx* zstd;
    EVP_MD_CTX* sha;
    Cached cache[CACHE_SLOTS];
    SnxU64 cached, tick;
    /* the zstd file being streamed: out holds its bytes [start, end), and its next stored bytes lie at next */
    const SnxNup* stream;
    SnxU64 stream_extent, start, end, next, left;
    ZSTD_inBuffer input;
};

/* the image's tree while it is made: a directory's first child and next sibling are in dirs, sorted by name */
typedef struct {
    const char* name;
    size_t size;
    SnxU32 parent, child, sibling, first_file, offset;
} TreeDir;
typedef struct {
    const char* name;
    size_t size;
    SnxU32 parent, file;
    unsigned layer;
    SnxU64 bytes;
} TreeFile;
typedef struct {
    TreeDir* dirs;
    TreeFile* files;
    SnxU32 ndirs, nfiles;
} Tree;

enum { WALK_COUNT, WALK_WRITE, WALK_TREE };
/* one walk over a tree */
typedef struct {
    SnxNupView* view;
    int mode;
    unsigned layer;   /* the layer walked: those after it cover its files. count for an ExeFS, which nothing covers */
    size_t root;      /* where the path below the tree starts in a path of the walk */
    SnxU64 bytes;
    Tree* tree;
    void (*progress)(uint64_t, void*);
    void* data;
} Walk;

static const unsigned char* package_at(const SnxNup* nup, unsigned i) {
    return nup->toc + TOC_HEADER_SIZE + (size_t)i * PACKAGE_SIZE;
}
static const unsigned char* dir_at(const SnxNup* nup, SnxU32 i) {
    return nup->toc + nup->dirs_at + (size_t)i * DIR_SIZE;
}
static const unsigned char* file_at(const SnxNup* nup, SnxU32 i) {
    return nup->toc + nup->files_at + (size_t)i * FILE_SIZE;
}
static SnxU32 slot_at(const SnxNup* nup, SnxU64 i) { return snx_ld_le32(nup->toc + nup->slots_at + i * 4); }
static SnxU64 package_title(const SnxNup* nup, unsigned i) { return snx_ld_le64(package_at(nup, i)); }
static SnxU32 package_exefs(const SnxNup* nup, unsigned i) { return snx_ld_le32(package_at(nup, i) + 0x0c); }
static SnxU32 package_romfs(const SnxNup* nup, unsigned i) { return snx_ld_le32(package_at(nup, i) + 0x10); }
static SnxU32 package_version(const SnxNup* nup, unsigned i) { return snx_ld_le32(package_at(nup, i) + 0x14); }
static unsigned package_kind(const SnxNup* nup, unsigned i) { return package_at(nup, i)[0x18]; }

/* node's record, the name's two fields first in a directory's and a file's alike */
static const unsigned char* node_at(const SnxNup* nup, SnxU32 node) {
    return node < nup->dirs ? dir_at(nup, node) : file_at(nup, (SnxU32)(node - nup->dirs));
}
static const char* node_name(const SnxNup* nup, SnxU32 node, size_t* size) {
    const unsigned char* record = node_at(nup, node);
    *size = snx_ld_le32(record + 4);
    return (const char*)nup->toc + nup->pool_at + snx_ld_le32(record);
}
/* bytewise, the shorter first, as children are sorted */
static int name_order(const char* a, size_t a_size, const char* b, size_t b_size) {
    int order = memcmp(a, b, a_size < b_size ? a_size : b_size);
    return order ? order : a_size < b_size ? -1 : a_size > b_size;
}
/* a name is a label from the file, and it becomes one part of a path */
static int name_safe(const char* name, size_t size) {
    if (!size || size > NAME_MAX_SIZE) return 0;
    if ((size == 1 && name[0] == '.') || (size == 2 && !memcmp(name, "..", 2))) return 0;
    for (size_t i = 0; i < size; ++i)
        if ((unsigned char)name[i] < 0x20 || name[i] == '/' || name[i] == '\\') return 0;
#ifdef _WIN32
    if (memchr(name, ':', size)) return 0; /* a stream of the file, not a name, when it is written out */
#endif
    return 1;
}
static int range_in(SnxU64 offset, SnxU64 size, SnxU64 limit) { return offset <= limit && size <= limit - offset; }

int snx_nup_is(const char* path) {
    unsigned char magic[4];
    FILE* file = snx_fopen(path, "rb");
    size_t size = file ? fread(magic, 1, sizeof magic, file) : 0;
    if (file) fclose(file);
    return size == sizeof magic && !memcmp(magic, "NUP\x01", 4);
}

static int bad(const SnxNup* nup, const char* what) { return snx_error("%s is a damaged NUP: %s", nup->path, what); }

/* the children of each directory: in bounds, safe, sorted, and no directory in two places, so a walk ends */
static int dirs_check(const SnxNup* nup) {
    unsigned char* placed = (unsigned char*)calloc((size_t)nup->dirs + 1, 1);
    SnxU64 used = 0;
    int failed = 0;
    if (!placed) return snx_error("out of memory reading %s", nup->path);
    for (SnxU32 d = 0; !failed && d < nup->dirs; ++d) {
        const unsigned char* dir = dir_at(nup, d);
        SnxU64 first = snx_ld_le32(dir + 8), count = snx_ld_le32(dir + 12);
        const char* last = NULL;
        size_t last_size = 0;
        if (!range_in(snx_ld_le32(dir), snx_ld_le32(dir + 4), nup->pool_size) || !range_in(first, count, nup->slots) ||
            (used += count) > nup->slots) {
            failed = bad(nup, "a directory lies outside its table");
            break;
        }
        for (SnxU64 i = first; !failed && i < first + count; ++i) {
            SnxU32 child = slot_at(nup, i);
            const char* name;
            size_t size;
            if (child >= nup->dirs + nup->files) {
                failed = bad(nup, "a directory names a node that does not exist");
                break;
            }
            if (!range_in(snx_ld_le32(node_at(nup, child)), snx_ld_le32(node_at(nup, child) + 4), nup->pool_size)) {
                failed = bad(nup, "a name lies outside the string pool");
                break;
            }
            name = node_name(nup, child, &size);
            if (!name_safe(name, size))
                failed = bad(nup, "a name is not one part of a path");
            else if (last && name_order(last, last_size, name, size) >= 0)
                failed = bad(nup, "the children of a directory are not sorted");
            else if (child < nup->dirs && placed[child]++)
                failed = bad(nup, "a directory lies in two places");
            last = name;
            last_size = size;
        }
    }
    free(placed);
    return failed;
}

static int files_check(const SnxNup* nup) {
    for (SnxU32 f = 0; f < nup->files; ++f) {
        const unsigned char* file = file_at(nup, f);
        SnxU64 size = snx_ld_le64(file + 8), offset = snx_ld_le64(file + 0x10), stored = snx_ld_le64(file + 0x18);
        unsigned codec = file[0x40];
        if (codec != CODEC_RAW && codec != CODEC_ZSTD)
            return snx_error("%s has a file in a codec this build does not know (%u)", nup->path, codec);
        if (file[0x41]) return snx_error("%s has a file with codec flags this build does not know", nup->path);
        if (codec == CODEC_RAW && stored != size) return bad(nup, "a raw file's stored size is not its size");
        if (size && !stored) return bad(nup, "a file with bytes has no extent");
        if (stored && (offset < nup->blob_offset || offset % 16 || !range_in(offset, stored, nup->file_size)))
            return bad(nup, "a file's extent lies outside the blob region");
    }
    return 0;
}

/* how deep dir goes: cycles through a root are all that dirs_check leaves */
static int depth_check(const SnxNup* nup, SnxU32 dir, unsigned depth) {
    const unsigned char* record = dir_at(nup, dir);
    SnxU64 first = snx_ld_le32(record + 8), count = snx_ld_le32(record + 12);
    if (depth > DEPTH_MAX) return bad(nup, "its directories go too deep, or in a circle");
    for (SnxU64 i = first; i < first + count; ++i) {
        SnxU32 child = slot_at(nup, i);
        if (child < nup->dirs && depth_check(nup, child, depth + 1)) return 1;
    }
    return 0;
}

/* the ID of the game a package's ID is of */
static SnxU64 title_game(SnxU64 id) { return id & ~PATCH_BIT; }

/* the base and its title's updates from oldest to newest, or the updates of the first one's title alone; the DLCs */
static int packages_read(SnxNup* nup) {
    SnxU64 game = 0;
    int found = 0;
    for (unsigned i = 0; i < nup->packages; ++i) {
        SnxU32 root = snx_ld_le32(package_at(nup, i) + 8), exefs = package_exefs(nup, i), romfs = package_romfs(nup, i);
        unsigned kind = package_kind(nup, i);
        SnxU64 meta = snx_ld_le64(package_at(nup, i) + 0x20), meta_size = snx_ld_le32(package_at(nup, i) + 0x28);
        if (kind >= KIND_RESERVED)
            return snx_error("%s has a package of a kind this build does not know (%u)", nup->path, kind);
        if (root >= nup->dirs || (exefs != NO_DIR && exefs >= nup->dirs) || (romfs != NO_DIR && romfs >= nup->dirs))
            return bad(nup, "a package names a directory that does not exist");
        if (!range_in(meta, meta_size, nup->file_size)) return bad(nup, "a package's meta block lies outside the file");
        if (depth_check(nup, root, 0) || (exefs != NO_DIR && depth_check(nup, exefs, 0)) ||
            (romfs != NO_DIR && depth_check(nup, romfs, 0)))
            return 1;
        if (kind == KIND_BASE) {
            if (nup->has_game) return bad(nup, "it has two base packages");
            nup->has_game = 1;
            game = title_game(package_title(nup, i));
            found = 1;
            nup->order = (unsigned*)snx_alloc(sizeof *nup->order * nup->packages * 2);
            nup->order[nup->layers++] = i;
        }
    }
    if (!nup->order) nup->order = (unsigned*)snx_alloc(sizeof *nup->order * nup->packages * 2);
    nup->dlcs = nup->order + nup->packages;
    for (unsigned i = 0; i < nup->packages; ++i) {
        unsigned kind = package_kind(nup, i);
        if (kind == KIND_ADDON) nup->dlcs[nup->ndlcs++] = i;
        if (kind != KIND_UPDATE) continue;
        if (!found) {
            game = title_game(package_title(nup, i));
            found = 1;
        }
        if (title_game(package_title(nup, i)) != game) continue;
        unsigned at = nup->layers++, first = (unsigned)nup->has_game;
        for (; at > first && package_version(nup, nup->order[at - 1]) > package_version(nup, i); --at)
            nup->order[at] = nup->order[at - 1];
        nup->order[at] = i;
    }
    return 0;
}

static int toc_read(SnxNup* nup, const unsigned char* block) {
    SnxU64 toc_offset = snx_ld_le64(block + 8);
    unsigned char hash[HASH_SIZE];
    unsigned digest_size = 0;
    nup->toc_size = snx_ld_le64(block + 0x10);
    nup->blob_offset = snx_ld_le64(block + 0x38);
    nup->packages = snx_ld_le32(block + 0x48);
    if (snx_ld_le16(block + 4) < SUPERBLOCK_SIZE || toc_offset != snx_ld_le16(block + 4))
        return bad(nup, "its header size");
    if (snx_ld_le64(block + 0x40) != nup->file_size)
        return bad(nup, "it is not the size its header says, so it may be cut short");
    if (snx_ld_le32(block + 0x4c)) return snx_error("%s uses flags this build does not know", nup->path);
    if (nup->blob_offset % 16 || nup->toc_size < TOC_HEADER_SIZE ||
        !range_in(toc_offset, nup->toc_size, nup->blob_offset) || nup->blob_offset > nup->file_size ||
        nup->toc_size > SIZE_MAX || !nup->packages)
        return bad(nup, "its regions do not fit");
    nup->toc = (unsigned char*)malloc((size_t)nup->toc_size);
    if (!nup->toc) return snx_error("out of memory reading %s", nup->path);
    if (snx_seek(nup->file, toc_offset) || fread(nup->toc, 1, (size_t)nup->toc_size, nup->file) != nup->toc_size)
        return snx_error("cannot read the table of contents of %s", nup->path);
    if (!EVP_Digest(nup->toc, (size_t)nup->toc_size, hash, &digest_size, EVP_sha256(), NULL) ||
        digest_size != HASH_SIZE || memcmp(hash, block + 0x18, HASH_SIZE))
        return bad(nup, "the hash of its table of contents");
    /* from here each value is the producer's, and bounded before use */
    nup->dirs = snx_ld_le64(nup->toc + 8);
    nup->files = snx_ld_le64(nup->toc + 0x10);
    nup->pool_at = snx_ld_le64(nup->toc + 0x18);
    nup->pool_size = snx_ld_le64(nup->toc + 0x20);
    if (memcmp(nup->toc, "TOC\x01", 4) || snx_ld_le32(nup->toc + 4) != nup->packages)
        return bad(nup, "its table of contents");
    if (nup->packages > (nup->toc_size - TOC_HEADER_SIZE) / PACKAGE_SIZE)
        return bad(nup, "too many packages for its table");
    nup->dirs_at = TOC_HEADER_SIZE + (SnxU64)nup->packages * PACKAGE_SIZE;
    if (nup->dirs >= NO_DIR / 2 || nup->files >= NO_DIR / 2 || nup->dirs > (nup->toc_size - nup->dirs_at) / DIR_SIZE)
        return bad(nup, "too many directories for its table");
    nup->files_at = nup->dirs_at + nup->dirs * DIR_SIZE;
    if (nup->files > (nup->toc_size - nup->files_at) / FILE_SIZE) return bad(nup, "too many files for its table");
    nup->slots_at = nup->files_at + nup->files * FILE_SIZE;
    if (nup->pool_at < nup->slots_at || !range_in(nup->pool_at, nup->pool_size, nup->toc_size))
        return bad(nup, "its string pool lies outside its table");
    nup->slots = (nup->pool_at - nup->slots_at) / 4;
    return dirs_check(nup) || files_check(nup) || packages_read(nup);
}

SnxNup* snx_nup_open(const char* path) {
    SnxNup* nup = (SnxNup*)calloc(1, sizeof *nup);
    unsigned char block[SUPERBLOCK_SIZE];
    char why[256];
    if (!nup) {
        snx_error("out of memory reading %s", path);
        return NULL;
    }
    nup->path = snx_strdup(path);
    nup->file_size = snx_file_size(path);
    nup->file = snx_fopen(path, "rb");
    if (!nup->file)
        snx_error("cannot read %s: %s", path, snx_os_error(why, sizeof why));
    else if (fread(block, 1, sizeof block, nup->file) != sizeof block || memcmp(block, "NUP\x01", 4))
        snx_error("%s is not a NUP this build reads (NUP, version 1)", path);
    else if (!toc_read(nup, block))
        return nup;
    snx_nup_close(nup);
    return NULL;
}

void snx_nup_close(SnxNup* nup) {
    if (!nup) return;
    if (nup->file) fclose(nup->file);
    free(nup->order);
    free(nup->toc);
    free(nup->path);
    free(nup);
}

int snx_nup_has_game(const SnxNup* nup) { return nup->has_game; }
unsigned snx_nup_updates(const SnxNup* nup) { return nup->layers - (unsigned)nup->has_game; }
unsigned snx_nup_dlcs(const SnxNup* nup) { return nup->ndlcs; }
void snx_nup_dlc(const SnxNup* nup, unsigned index, SnxU64* title, SnxU64* version) {
    *title = package_title(nup, nup->dlcs[index]);
    *version = package_version(nup, nup->dlcs[index]);
}

int snx_nup_title(const SnxNup* nup, SnxU64* title, SnxU64* game, SnxU64* version) {
    if (nup->has_game) {
        *title = *game = package_title(nup, nup->order[0]);
        *version = SNX_NO_VERSION;
    } else if (nup->layers) {
        unsigned newest = nup->order[nup->layers - 1];
        *game = title_game(package_title(nup, newest));
        *title = *game | PATCH_BIT;
        *version = package_version(nup, newest);
    } else if (nup->ndlcs) {
        snx_nup_dlc(nup, 0, title, version);
        *game = snx_addon_guess(*title);
    } else
        return snx_error("%s holds no game, update or DLC this build reads", nup->path);
    return 0;
}

unsigned char* snx_nup_meta(const SnxNup* nup, unsigned type, size_t* size) {
    for (unsigned layer = nup->layers; layer-- > 0;) {
        const unsigned char* package = package_at(nup, nup->order[layer]);
        SnxU64 at = snx_ld_le64(package + 0x20), left = snx_ld_le32(package + 0x28);
        while (at && left >= 8) {
            unsigned char head[8];
            SnxU64 payload;
            if (snx_seek(nup->file, at) || fread(head, 1, sizeof head, nup->file) != sizeof head) return NULL;
            payload = snx_ld_le32(head + 4);
            if (payload > left - 8) break;
            if (snx_ld_le16(head) == type) {
                unsigned char* copy = (unsigned char*)malloc(payload ? (size_t)payload : 1);
                if (copy && fread(copy, 1, (size_t)payload, nup->file) == payload) {
                    *size = (size_t)payload;
                    return copy;
                }
                free(copy);
                return NULL;
            }
            at += 8 + payload;
            left -= 8 + payload;
        }
    }
    return NULL;
}

/* what path, below a tree at dir, is in it: a part that is a file ends the search */
static int node_find(const SnxNup* nup, SnxU32 dir, const char* path) {
    for (;;) {
        const unsigned char* record = dir_at(nup, dir);
        SnxU64 low = snx_ld_le32(record + 8), high = low + snx_ld_le32(record + 12);
        size_t part = 0;
        SnxU32 found = NO_DIR;
        while (path[part] && path[part] != '/' && path[part] != '\\') ++part;
        while (low < high) {
            SnxU64 middle = low + (high - low) / 2;
            SnxU32 child = slot_at(nup, middle);
            size_t size;
            const char* name = node_name(nup, child, &size);
            int order = name_order(path, part, name, size);
            if (!order) {
                found = child;
                break;
            }
            if (order < 0)
                high = middle;
            else
                low = middle + 1;
        }
        if (found == NO_DIR) return NODE_NONE;
        if (found >= nup->dirs) return NODE_FILE;
        if (!path[part]) return NODE_DIR;
        dir = found;
        path += part + 1;
    }
}
/* what the layers above this walk's have at path: the strongest, a file over a folder */
static int covered(const Walk* walk, const char* path) {
    const SnxNupView* view = walk->view;
    int cover = NODE_NONE;
    for (unsigned layer = walk->layer + 1; layer < view->count; ++layer) {
        const Layer* above = &view->layers[layer];
        SnxU32 romfs = package_romfs(above->nup, above->package);
        int found = romfs == NO_DIR ? NODE_NONE : node_find(above->nup, romfs, path);
        if (found > cover) cover = found;
    }
    return cover;
}

static int file_fail(const char* path, const char* what) { return snx_error("cannot read %s: %s", path, what); }

/* n bytes of the file's content: hashed, written, counted */
static int content_put(Walk* walk, FILE* to, const char* path, const unsigned char* bytes, size_t n) {
    if (!EVP_DigestUpdate(walk->view->sha, bytes, n)) return file_fail(path, "its hash failed");
    if (fwrite(bytes, 1, n, to) != n) return file_fail(path, "the disk may be full");
    walk->bytes += n;
    if (walk->progress) walk->progress(walk->bytes, walk->data);
    return 0;
}

/* the file's stored bytes from where they lie into to, decompressed as its codec says */
static int content_copy(Walk* walk, const SnxNup* nup, const unsigned char* record, FILE* to, const char* path) {
    SnxNupView* view = walk->view;
    SnxU64 size = snx_ld_le64(record + 8), left = snx_ld_le64(record + 0x18), made = 0;
    int zstd = record[0x40] == CODEC_ZSTD;
    size_t ended = 1; /* zstd's hint: 0 once its frame is whole */
    if (left && snx_seek(nup->file, snx_ld_le64(record + 0x10))) return file_fail(path, "the NUP cannot be read");
    if (zstd && ZSTD_isError(ZSTD_DCtx_reset(view->zstd, ZSTD_reset_session_only)))
        return file_fail(path, "zstd failed");
    while (left) {
        size_t n = left < CHUNK_SIZE ? (size_t)left : CHUNK_SIZE;
        ZSTD_inBuffer input;
        if (fread(view->in, 1, n, nup->file) != n) return file_fail(path, "the NUP cannot be read");
        left -= n;
        if (!zstd) {
            if (content_put(walk, to, path, view->in, n)) return 1;
            made += n;
            continue;
        }
        input = (ZSTD_inBuffer){view->in, n, 0};
        while (input.pos < input.size) {
            ZSTD_outBuffer output = {view->out, CHUNK_SIZE, 0};
            if (!ended) return file_fail(path, "bytes follow its zstd frame");
            ended = ZSTD_decompressStream(view->zstd, &output, &input);
            if (ZSTD_isError(ended)) return file_fail(path, ZSTD_getErrorName(ended));
            made += output.pos;
            if (made > size) return file_fail(path, "it is larger than the NUP says");
            if (output.pos && content_put(walk, to, path, view->out, output.pos)) return 1;
        }
    }
    /* the last output of a frame can wait in zstd for room that the loop above gave it */
    while (zstd && ended && snx_ld_le64(record + 0x18)) {
        ZSTD_inBuffer input = {view->in, 0, 0};
        ZSTD_outBuffer output = {view->out, CHUNK_SIZE, 0};
        ended = ZSTD_decompressStream(view->zstd, &output, &input);
        if (ZSTD_isError(ended)) return file_fail(path, ZSTD_getErrorName(ended));
        if (!output.pos) return file_fail(path, "its zstd frame is cut short");
        made += output.pos;
        if (made > size) return file_fail(path, "it is larger than the NUP says");
        if (content_put(walk, to, path, view->out, output.pos)) return 1;
    }
    return made == size ? 0 : file_fail(path, "it is smaller than the NUP says");
}

static int file_write(Walk* walk, const SnxNup* nup, const unsigned char* record, const char* path) {
    SnxNupView* view = walk->view;
    unsigned char hash[HASH_SIZE];
    unsigned digest_size = 0;
    char why[256];
    FILE* to = snx_fopen(path, "wb");
    int failed;
    if (!to) return snx_error("cannot write %s: %s", path, snx_os_error(why, sizeof why));
    failed = !EVP_DigestInit_ex(view->sha, EVP_sha256(), NULL) ? file_fail(path, "its hash failed")
                                                               : content_copy(walk, nup, record, to, path);
    if (fclose(to) && !failed) failed = file_fail(path, "the disk may be full");
    if (failed) return 1;
    if (!EVP_DigestFinal_ex(view->sha, hash, &digest_size) || memcmp(hash, record + 0x20, HASH_SIZE))
        return file_fail(path, "its content does not match its hash, so the NUP is damaged");
    return 0;
}

/* the directory named name under parent in the tree, added where its order among its siblings puts it */
static SnxU32 tree_dir(Tree* tree, SnxU32 parent, const char* name, size_t size) {
    SnxU32 at = tree->dirs[parent].child, last = ROM_NONE;
    while (at != ROM_NONE) {
        int order = name_order(name, size, tree->dirs[at].name, tree->dirs[at].size);
        if (!order) return at;
        if (order < 0) break;
        last = at;
        at = tree->dirs[at].sibling;
    }
    SnxU32 made = tree->ndirs++;
    tree->dirs[made] = (TreeDir){name, size, parent, ROM_NONE, at, ROM_NONE, 0};
    if (last == ROM_NONE)
        tree->dirs[parent].child = made;
    else
        tree->dirs[last].sibling = made;
    return made;
}

static int tree_walk(Walk* walk, const SnxNup* nup, SnxU32 dir, const char* path, SnxU32 into) {
    const unsigned char* record = dir_at(nup, dir);
    SnxU64 first = snx_ld_le32(record + 8), count = snx_ld_le32(record + 12);
    int failed = walk->mode == WALK_WRITE && snx_mkdirs(path) ? snx_error("cannot create %s", path) : 0;
    for (SnxU64 i = first; !failed && i < first + count; ++i) {
        SnxU32 child = slot_at(nup, i);
        size_t size;
        const char* label = node_name(nup, child, &size);
        char name[NAME_MAX_SIZE + 1], *to;
        int cover;
        memcpy(name, label, size);
        name[size] = 0;
        to = snx_path_join(path, name);
        if (!to) return snx_error("out of memory reading %s", nup->path);
        cover = covered(walk, to + walk->root);
        if (child < nup->dirs) {
            if (cover != NODE_FILE)
                failed = tree_walk(walk, nup, child, to,
                                   walk->mode == WALK_TREE ? tree_dir(walk->tree, into, label, size) : 0);
        } else if (cover == NODE_NONE) {
            SnxU32 index = (SnxU32)(child - nup->dirs);
            const unsigned char* file = file_at(nup, index);
            if (walk->mode == WALK_WRITE)
                failed = file_write(walk, nup, file, to);
            else if (walk->mode == WALK_COUNT)
                walk->bytes += snx_ld_le64(file + 8);
            else
                walk->tree->files[walk->tree->nfiles++] =
                    (TreeFile){label, size, into, index, walk->layer, snx_ld_le64(file + 8)};
        }
        free(to);
    }
    return failed;
}

/* tree of the layer into folder: its paths below folder are what covered looks up */
static int layer_walk(Walk* walk, const SnxNup* nup, SnxU32 tree, unsigned layer, const char* folder) {
    char* probe = snx_path_join(folder, "x");
    if (!probe) return snx_error("out of memory reading %s", nup->path);
    walk->layer = layer;
    walk->root = strlen(probe) - 1;
    free(probe);
    return tree_walk(walk, nup, tree, folder, 0);
}

/* each layer's RomFS, from newest to oldest */
static int romfs_walk(Walk* walk, const char* romfs) {
    SnxNupView* view = walk->view;
    if (view->no_romfs) return 0;
    for (unsigned layer = view->count; layer-- > 0;) {
        const Layer* at = &view->layers[layer];
        SnxU32 dir = package_romfs(at->nup, at->package);
        if (dir != NO_DIR && layer_walk(walk, at->nup, dir, layer, romfs)) return 1;
    }
    return 0;
}
/* the ExeFS of the newest layer with one, then the RomFS */
static int game_walk(Walk* walk, const char* exefs, const char* romfs) {
    SnxNupView* view = walk->view;
    if (view->exefs) {
        const Layer* at = &view->layers[view->exefs_layer];
        if (layer_walk(walk, at->nup, package_exefs(at->nup, at->package), view->count, exefs)) return 1;
    }
    return romfs_walk(walk, romfs);
}

SnxU64 snx_nup_bytes(SnxNupView* view) {
    Walk walk = {0};
    walk.view = view;
    return game_walk(&walk, "exefs", "romfs") ? 0 : walk.bytes;
}

int snx_nup_extract(SnxNupView* view, const char* exefs, const char* romfs,
                    void (*progress)(uint64_t written, void* data), void* data) {
    Walk walk = {0};
    if (!view->sha) view->sha = EVP_MD_CTX_new();
    if (!view->sha) return snx_error("out of memory extracting a NUP");
    view->stream = NULL; /* its decoder and buffers are the extraction's now */
    walk.view = view;
    walk.mode = WALK_WRITE;
    walk.progress = progress;
    walk.data = data;
    return game_walk(&walk, exefs, romfs);
}

static SnxU64 entry_size(unsigned fixed, size_t name) { return fixed + ((name + 3) & ~(size_t)3); }

/* by directory, then name: siblings next to each other, as the table chains them */
static int tree_file_order(const void* a, const void* b) {
    const TreeFile *x = (const TreeFile*)a, *y = (const TreeFile*)b;
    if (x->parent != y->parent) return x->parent < y->parent ? -1 : 1;
    return name_order(x->name, x->size, y->name, y->size);
}

/* the tree as an image's header and tables, laid out as romfs_build lays them (fs.c), its files in view->files */
static int image_lay(SnxNupView* view, Tree* tree) {
    SnxU64 dir_bytes = 0, file_bytes = 0, data = 0;
    SnxU32 dbuckets = snx_romfs_buckets(tree->ndirs), fbuckets = snx_romfs_buckets(tree->nfiles);
    for (SnxU32 i = 0; i < tree->ndirs; ++i) {
        tree->dirs[i].offset = (SnxU32)dir_bytes;
        dir_bytes += entry_size(ROM_DIR_ENTRY, tree->dirs[i].size);
    }
    for (SnxU32 i = 0; i < tree->nfiles; ++i) file_bytes += entry_size(ROM_FILE_ENTRY, tree->files[i].size);
    if (dir_bytes >= ROM_NONE || file_bytes >= ROM_NONE) return snx_error("the RomFS of a NUP has too many files");
    SnxU64 dhash = 0x50, dtab = dhash + (SnxU64)dbuckets * 4, fhash = dtab + dir_bytes;
    SnxU64 ftab = fhash + (SnxU64)fbuckets * 4, end = ftab + file_bytes;
    unsigned char* m = (unsigned char*)calloc(1, (size_t)end);
    view->files = (ImageFile*)malloc(sizeof *view->files * (tree->nfiles ? tree->nfiles : 1));
    if (!m || !view->files) {
        free(m);
        return snx_error("out of memory reading a NUP");
    }
    memset(m + dhash, 0xff, (size_t)dbuckets * 4);
    memset(m + fhash, 0xff, (size_t)fbuckets * 4);
    qsort(tree->files, tree->nfiles, sizeof *tree->files, tree_file_order);
    SnxU32 off = 0;
    for (SnxU32 i = 0; i < tree->nfiles; ++i) {
        const TreeFile* file = &tree->files[i];
        TreeDir* dir = &tree->dirs[file->parent];
        int last = i + 1 == tree->nfiles || tree->files[i + 1].parent != file->parent;
        SnxU32 next = off + (SnxU32)entry_size(ROM_FILE_ENTRY, file->size);
        SnxU32 bucket = snx_romfs_hash(dir->offset, file->name, file->size) % fbuckets;
        unsigned char* e = m + ftab + off;
        if (dir->first_file == ROM_NONE) dir->first_file = off;
        data = (data + 15) & ~(SnxU64)15;
        snx_st_le32(e, dir->offset);
        snx_st_le32(e + 4, last ? ROM_NONE : next);
        snx_st_le64(e + 8, data);
        snx_st_le64(e + 16, file->bytes);
        memcpy(e + 24, m + fhash + (SnxU64)bucket * 4, 4);
        snx_st_le32(m + fhash + (SnxU64)bucket * 4, off);
        snx_st_le32(e + 28, (SnxU32)file->size);
        memcpy(e + ROM_FILE_ENTRY, file->name, file->size);
        if (file->bytes) view->files[view->nfiles++] = (ImageFile){data, file->bytes, file->layer, file->file};
        data += file->bytes;
        off = next;
    }
    for (SnxU32 i = 0; i < tree->ndirs; ++i) {
        const TreeDir* dir = &tree->dirs[i];
        SnxU32 parent = tree->dirs[dir->parent].offset;
        SnxU32 bucket = snx_romfs_hash(parent, dir->name, dir->size) % dbuckets;
        unsigned char* e = m + dtab + dir->offset;
        snx_st_le32(e, parent);
        snx_st_le32(e + 4, dir->sibling == ROM_NONE ? ROM_NONE : tree->dirs[dir->sibling].offset);
        snx_st_le32(e + 8, dir->child == ROM_NONE ? ROM_NONE : tree->dirs[dir->child].offset);
        snx_st_le32(e + 12, dir->first_file);
        memcpy(e + 16, m + dhash + (SnxU64)bucket * 4, 4);
        snx_st_le32(m + dhash + (SnxU64)bucket * 4, dir->offset);
        snx_st_le32(e + 20, (SnxU32)dir->size);
        memcpy(e + ROM_DIR_ENTRY, dir->name, dir->size);
    }
    view->meta = m;
    view->meta_size = end;
    view->data_at = (end + 0x1ff) & ~(SnxU64)0x1ff;
    for (size_t i = 0; i < view->nfiles; ++i) view->files[i].offset += view->data_at;
    view->total = view->data_at + data;
    snx_st_le64(m, 0x50);
    snx_st_le64(m + 8, dhash);
    snx_st_le64(m + 0x10, (SnxU64)dbuckets * 4);
    snx_st_le64(m + 0x18, dtab);
    snx_st_le64(m + 0x20, dir_bytes);
    snx_st_le64(m + 0x28, fhash);
    snx_st_le64(m + 0x30, (SnxU64)fbuckets * 4);
    snx_st_le64(m + 0x38, ftab);
    snx_st_le64(m + 0x40, file_bytes);
    snx_st_le64(m + 0x48, view->data_at);
    return 0;
}

/* the merged RomFS of the view's layers, when one has a RomFS */
static int image_make(SnxNupView* view) {
    Tree tree = {0};
    Walk walk = {0};
    SnxU64 dirs = 1, files = 0;
    int any = 0, failed;
    if (view->no_romfs) return 0;
    for (unsigned i = 0; i < view->count; ++i) {
        const Layer* layer = &view->layers[i];
        any |= package_romfs(layer->nup, layer->package) != NO_DIR;
        dirs += layer->nup->dirs;
        files += layer->nup->files;
    }
    if (!any) return 0;
    tree.dirs = (TreeDir*)malloc(sizeof *tree.dirs * (size_t)dirs);
    tree.files = (TreeFile*)malloc(sizeof *tree.files * (size_t)(files ? files : 1));
    if (!tree.dirs || !tree.files) {
        free(tree.dirs);
        free(tree.files);
        return snx_error("out of memory reading a NUP");
    }
    tree.dirs[0] = (TreeDir){"", 0, 0, ROM_NONE, ROM_NONE, ROM_NONE, 0};
    tree.ndirs = 1;
    walk.view = view;
    walk.mode = WALK_TREE;
    walk.tree = &tree;
    failed = romfs_walk(&walk, "romfs") || image_lay(view, &tree);
    free(tree.dirs);
    free(tree.files);
    return failed;
}

/* the top files of the newest layer with an ExeFS, which a directory's sorted children give by name */
static int exefs_list(SnxNupView* view) {
    for (unsigned layer = view->count; layer-- > 0;) {
        const SnxNup* nup = view->layers[layer].nup;
        SnxU32 dir = package_exefs(nup, view->layers[layer].package);
        if (dir == NO_DIR) continue;
        const unsigned char* record = dir_at(nup, dir);
        SnxU64 first = snx_ld_le32(record + 8), count = snx_ld_le32(record + 12);
        view->exefs_layer = layer;
        view->exefs = (SnxU32*)malloc(sizeof *view->exefs * (size_t)(count ? count : 1));
        view->exefs_names = (char(*)[NAME_MAX_SIZE + 1])malloc(sizeof *view->exefs_names * (size_t)(count ? count : 1));
        if (!view->exefs || !view->exefs_names) return snx_error("out of memory reading a NUP");
        for (SnxU64 i = first; i < first + count; ++i) {
            SnxU32 child = slot_at(nup, i);
            size_t size;
            const char* name = node_name(nup, child, &size);
            if (child < nup->dirs) continue;
            memcpy(view->exefs_names[view->nexefs], name, size);
            view->exefs_names[view->nexefs][size] = 0;
            view->exefs[view->nexefs++] = (SnxU32)(child - nup->dirs);
        }
        return 0;
    }
    return 0;
}

static SnxNupView* view_new(unsigned layers) {
    SnxNupView* view = (SnxNupView*)calloc(1, sizeof *view);
    if (view) view->layers = (Layer*)malloc(sizeof *view->layers * (layers ? layers : 1));
    if (view) view->in = (unsigned char*)malloc((size_t)CHUNK_SIZE * 2);
    if (view) view->zstd = ZSTD_createDCtx();
    if (!view || !view->layers || !view->in || !view->zstd) {
        snx_nup_view_free(view);
        snx_error("out of memory reading a NUP");
        return NULL;
    }
    view->out = view->in + CHUNK_SIZE;
    return view;
}
static SnxNupView* view_finish(SnxNupView* view) {
    if (!exefs_list(view) && !image_make(view)) return view;
    snx_nup_view_free(view);
    return NULL;
}

SnxNupView* snx_nup_game(SnxNup* base, SnxNup* update) {
    SnxNupView* view;
    if (base && !base->has_game) {
        snx_error("%s holds no game", base->path);
        return NULL;
    }
    if (update && !snx_nup_updates(update)) {
        snx_error("%s holds no update", update->path);
        return NULL;
    }
    if (base && update) {
        SnxU64 game = title_game(package_title(base, base->order[0]));
        SnxU64 own = title_game(package_title(update, update->order[update->layers - 1]));
        if (game != own) {
            snx_error("%s is not an update of %s", update->path, base->path);
            return NULL;
        }
    }
    view = view_new(2);
    if (!view) return NULL;
    if (base) view->layers[view->count++] = (Layer){base, base->order[0]};
    /* The newest update alone: a patch is made against the base, not against the one before it, so an older one's
       files can be what the newest took away. With an update given, it is played, not the one bundled with the game */
    SnxNup* patch = update ? update : base;
    if (snx_nup_updates(patch)) view->layers[view->count++] = (Layer){patch, patch->order[patch->layers - 1]};
    view->no_romfs = !base;
    return view_finish(view);
}

SnxNupView* snx_nup_aoc(SnxNup* nup, SnxU64 title) {
    for (unsigned i = 0; i < nup->ndlcs; ++i)
        if (package_title(nup, nup->dlcs[i]) == title) {
            SnxNupView* view = view_new(1);
            if (!view) return NULL;
            view->layers[view->count++] = (Layer){nup, nup->dlcs[i]};
            return view_finish(view);
        }
    snx_error("%s holds no DLC %016llx", nup->path, (unsigned long long)title);
    return NULL;
}

void snx_nup_view_free(SnxNupView* view) {
    if (!view) return;
    for (size_t i = 0; i < CACHE_SLOTS; ++i) free(view->cache[i].data);
    if (view->zstd) ZSTD_freeDCtx(view->zstd);
    if (view->sha) EVP_MD_CTX_free(view->sha);
    free(view->in);
    free(view->meta);
    free(view->files);
    free(view->exefs);
    free(view->exefs_names);
    free(view->layers);
    free(view);
}

SnxU64 snx_nup_version(const SnxNupView* view) {
    const Layer* newest = &view->layers[view->count - 1];
    return package_kind(newest->nup, newest->package) == KIND_UPDATE ? package_version(newest->nup, newest->package)
                                                                     : SNX_NO_VERSION;
}
size_t snx_nup_exefs_count(const SnxNupView* view) { return view->nexefs; }
void snx_nup_exefs_file(const SnxNupView* view, size_t file, const char** name, SnxU64* size) {
    const SnxNup* nup = view->layers[view->exefs_layer].nup;
    *name = view->exefs_names[file];
    *size = snx_ld_le64(file_at(nup, view->exefs[file]) + 8);
}
SnxU64 snx_nup_image_size(const SnxNupView* view) { return view->total; }

/* a slot for size bytes, freed of what was used longest ago until they fit */
static Cached* cache_room(SnxNupView* view, SnxU64 size) {
    for (;;) {
        Cached* oldest = NULL;
        Cached* empty = NULL;
        for (size_t i = 0; i < CACHE_SLOTS; ++i) {
            Cached* slot = &view->cache[i];
            if (!slot->data)
                empty = slot;
            else if (!oldest || slot->used < oldest->used)
                oldest = slot;
        }
        if (empty && view->cached + size <= CACHE_BYTES) return empty;
        view->cached -= oldest->size;
        free(oldest->data);
        *oldest = (Cached){0};
    }
}

/* the small zstd file decoded whole, kept, or NULL, said why */
static const unsigned char* cache_file(SnxNupView* view, const SnxNup* nup, const unsigned char* record) {
    SnxU64 extent = snx_ld_le64(record + 0x10), stored = snx_ld_le64(record + 0x18), size = snx_ld_le64(record + 8);
    Cached* slot;
    unsigned char *packed, *data;
    size_t made;
    for (size_t i = 0; i < CACHE_SLOTS; ++i)
        if (view->cache[i].data && view->cache[i].nup == nup && view->cache[i].extent == extent) {
            view->cache[i].used = ++view->tick;
            return view->cache[i].data;
        }
    packed = (unsigned char*)malloc((size_t)stored);
    data = (unsigned char*)malloc((size_t)size);
    if (!packed || !data || snx_seek(nup->file, extent) || fread(packed, 1, (size_t)stored, nup->file) != stored) {
        free(packed);
        free(data);
        file_fail(nup->path, "a file of it cannot be read");
        return NULL;
    }
    view->stream = NULL; /* this uses the decoder a stream's state is in */
    made = ZSTD_decompressDCtx(view->zstd, data, (size_t)size, packed, (size_t)stored);
    free(packed);
    if (ZSTD_isError(made) || made != size) {
        free(data);
        file_fail(nup->path, "a zstd file of it is damaged");
        return NULL;
    }
    slot = cache_room(view, size);
    *slot = (Cached){nup, extent, size, ++view->tick, data};
    view->cached += size;
    return data;
}

/* size bytes at offset of a zstd file too large to keep: on from where the stream is, else from its start. A read
   before out's bytes decodes all that comes before it again */
static int stream_read(SnxNupView* view, const SnxNup* nup, const unsigned char* record, SnxU64 offset,
                       unsigned char* to, size_t size) {
    SnxU64 extent = snx_ld_le64(record + 0x10);
    if (view->stream != nup || view->stream_extent != extent || offset < view->start) {
        if (ZSTD_isError(ZSTD_DCtx_reset(view->zstd, ZSTD_reset_session_only)))
            return file_fail(nup->path, "zstd failed");
        view->stream = nup;
        view->stream_extent = extent;
        view->start = view->end = 0;
        view->next = extent;
        view->left = snx_ld_le64(record + 0x18);
        view->input = (ZSTD_inBuffer){view->in, 0, 0};
    }
    while (size) {
        if (offset >= view->start && offset < view->end) {
            SnxU64 have = view->end - offset;
            size_t n = have < size ? (size_t)have : size;
            memcpy(to, view->out + (offset - view->start), n);
            to += n;
            offset += n;
            size -= n;
            continue;
        }
        if (view->input.pos == view->input.size) {
            size_t n = view->left < CHUNK_SIZE ? (size_t)view->left : CHUNK_SIZE;
            if (n && (snx_seek(nup->file, view->next) || fread(view->in, 1, n, nup->file) != n)) {
                view->stream = NULL;
                return file_fail(nup->path, "a file of it cannot be read");
            }
            view->next += n;
            view->left -= n;
            view->input = (ZSTD_inBuffer){view->in, n, 0};
        }
        ZSTD_outBuffer output = {view->out, CHUNK_SIZE, 0};
        size_t ended = ZSTD_decompressStream(view->zstd, &output, &view->input);
        if (ZSTD_isError(ended) || (!output.pos && !view->left && view->input.pos == view->input.size)) {
            view->stream = NULL;
            return file_fail(nup->path, "a zstd file of it is damaged");
        }
        view->start = view->end;
        view->end += output.pos;
    }
    return 0;
}

/* size bytes at offset of the layer's file, which the caller has kept inside it */
static int file_read(SnxNupView* view, unsigned layer, SnxU32 file, SnxU64 offset, unsigned char* to, size_t size) {
    const SnxNup* nup = view->layers[layer].nup;
    const unsigned char* record = file_at(nup, file);
    if (!size) return 0;
    if (record[0x40] == CODEC_RAW) {
        if (snx_seek(nup->file, snx_ld_le64(record + 0x10) + offset) || fread(to, 1, size, nup->file) != size)
            return file_fail(nup->path, "a file of it cannot be read");
        return 0;
    }
    if (snx_ld_le64(record + 8) > NUP_CACHE_FILE_MAX) return stream_read(view, nup, record, offset, to, size);
    const unsigned char* data = cache_file(view, nup, record);
    if (!data) return 1;
    memcpy(to, data + offset, size);
    return 0;
}

int snx_nup_exefs_read(SnxNupView* view, size_t file, SnxU64 offset, void* buffer, size_t size) {
    SnxU64 total = snx_ld_le64(file_at(view->layers[view->exefs_layer].nup, view->exefs[file]) + 8);
    if (offset > total || size > total - offset) return snx_error("an ExeFS read past its file in a NUP");
    return file_read(view, view->exefs_layer, view->exefs[file], offset, (unsigned char*)buffer, size);
}

int snx_nup_image_read(SnxNupView* view, SnxU64 offset, void* buffer, size_t size) {
    unsigned char* to = (unsigned char*)buffer;
    if (offset > view->total || size > view->total - offset) return snx_error("a RomFS read past its image in a NUP");
    while (size) {
        size_t low = 0, high = view->nfiles, n;
        SnxU64 next = view->total;
        if (offset < view->meta_size) {
            SnxU64 have = view->meta_size - offset;
            n = have < size ? (size_t)have : size;
            memcpy(to, view->meta + offset, n);
        } else {
            while (low < high) { /* the first file past offset: the one before it may hold offset */
                size_t middle = low + (high - low) / 2;
                if (view->files[middle].offset <= offset)
                    low = middle + 1;
                else
                    high = middle;
            }
            if (low < view->nfiles) next = view->files[low].offset;
            const ImageFile* file = low ? &view->files[low - 1] : NULL;
            if (file && offset < file->offset + file->size) {
                SnxU64 have = file->offset + file->size - offset;
                n = have < size ? (size_t)have : size;
                if (file_read(view, file->layer, file->file, offset - file->offset, to, n)) return 1;
            } else { /* the padding before the next file's data */
                SnxU64 have = next - offset;
                n = have < size ? (size_t)have : size;
                memset(to, 0, n);
            }
        }
        to += n;
        offset += n;
        size -= n;
    }
    return 0;
}
