/* SPDX-License-Identifier: GPL-3.0-or-later
   Copyright 2026 the ScarletNX contributors */
/* A NUP (https://github.com/a55uka/nup, SPEC.md): a game's unencrypted ExeFS and RomFS trees, its updates and DLCs in
   one file, each file raw or a zstd frame. A view reads what a dump's NCAs give: the ExeFS's files and a RomFS image,
   which it makes up, its file data read where it lies. container.c puts a view behind SnxDump and SnxHacFs, so what
   reads a dump reads a NUP */
#ifndef SNX_NUP_H
#define SNX_NUP_H

#include "common/utilities/common.h"

typedef struct SnxNup SnxNup;
typedef struct SnxNupView SnxNupView;

/* what a package's meta block holds, by its record's type */
enum { SNX_NUP_META_NACP = 2, SNX_NUP_META_ICON = 3, SNX_NUP_META_NAME = 5 };

/* 1 for a file that starts as a NUP, else 0, saying nothing */
int snx_nup_is(const char* path);
/* path read and its table of contents checked: the hash, each bound, each name. NULL when it fails, said why */
SnxNup* snx_nup_open(const char* path);
void snx_nup_close(SnxNup* nup);
/* 1 when it holds a game, else 0: a NUP of updates or DLCs alone */
int snx_nup_has_game(const SnxNup* nup);
/* as snx_dump_title says it: a game's ID in title and game, else an add-on's own in title and its game in game, an
   update's as the console numbers it (ID with 0x800) whichever way its package does. version is the add-on's,
   SNX_NO_VERSION for a game. 0, else nonzero, said why: a NUP of nothing this reads */
int snx_nup_title(const SnxNup* nup, SnxU64* title, SnxU64* game, SnxU64* version);
/* how many updates it holds, and how many DLCs */
unsigned snx_nup_updates(const SnxNup* nup);
unsigned snx_nup_dlcs(const SnxNup* nup);
/* the DLC of index: its title ID and version */
void snx_nup_dlc(const SnxNup* nup, unsigned index, SnxU64* title, SnxU64* version);
/* the record of the type in the newest package that has one, malloc'd, its size in *size. NULL for none, or one that
   cannot be read */
unsigned char* snx_nup_meta(const SnxNup* nup, unsigned type, size_t* size);

/* What a dump's program reads. base is a NUP with a game, or NULL. update is a NUP of updates, or NULL for base's own:
   over base when it is given, else alone, its ExeFS with no RomFS as an update's patch alone has. They stay open while
   the view does. Of several updates only the newest is read, as a patch is made against the base. Its ExeFS replaces
   the base's whole, and its RomFS goes over the base's, by path. NULL when it fails, said why */
SnxNupView* snx_nup_game(SnxNup* base, SnxNup* update);
/* a DLC's RomFS. NULL when nup does not hold it, said why */
SnxNupView* snx_nup_aoc(SnxNup* nup, SnxU64 title);
void snx_nup_view_free(SnxNupView* view);
/* the newest update's version in the view, SNX_NO_VERSION without an update */
SnxU64 snx_nup_version(const SnxNupView* view);
/* the ExeFS's files: their count, then each one's name and size */
size_t snx_nup_exefs_count(const SnxNupView* view);
void snx_nup_exefs_file(const SnxNupView* view, size_t file, const char** name, SnxU64* size);
/* size bytes at offset of an ExeFS file: 0, or nonzero, said why */
int snx_nup_exefs_read(SnxNupView* view, size_t file, SnxU64 offset, void* buffer, size_t size);
/* the RomFS image's size, 0 without one */
SnxU64 snx_nup_image_size(const SnxNupView* view);
/* size bytes of the RomFS image at offset: 0, or nonzero, said why. Not thread safe, as hactool's reads are not */
int snx_nup_image_read(SnxNupView* view, SnxU64 offset, void* buffer, size_t size);
/* the bytes snx_nup_extract writes */
SnxU64 snx_nup_bytes(SnxNupView* view);
/* The view's files into two folders, each file's hash checked as it is written, progress (NULL for none) hearing the
   bytes written so far. 0, else nonzero, said why */
int snx_nup_extract(SnxNupView* view, const char* exefs, const char* romfs,
                    void (*progress)(uint64_t written, void* data), void* data);

#endif
