#ifndef VM_SWAP_H
#define VM_SWAP_H

#include <bitmap.h>
#include "lib/kernel/hash.h"
#include "threads/palloc.h"
#include "threads/synch.h"

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)
#define SWAP_START_INDEX 0
#define SWAP_SINGLE_SPACE 1
#define NOT_OCCUPIED 1
#define OCCUPIED 0

struct swap
{
  struct bitmap *swap_bitmap; /* Bitmap for indication which index is occupied */
  struct block *block;        /* Block device */
};

/* Initialization */
void st_init(void);

/* Controller Functions */
size_t st_insert(void *);
void st_retrieve(size_t, void *);
void st_free(size_t);

#endif /* vm/swap.h */