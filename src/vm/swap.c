#include <string.h>
#include <bitmap.h>
#include "vm/swap.h"
#include "vm/page.h"
#include "devices/block.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "lib/kernel/hash.h"

/* The Swap Table does not need to be an actual table since the swap index of
   each swapped page is stored in the supplemental page table.
   When writing to the swap table, update the page index of the SPT.
   When reading from the swap table, use the page index of the SPT to retrieve
   the page from the block. */
static struct swap st;

/* Lock for frame table actions */
static struct lock swap_table_lock;

static void start_st_access(void);
static void end_st_access(void);
static void write_to_block(size_t, void *);
static void read_from_block(size_t, void *);

void st_init(void);

void st_init(void)
{
  /* Initialize swap block */
  st.block = block_get_role(BLOCK_SWAP);
  /* Use the size of the swap block to determine how big our bitmap needs
     to be */
  st.swap_bitmap = bitmap_create(block_size(st.block) / SECTORS_PER_PAGE);
  lock_init(&swap_table_lock);
}

static void start_st_access(void)
{
  lock_acquire(&swap_table_lock);
}

static void end_st_access(void)
{
  lock_release(&swap_table_lock);
}

/* Insert a page into the swap table. The caller of this function needs to
   set the supplemental page table value for this page to the index returned,
   as well as freeing the frame and page. */
size_t st_insert(void *kpage)
{
  start_st_access();
  size_t free_index = bitmap_scan_and_flip(st.swap_bitmap, SWAP_START_INDEX, SWAP_SINGLE_SPACE, OCCUPIED);
  /* ST access can be ended here since block writing is synchronized internally */
  end_st_access();
  /* When a BITMAP_ERROR is returned from bitmap_scan_and_flip, the swap
     table is out of space. Do not make any operation and just return it.
     The caller will handle the rest. */
  if (free_index != BITMAP_ERROR)
  {
    write_to_block(free_index, kpage);
  }
  return free_index;
}

/* Retrieve a page from the swap table. The caller of this function needs to
   unset the supplemental page table value for this page.
   It can be assumed that kpage points to the start of a page that has been
   allocated and that a frame has already been created. */
void st_retrieve(size_t index, void *kpage)
{
  start_st_access();
  ASSERT(bitmap_test(st.swap_bitmap, index) != 0);
  read_from_block(index, kpage);
  bitmap_flip(st.swap_bitmap, index);
  end_st_access();
}

/* Use the index to free the swap space. By flipping the bit, we allow future
   processes to overwrite the block space that was previously occupied. */
void st_free(size_t index)
{
  start_st_access();
  ASSERT(bitmap_test(st.swap_bitmap, index) != 0);
  bitmap_flip(st.swap_bitmap, index);
  end_st_access();
}

/* Write a page to the swap block. This function's sole purpose is to write,
   it will not do anything else. */
static void write_to_block(size_t index, void *kpage)
{
  for (int cnt = 0; cnt < SECTORS_PER_PAGE; ++cnt)
  {
    block_write(st.block,
                cnt + index * SECTORS_PER_PAGE,
                kpage + cnt * BLOCK_SECTOR_SIZE);
  }
}

/* Reads a page to the swap block. This function's sole purpose is to read,
   it will not do anything else. */
static void read_from_block(size_t index, void *kpage)
{
  for (int cnt = 0; cnt < SECTORS_PER_PAGE; ++cnt)
  {
    block_read(st.block,
               cnt + index * SECTORS_PER_PAGE,
               kpage + cnt * BLOCK_SECTOR_SIZE);
  }
}