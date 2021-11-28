#include "vm/frame.h"
#include <bitmap.h>
#include <string.h>
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/process.h"

static struct lock frame_table_lock;
static struct frame_table ft;

void ft_lock(void)
{
  lock_acquire(&frame_table_lock);
}

void ft_release(void)
{
  lock_release(&frame_table_lock);
}

void ft_init(void)
{
  lock_init(&frame_table_lock);
  ft.ft_bitmap = bitmap_create();
}

/* Hash function for frame table hash. Returns each frame's kernel page */
unsigned frame_table_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
  return (unsigned)hash_entry(e, struct frame, elem)->kpage;
}

bool frame_table_less_func(
    const struct hash_elem *e1, const struct hash_elem *e2, void *aux UNUSED)
{
  return hash_entry(e1, struct frame, elem)->kpage <
         hash_entry(e2, struct frame, elem)->kpage;
  ;
}