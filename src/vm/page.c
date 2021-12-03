#include <string.h>
#include "vm/page.h"
#include "vm/frame.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "lib/kernel/hash.h"

static unsigned sp_table_hash_func(const struct hash_elem *, void *UNUSED);
bool sp_table_less_func(const struct hash_elem *,
                        const struct hash_elem *, void *UNUSED);
void sp_destroy_page_info(struct hash_elem *, void *UNUSED);

void sp_init(void)
{
  struct thread *cur = thread_current();
  hash_init(&cur->sp_table, sp_table_hash_func, sp_table_less_func, NULL);
  lock_init(&cur->sp_table_lock);
}

void start_sp_access(void)
{
  lock_acquire(&thread_current()->sp_table_lock);
}

void end_sp_access(void)
{
  lock_release(&thread_current()->sp_table_lock);
}

void sp_insert_page_info(struct page_info *page_info)
{
  /* If page_read_bytes is 0, then page_zero_bytes is PGSIZE */
  if (page_info->page_read_bytes == 0)
  {
    page_info->page_status = PAGE_ZERO;
  }
  /* Insert the newly created page_info into this process' sp_table */
  /* Insert page metadata into hash table through hash_replace due to GCC
     complications where the same code can be inserted in the same segment */
  start_sp_access();
  struct hash_elem *old_e = hash_replace(&thread_current()->sp_table, &page_info->elem);
  struct page_info *old_info;
  /* If something has been replaced it means that this page_info was the old
     info. Free it as it is no longer needed */
  if (old_e)
  {
    old_info = hash_entry(old_e, struct page_info, elem);
    page_info->writable = old_info->writable || page_info->writable;
    free(old_info);
  }
  end_sp_access();
}

struct page_info *sp_search_page_info(void *upage)
{
  start_sp_access();
  struct page_info dummy_page_info;
  struct hash_elem *e;
  dummy_page_info.upage = upage;
  e = hash_find(&thread_current()->sp_table, &dummy_page_info.elem);
  end_sp_access();
  if (!e)
  {
    return NULL;
  }
  return hash_entry(e, struct page_info, elem);
}

/* Removes a frame from the frame table. This is used by ft_destroy_frame
   when the vm is trying to free frames */
void sp_destroy_page_info(struct hash_elem *e, void *aux UNUSED)
{
  struct page_info *to_remove = hash_entry(e, struct page_info, elem);
  struct frame *frame_to_free = to_remove->frame;
  if (frame_to_free)
  {
    /* kpage is set to NULL because the page has been wiped when
       pagedir_destroy was called. ft_destroy_frame() will not free pages
       if the pointer of the frame is NULL */
    frame_to_free->kpage = NULL;
    ft_destroy_frame(frame_to_free);
  }
  hash_delete(&thread_current()->sp_table, e);
  free(to_remove);
}

/* Destroys a frame, removing it from the frame table, freeing the page, and
   also frees the frame. */
void sp_destroy_complete(void)
{
  /* No need to acquire lock here since ft_remove will do so.
     Moreover, the next actions are independent from the frame table. */
  start_sp_access();
  hash_destroy(&thread_current()->sp_table, sp_destroy_page_info);
  end_sp_access();
}

unsigned sp_table_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
  return (unsigned)hash_entry(e, struct page_info, elem)->upage;
}

bool sp_table_less_func(const struct hash_elem *e1,
                        const struct hash_elem *e2, void *aux UNUSED)
{
  return hash_entry(e1, struct page_info, elem)->upage <
         hash_entry(e2, struct page_info, elem)->upage;
}