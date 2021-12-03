#include <string.h>
#include "vm/frame.h"
#include "vm/page.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "lib/kernel/hash.h"

/* The frame table is represented as a list.
   There is no fixed size.
   Whenever a new frame is to be added, it is appended to the back
   Whenever anything happens to a frame, it will be removed and reinserted
   to the back of the list.
   Whenever eviction needs to happen, pop directly from front of list as it
   will definitely be the least recently used frame */
static struct hash ft;

/* Helper list for two purposes:
   1. This list is used to implement our LRU cache for eviction.
   2. This list is used to implement sharing. All loading threads will
      iterate through this list before allocating any pages. */
static struct list frame_list;

/* Lock for frame table actions */
static struct lock frame_table_lock;

static void start_ft_access(void);
static void end_ft_access(void);

void ft_init(void);
unsigned frame_table_hash_func(const struct hash_elem *, void *UNUSED);
bool frame_table_less_func(
    const struct hash_elem *, const struct hash_elem *, void *UNUSED);

void ft_init(void)
{
  lock_init(&frame_table_lock);
  hash_init(&ft, frame_table_hash_func, frame_table_less_func, NULL);
  list_init(&frame_list);
}

static void start_ft_access(void)
{
  lock_acquire(&frame_table_lock);
}

static void end_ft_access(void)
{
  lock_release(&frame_table_lock);
}

/* Requests for a new frame and page.
   If a new page can be allocated, creates a new frame for this page and
   returns it.
   If a new page cannot be allocated, returns false. The controller will
   determine what to do next */
struct frame *ft_request_frame(enum palloc_flags flags, void *upage)
{
  ASSERT(check_page_alignment(upage));
  start_ft_access();
  void *kpage = palloc_get_page(flags);
  /* No more space, notify vm and attempt swapping */
  if (!kpage)
  {
    end_ft_access();
    return NULL;
  }
  /* There is space available, no swapping is necessary */
  struct frame *new_frame = malloc(sizeof(struct frame));
  /* Panic the kernel if new_frame is null. This means somehow the kernel
     pool is exhausted. This should not happen since there is a finite
     number of frames, and other structures that are allocated are freed
     appropriately. */
  ASSERT(new_frame != NULL);
  new_frame->kpage = kpage;
  lock_init(&new_frame->lock);
  hash_insert(&ft, &new_frame->hashelem);
  list_push_back(&frame_list, &new_frame->listelem);
  /* Update supplemental page table to reflect that the provided
     upage has a kpage */
  struct page_info *page_info = sp_search_page_info(upage);
  if (page_info)
  {
    page_info->frame = new_frame;
  }
  end_ft_access();
  return new_frame;
}

/* Looks up the frame table through the use of kernel pages. Checks for
   result will be performed by the caller. */
struct frame *ft_search_frame(void *kpage)
{
  start_ft_access();
  struct frame dummy_frame;
  struct hash_elem *e;
  dummy_frame.kpage = kpage;
  e = hash_find(&ft, &dummy_frame.hashelem);
  end_ft_access();
  if (!e)
  {
    return NULL;
  }
  return hash_entry(e, struct frame, hashelem);
}

/* Removes a frame from the frame table. This is used by ft_destroy_frame
   when the vm is trying to free frames */
void ft_remove_frame(struct frame *frame)
{
  start_ft_access();
  hash_delete(&ft, &frame->hashelem);
  list_remove(&frame->listelem);
  end_ft_access();
}

/* Destroys a frame, removing it from the frame table, freeing the page, and
   also frees the frame. */
void ft_destroy_frame(struct frame *frame)
{
  /* No need to acquire lock here since ft_remove will do so.
     Moreover, the next actions are independent from the frame table. */
  ft_remove_frame(frame);
  if (frame->kpage)
  {
    palloc_free_page(frame->kpage);
  }
  free(frame);
}

/* Loop through the frame list to find a frame with a upage that contains a page
   that is read only (type = FILE) */
struct frame *frame_list_find_upage(void *upage)
{
  struct list_elem *e;
  struct frame *f;
  for (e = list_begin(&frame_list); e != list_end(&frame_list); e = list_next(e))
  {
    f = list_entry(e, struct frame, listelem);
    /* Identify a frame with the same upage */
    if (f->upage == upage)
    {
      /* If the identified frame is not of type FILE, then it is
         not a read_only file. Hence it should not be shareable.
         We know there will never be two pages with the same upage mapping
         so we can break the loop and immediately return NULL */
      if (f->type != FILE)
      {
        return NULL;
      }
      return f;
    }
  }
  return NULL;
}

unsigned frame_table_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
  return (unsigned)hash_entry(e, struct frame, hashelem)->kpage;
}

bool frame_table_less_func(const struct hash_elem *e1,
                           const struct hash_elem *e2, void *aux UNUSED)
{
  return hash_entry(e1, struct frame, hashelem)->kpage <
         hash_entry(e2, struct frame, hashelem);
}