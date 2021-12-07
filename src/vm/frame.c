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
  list_init(&new_frame->shared);
  new_frame->kpage = kpage;
  new_frame->upage = upage;
  new_frame->owner = thread_current();
  // printf("I am inserting a new frame at %x: kpage: %x upage: %x owner: %x\n", new_frame, kpage, upage, thread_current());
  lock_init(&new_frame->lock);
  hash_insert(&ft, &new_frame->hashelem);
  list_push_back(&frame_list, &new_frame->listelem);
  /* Update supplemental page table to reflect that the provided
     upage has a kpage */
  struct page_info *page_info = sp_search_page_info(thread_current(), upage);
  if (page_info)
  {
    struct thread *t = thread_current();
    start_sp_access(t);
    page_info->frame = new_frame;
    end_sp_access(t);
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

/* Evict a frame based on a LRU cache. This function loops through the frame
   list and checks whether each frame is accessed or not. Accessed frames will
   have their accessed bit reset to 0, and shifted to the back of the list. */
struct frame *ft_evict(void)
{
  struct frame *evictee;
  struct list_elem *e, *refresher;
  start_ft_access();
  e = list_begin(&frame_list);
  /* Loop through the frame list.
     If the current frame has been accessed, reset it and append it to the back
     of the list.
     If the current frame has not been accessed, it will be the evictee */
  while (e != list_end(&frame_list))
  {
    evictee = list_entry(e, struct frame, listelem);
    /* If the page has not been accessed, it will be used as the evictee */
    if (!pagedir_is_accessed(evictee->owner->pagedir, evictee->upage))
    {
      /* Remove this frame from the frame table and the frame list */
      ft_remove_frame(evictee);
      end_ft_access();
      return evictee;
    }
    /* If the page has been accessed, reset it and append it to the back */
    else
    {
      pagedir_set_accessed(evictee->owner->pagedir, evictee->upage, false);
      refresher = e;
      e = list_remove(e);
      list_push_back(&frame_list, refresher);
    }
  }
  end_ft_access();
  return evictee;
}

/* Removes a frame from the frame table. This is used by ft_destroy_frame
   when the vm is trying to free frames */
void ft_remove_frame(struct frame *frame)
{
  hash_delete(&ft, &frame->hashelem);
  list_remove(&frame->listelem);
}

/* Destroys a frame, removing it from the frame table, freeing the page, and
   also frees the frame. */
void ft_destroy_frame(struct frame *frame)
{
  lock_acquire(&frame->lock);
  start_ft_access();
  ft_remove_frame(frame);
  end_ft_access();
  /* If this frame's owner is destroying it.
     Free page and unset the page for all other threads using this page */
  if (frame->owner == thread_current())
  {
    ft_destroy_frame_sharing(frame);
    if (frame->kpage)
    {
      palloc_free_page(frame->kpage);
    }
    free(frame);
    /* No need to release lock as it no longer exists after free */
  }
  /* If this process is not the owner of this frame, just remove itself from
     the share list */
  else
  {
    struct list_elem *e;
    struct pd_share *share;
    for (e = list_begin(&frame->shared); e != list_end(&frame->shared); e = list_next(e))
    {
      share = list_entry(e, struct pd_share, elem);
      if (share->pd == thread_current()->pagedir)
      {
        list_remove(&share->elem);
        break;
      }
    }
    free(share);
    lock_release(&frame->lock);
  }
}

/* Loop through the frame list to find a frame with a upage that contains a page
   that is read only (type = FILE) */
struct frame *frame_list_find(struct page_info *page_info)
{
  struct list_elem *e;
  struct frame *f;
  for (e = list_begin(&frame_list); e != list_end(&frame_list); e = list_next(e))
  {
    f = list_entry(e, struct frame, listelem);
    /* Identify a frame with the same upage and file */
    if (f->upage == page_info->upage && f->file == page_info->file)
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

void ft_add_pd_to_frame(struct frame *f, uint32_t *pd)
{
  lock_acquire(&f->lock);
  struct pd_share *share = malloc(sizeof(struct pd_share));
  if (!share)
  {
    PANIC("No more kernel memory");
  }
  share->pd = pd;
  list_push_back(&f->shared, &share->elem);
  lock_release(&f->lock);
}

void ft_destroy_frame_sharing(struct frame *f)
{
  start_ft_access();
  if (list_empty(&f->shared))
  {
    end_ft_access();
    return;
  }
  struct list_elem *e;
  struct pd_share *share;
  /* Using method provided in list.c for freeing list elements */
  while (!list_empty(&f->shared))
  {
    e = list_pop_front(&f->shared);
    share = list_entry(e, struct pd_share, elem);
    pagedir_clear_page(share, f->upage);
    free(share);
  }
  end_ft_access();
}

unsigned frame_table_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
  return (unsigned)hash_entry(e, struct frame, hashelem)->kpage;
}

bool frame_table_less_func(const struct hash_elem *e1,
                           const struct hash_elem *e2, void *aux UNUSED)
{
  return hash_entry(e1, struct frame, hashelem)->kpage <
         hash_entry(e2, struct frame, hashelem)->kpage;
}