#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "lib/kernel/hash.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "vm/page.h"

enum frame_types
{
  STACK, /* Frame contains a page for a stack */
  FILE,  /* Frame contains a page for a file */
  MMAP,  /* Frame contains a page for a mmap */
};

struct pd_share
{
  struct list_elem elem;
  uint32_t *pd;
};

struct frame
{
  void *kpage;               /* Address of page in kernel virtual memory */
  void *upage;               /* Address of page in user virtual memory */
  struct file *file;         /* Pointer to a the file this frame is storing */
  struct thread *owner;      /* Pointer to thread which owns the page */
  struct hash_elem hashelem; /* Hash element for frame hash table */
  struct list_elem listelem; /* List element for frame list */
  enum frame_types type;     /* Boolean value for whether the page is writable */
  struct lock lock;          /* Lock for synchronizing access to the frame hash table */
  struct list shared;        /* List of pds that have installed this frame */
};

/* Initialization */
void ft_init(void);

/* Controller Functions */
struct frame *ft_request_frame(enum palloc_flags, void *);
void ft_update(struct frame *);
struct frame *ft_search_frame(void *);
void ft_remove_frame(struct frame *);
void ft_destroy_frame(struct frame *);
struct frame *ft_evict(void);
void ft_add_pd_to_frame(struct frame *, uint32_t *);
void ft_destroy_frame_sharing(struct frame *);

/* Frame list functions */
struct frame *frame_list_find(struct page_info *);
#endif /* vm/frame.h */