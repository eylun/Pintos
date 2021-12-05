#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "lib/kernel/hash.h"
#include "threads/palloc.h"
#include "threads/synch.h"

enum frame_types
{
  STACK, /* Frame contains a page for a stack */
  FILE,  /* Frame contains a page for a file */
  MMAP,  /* Frame contains a page for a mmap */
};
struct frame
{
  void *kpage;               /* Address of page in kernel virtual memory */
  void *upage;               /* Address of page in user virtual memory */
  struct thread *owner;      /* Pointer to thread which owns the page */
  struct hash_elem hashelem; /* Hash element for frame hash table */
  struct list_elem listelem; /* List element for frame list */
  enum frame_types type;     /* Boolean value for whether the page is writable */
  struct lock lock;          /* Lock for synchronizing access to the frame hash table */
};

/* Initialization */
void ft_init(void);

/* Controller Functions */
struct frame *ft_request_frame(enum palloc_flags, void *);
void ft_update(struct frame *);
struct frame *ft_search_frame(void *);
void ft_remove_frame(struct frame *);
void ft_destroy_frame(struct frame *);

/* Frame list functions */
struct frame *frame_list_find_upage(void *);
#endif /* vm/frame.h */