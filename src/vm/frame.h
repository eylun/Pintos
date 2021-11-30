#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "lib/kernel/hash.h"
#include "threads/palloc.h"
#include "threads/synch.h"

struct frame
{
  void *kpage;
  void *upage;
  struct thread *owner;
  struct hash_elem elem;
  struct lock lock;
};

/* Initialization */
void ft_init(void);

/* Controller Functions */
struct frame *ft_request_frame(enum palloc_flags, void *);
void ft_update(struct frame *);
struct frame *ft_search_frame(void *);
void ft_remove_frame(struct frame *);
void ft_destroy_frame(struct frame *);
#endif /* vm/frame.h */