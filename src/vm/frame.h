#ifndef FRAME_H
#define FRAME_H

#include <hash.h>
#include <threads/palloc.h>

struct frame_table
{
  struct hash ft_hash;
  struct bitmap *ft_bitmap;
};

struct frame
{
  size_t bitmap_index;
  void *kpage;
  void *upage;
  struct thread *owner;
  struct hash_elem elem;
};

#endif /* vm/frame.h */