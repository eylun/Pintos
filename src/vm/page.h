#ifndef PAGE_H
#define PAGE_H

#include <hash.h>
#include <threads/palloc.h>
#include "filesys/file.h"
#include "userprog/process.h"

enum page_status
{
  PAGE_SWAP,
  PAGE_ZERO,
  PAGE_FILESYS
};

struct page_info
{
  void *upage; /* Address of the page in user virtual memory */
  void *kpage; /* Address of the page in kernel memory */
  size_t page_read_bytes;
  size_t page_zero_bytes;
  off_t start;
  bool writable;
  struct file *file;
  struct hash_elem elem;        /* Used to store the page in the process's supplemental page table */
  struct frame *frame;          /* Pointer to frame corresponding to this page */
  enum page_status page_status; /* Stores page current status */
  int index;
};

/* Initialization */
void sp_init(void);

/* Lock Access */
void start_sp_access(void);
void end_sp_access(void);

/* Controller Functions */

#endif /* vm/page.h */