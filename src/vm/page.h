#ifndef PAGE_H
#define PAGE_H

#include <hash.h>
#include <threads/palloc.h>

enum page_status
{
  PAGE_SWAP,
  PAGE_ZERO,
  PAGE_FILESYS
};

struct page_info
{
  void *upage;                  /* Address of the page in user virtual memory */
  struct hash_elem elem;        /* Used to store the page in the process's supplemental page table */
  struct frame *frame;          /* Pointer to frame corresponding to this page */
  enum page_status page_status; /* Stores page current status */
  int index;
};

/* Initialization */
void sp_init();

/* Lock Access */
void start_sp_access(void);
void end_sp_access(void);

/* Controller Functions */

#endif /* vm/page.h */