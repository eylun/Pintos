#ifndef PAGE_H
#define PAGE_H

#include <hash.h>
#include <threads/palloc.h>

struct page_info
{
  void *upage;
  struct hash_elem elem;
  struct frame *frame;
  int index;
};

/* Initialization */
void sp_init();

/* Lock Access */
void start_sp_access(void);
void end_sp_access(void);

/* Controller Functions */

#endif /* vm/page.h */