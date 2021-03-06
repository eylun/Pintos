#ifndef PAGE_H
#define PAGE_H

#include <hash.h>
#include <threads/palloc.h>
#include "filesys/file.h"
#include "userprog/process.h"

enum page_status
{
  PAGE_STACK,
  PAGE_FILESYS,
  PAGE_SWAP,
  PAGE_MMAP
};

struct page_info
{
  void *upage;                  /* Address of the page in user virtual memory */
  size_t page_read_bytes;       /* Number of bytes to read (For filesys and mmap) */
  off_t start;                  /* Lazy loading offset (For filesys and mmap) */
  bool writable;                /* File writable flag (For filesys only) */
  struct file *file;            /* File attached to page (For filesys only) */
  struct hash_elem elem;        /* Used to store the page in the process's supplemental page table */
  struct frame *frame;          /* Pointer to frame corresponding to this page */
  enum page_status page_status; /* Stores page current status */
  mapid_t mapid;                /* Memory map id (For mmap only) */
  int index;                    /* Index for swapping if this page is a swap */
};

/* Initialization */
void sp_init(void);

/* Lock Access */
void start_sp_access(struct thread *);
void end_sp_access(struct thread *);

/* Controller Functions */
void sp_insert_page_info(struct page_info *);
struct page_info *sp_search_page_info(struct thread *t, void *);
void sp_destroy_complete(void);

#endif /* vm/page.h */