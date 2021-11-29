#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "string.h"
#include "vm/vm.h"
#include "vm/frame.h"
#include "vm/swap.h"

/* Lock for accessing vm brain */
static struct lock vm_lock;

void start_vm_access(void)
{
  lock_acquire(&vm_lock);
}

void end_vm_access(void)
{
  lock_release(&vm_lock);
}

void vm_init(void)
{
  lock_init(&vm_lock);
  ft_init();
}

/* Access point for the rest of the OS to get a page.
   vm_alloc_page calls for the frame table to perform the following:
   1. Request for a new frame.
   If a pointer to a frame is returned.
    2a. Asks the frame table to insert the frame.
    3a. Returns the pointer to the page.
   If NULL is returned.
    2b. Performs a swap
    3b. Request for a frame again (ONLY IF SWAPPED)
    4b. Asks the frame table to insert the frame.
    5b. Returns the pointer to the page. */
void *vm_alloc_get_page(enum palloc_flags flag, void *upage)
{
  ASSERT(check_page_alignment(upage));
  start_vm_access();
  struct frame *new_frame = ft_request_frame(flag, upage);
  if (!new_frame)
  {
    /* FOR NOW, KERNEL PANIC. */
    PANIC("This is a temporary PANIC for 'no more space in frame table'\n");
    /* TODO: Swap function call */
    new_frame = ft_request_frame(flag, upage);
    /* If new_frame is null at this point
       no frames are available for eviction. Panic the kernel through
       the ASSERT call. */
    ASSERT(new_frame != NULL);
  }
  end_vm_access();
  return new_frame->kpage;
}

/* VM page fault handler. Called when a page fault occurs where a page
   is present.
   This function will check the memory reference of the faulted thread's
   supplemental page table.
   If the memory reference is invalid, returns NULL and lets the exception
   handler kill the process.
   If the memory reference is valid, this will attempt to commence swap and
   recover the memory from wherever it was stored previously. Then returns a
   non-NULL pointer so the exception handler will not kill the process. */
void *vm_page_fault(void *fault_addr, void *esp)
{
  return NULL;
}

/* VM free page. The VM will search for the pointer provided in the frame table.
   It will assert that the Search has to return something valid.
   The VM will then remove this page from the frame table and the supplemental
   page table of the thread that contains this page. */
void vm_free_page(void *kpage)
{
  start_vm_access();
  struct frame *frame = ft_search_frame(kpage);
  ASSERT(frame); /* If the search fails, panic */
  ft_destroy_frame(frame);
  end_vm_access();
}
