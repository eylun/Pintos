#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"
#include "filesys/file.h"
#include "string.h"
#include "vm/frame.h"
#include "vm/vm.h"
#include "vm/swap.h"
#include "vm/page.h"

/* Lock for accessing vm brain */
static struct lock vm_lock;

static void *load_file(struct page_info *, bool);

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
  /* Initialize vm lock */
  lock_init(&vm_lock);
  /* Initialize frame table */
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
void *vm_alloc_get_page(enum palloc_flags flag, void *upage, enum frame_types type)
{
  ASSERT(check_page_alignment(upage));
  // printf("I have arrived in vm_alloc\n");
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
  new_frame->type = type;
  end_vm_access();
  return new_frame->kpage;
}

/* Function to check if a pointer access is a valid stack access */
bool is_stack_access(void *fault_addr, void *esp)
{
  unsigned long offset = esp - fault_addr;
  /* Checks if fault address occurred within 32 bits from the esp.
     Also checks if the fault address location lies within the maximum stack space*/
  return (fault_addr >= esp - 32 && PHYS_BASE - pg_round_down(fault_addr) <= STACK_MAX_SPACE);
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
  // printf("there is a page fault at : %x\n", fault_addr);
  // if (fault_addr == 0)
  // {
  //   PANIC("WTF");
  // }
  // Check if fault_addr is a key in this thread's SPT
  struct thread *cur = thread_current();
  void *aligned = pg_round_down(fault_addr);
  /* Faulted address passed in is already on the page directory
     THIS ONLY HAPPENS WHEN PASSED IN FROM SYSCALL VALIDATION */

  /* Check if this page fault is a stack growth fault */
  if (is_stack_access(fault_addr, esp))
  {
    return vm_grow_stack(aligned);
  }
  /* Faulted address does not have a value mapped to it in the sp_table
     Return NULL to let exception.c kill this frame */
  struct page_info *page_info = sp_search_page_info(aligned);
  if (!page_info)
  {
    return NULL;
  }
  switch (page_info->page_status)
  {
  case PAGE_FILESYS:
    return load_file(page_info, NO_ZERO);
  case PAGE_ZERO:
    return load_file(page_info, ZERO);
  default:
    PANIC("This should not happen\n");
  }
}

static void *load_file(struct page_info *page_info, bool non_zero)
{
  void *kpage;
  // struct frame *frame = frame_list_find_upage(page_info->upage);
  // // printf("the frame is: %x with upage :%x\n", frame, page_info->upage);
  // /* If kpage is NULL, get a new page of memory.
  //    If kpage is not NULL, that means it has already been allocated in the past.
  //    */
  // if (frame)
  // {
  //   // printf("frame exists: %x\n", frame);
  //   if (!install_page(page_info->upage, frame->kpage, page_info->writable))
  //   {
  //     return NULL;
  //   }
  //   page_info->frame = frame;
  //   return frame->kpage;
  // }
  kpage = vm_alloc_get_page(PAL_USER | PAL_ZERO, page_info->upage, FILE);
  if (!kpage)
  {
    return NULL;
  }
  /* Add the page to the process's address space. */
  if (!install_page(page_info->upage, kpage, page_info->writable))
  {
    vm_free_page(kpage);
    return NULL;
  }

  /* Load data into the page. */
  if (non_zero)
  {
    start_filesys_access();
    file_seek(page_info->file, page_info->start);
    if (file_read(page_info->file, kpage, page_info->page_read_bytes) != (int)page_info->page_read_bytes)
    {
      end_filesys_access();
      vm_free_page(kpage);
      return NULL;
    }
    end_filesys_access();
  }
  /* The value page_zero_bytes is equal to PGSIZE - page_info->page_read_bytes */
  memset(kpage + page_info->page_read_bytes, 0, PGSIZE - page_info->page_read_bytes);
  return kpage;
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

/* Grows the stack by mapping a zeroed page at upage */
void *vm_grow_stack(void *upage)
{
  /* Add page_info of this new stack into the thread's sp table */
  struct thread *t = thread_current();
  /*Malloc new page_info for stack page
    1. upage
    2. writable */
  struct page_info *page_info = calloc(1, sizeof(struct page_info));
  page_info->page_status = PAGE_STACK;
  page_info->upage = upage;
  /* Stack pages have to be writable */
  page_info->writable = true;
  // printf("addr: %x read: %d, zero: %d\n", upage, page_read_bytes, page_zero_bytes);
  sp_insert_page_info(page_info);
  void *kpage = vm_alloc_get_page(PAL_USER | PAL_ZERO, upage, STACK);
  if (kpage != NULL)
  {
    if (!install_page(upage, kpage, true))
    {
      vm_free_page(kpage);
    }
  }
  return kpage;
}