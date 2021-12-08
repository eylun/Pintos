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

static void *load_swap(struct page_info *);
static void *load_file(struct page_info *, enum frame_types);
static void evict_and_swap(void);
static void perform_swap(struct frame *, struct page_info *);

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
  /* Initialize swap */
  st_init();
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
void *vm_alloc_get_page(enum palloc_flags flag, void *upage, enum frame_types type, struct file *file)
{
  ASSERT(check_page_alignment(upage));
  start_vm_access();
  struct frame *new_frame = ft_request_frame(flag, upage);
  if (!new_frame)
  {
    evict_and_swap();
    new_frame = ft_request_frame(flag, upage);
    /* If new_frame is null at this point
       no frames are available for eviction. Panic the kernel through
       the ASSERT call. */
    ASSERT(new_frame != NULL);
  }
  new_frame->type = type;
  if (type == FILE)
  {
    new_frame->file = file;
  }
  end_vm_access();
  return new_frame->kpage;
}

/* Function to check if a pointer access is a valid stack access */
bool is_stack_access(void *fault_addr, void *esp)
{
  /* Checks if fault address occurred within 32 bits from the esp.
     Also checks if the fault address location lies within the maximum stack space*/
  return (fault_addr >= esp - STACK_OFFSET && PHYS_BASE - pg_round_down(fault_addr) <= STACK_MAX_SPACE);
}

/* VM page fault handler. Called when a page fault occurs where a page
   is present.
   This function will check the memory reference of the faulted thread's
   supplemental page table.
   If the memory reference is invalid, returns NULL and lets the exception
   handler kill the process.
   If the memory reference is valid, this will attempt to commence swap and
   recover the memory from wherever it was stored previously. Then returns a
   non-NULL pointer so the exception handler will not kill the process.

   Faulted address passed in is already on the page directory
   THIS ONLY HAPPENS WHEN PASSED IN FROM SYSCALL VALIDATION */
void *vm_page_fault(void *fault_addr, void *esp)
{
  // Check if fault_addr is a key in this thread's SPT
  struct thread *cur = thread_current();
  void *aligned = pg_round_down(fault_addr);
  /* Faulted address does not have a value mapped to it in the sp_table
     This either means we are attempting to grow stack or throw an error. */
  struct page_info *page_info = sp_search_page_info(thread_current(), aligned);
  if (!page_info)
  { /* Check if this page fault is a stack growth fault */
    if (is_stack_access(fault_addr, esp))
    {
      return vm_grow_stack(aligned);
    }
    return NULL;
  }
  switch (page_info->page_status)
  {
  case PAGE_SWAP:
    return load_swap(page_info);
  case PAGE_MMAP:
    return load_file(page_info, MMAP);
  case PAGE_FILESYS:
    return load_file(page_info, FILE);
  default:
    PANIC("Invalid Page Status\n");
  }
}

static void *load_swap(struct page_info *page_info)
{
  void *kpage = vm_alloc_get_page(PAL_USER, page_info->upage, STACK, NULL);
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
  /* Retrieve the page out from the swap block */
  st_retrieve(page_info->index, kpage);
  /* Set the status of the page back to stack. */
  page_info->page_status = PAGE_STACK;
  return kpage;
}

static void *load_file(struct page_info *page_info, enum frame_types status)
{
  void *kpage;
  /* Sharing
     Loop through the currently present list of frames.
     If a frame with the upage we are looking for already exists, we do not need
     to allocate a new page for it, but just install it.
     Since the frame should already have a page that has data written into it,
     the function returns directly from there */
  struct frame *frame = frame_list_find(page_info);
  /* If kpage is NULL, get a new page of memory.
     If kpage is not NULL, that means it has already been allocated in the past.
     */
  if (frame)
  {
    if (!install_page(page_info->upage, frame->kpage, page_info->writable))
    {
      return NULL;
    }
    struct thread *t = thread_current();
    start_sp_access(t);
    page_info->frame = frame;
    end_sp_access(t);
    ft_add_pd_to_frame(frame, thread_current()->pagedir);
    return frame->kpage;
  }
  kpage = vm_alloc_get_page(PAL_USER | PAL_ZERO, page_info->upage, status, page_info->file);
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
  if (page_info->page_read_bytes != 0)
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

static void evict_and_swap(void)
{
  /* The evicted frame is no longer present in the frame table/list */
  struct frame *evicted = ft_evict();
  /* Acquire frame lock to prevent other processes from tapping into this frame */
  lock_acquire(&evicted->lock);
  /* Destroy this frame for all other pagedirs */
  ft_destroy_frame_sharing(evicted);
  struct page_info *page_info = sp_search_page_info(evicted->owner, evicted->upage);
  switch (evicted->type)
  {
  case STACK:
    perform_swap(evicted, page_info);
    break;
  case FILE:
    /* Check if these frames have been written to. If so, write them to the
       stack. If not, just remove them. */
    if (pagedir_is_dirty(evicted->owner->pagedir, evicted->upage))
    {
      perform_swap(evicted, page_info);
    }
    break;
  case MMAP:
    if (pagedir_is_dirty(evicted->owner->pagedir, evicted->upage))
    {
      mmap_write_back_data(
          mmap_search_mapping(&evicted->owner->mmap_table, page_info->mapid),
          pagedir_get_page(thread_current()->pagedir, evicted->upage),
          page_info->start,
          page_info->page_read_bytes);
    }
    break;
  default:
    PANIC("Invalid Frame Type\n");
  }

  start_sp_access(evicted->owner);
  page_info->frame = NULL;
  end_sp_access(evicted->owner);
  /* Clear the pagedir of the owner so it can no longer access this frame */
  pagedir_clear_page(evicted->owner->pagedir, evicted->upage);
  /* Free the page of the evicted frame and the frame itself */
  palloc_free_page(evicted->kpage);
  free(evicted);
}

static void perform_swap(struct frame *evicted, struct page_info *page_info)
{
  size_t index = st_insert(evicted->upage);
  if (index == -1)
  {
    lock_release(&evicted->lock);
    exit(-1);
  }
  start_sp_access(evicted->owner);
  page_info->page_status = PAGE_SWAP;
  page_info->index = index;
  end_sp_access(evicted->owner);
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
  struct thread *t = thread_current();
  struct page_info *page_info = sp_search_page_info(t, frame->upage);
  if (page_info)
  {
    start_sp_access(t);
    page_info->frame = NULL;
    end_sp_access(t);
  }
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
  sp_insert_page_info(page_info);
  void *kpage = vm_alloc_get_page(PAL_USER | PAL_ZERO, upage, STACK, NULL);
  if (kpage != NULL)
  {
    if (!install_page(upage, kpage, true))
    {
      vm_free_page(kpage);
      return NULL;
    }
  }
  return kpage;
}