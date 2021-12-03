#ifndef VM_VM_H
#define VM_VM_H

#include <hash.h>
#include <threads/palloc.h>
#include "vm/frame.h"

#define ZERO 0
#define NO_ZERO 1

/* Initialize the VM controller */
void vm_init(void);

/* Function to call when a new page needs to be retrieved */
void *vm_alloc_get_page(enum palloc_flags, void *, enum frame_types);

/* Function to call upon a virtual memory page fault */
void *vm_page_fault(void *, void *);

/* Function to call for freeing a VM page */
void vm_free_page(void *);

#endif /* vm/vm.h */