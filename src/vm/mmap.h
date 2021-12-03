#ifndef MMAP_H
#define MMAP_H

#include <hash.h>

typedef int mapid_t;

struct mmap_entry
{
    mapid_t mapid;              /* Mapping ID to identify the mapping within the process */
    void *uaddr;                /* Address of the file in user virtual memory */
    struct file *file;          /* Pointer to the file that is mapped into the process's virtual memory */
    struct hash_elem hash_elem; /* Hash element for the mmap hash table */
};

/* Inititalization */
void mmap_init(void);

/* Controller Functions */
struct mmap_entry *mmap_search_mapping(void *);
void mmap_insert_mapping(struct mmap_entry *);
void mmap_destroy_complete(void);

#endif