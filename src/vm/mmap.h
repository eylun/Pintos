#ifndef MMAP_H
#define MMAP_H

#include <hash.h>

<<<<<<< HEAD
#define MMAP_ERROR - 1
=======
>>>>>>> feat: added struct mmap_entry and mmap controller function signatures
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
struct mmap_entry *mmap_search_mapping(struct hash *mmap_table, mapid_t mapid);
void mmap_insert_mapping(struct mmap_entry *);
void mmap_destroy_complete(void);
void mmap_write_back_data(struct mmap_entry *entry, void *src, size_t offset, size_t length);

#endif
