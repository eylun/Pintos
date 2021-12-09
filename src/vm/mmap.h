#ifndef MMAP_H
#define MMAP_H

#include <hash.h>

#define MMAP_ERROR -1
typedef int mapid_t;

struct mmap_entry
{
    mapid_t mapid;              /* Mapping ID to identify the mapping within the process */
    void *upage;                /* Address of the file in user virtual memory */
    struct file *file;          /* Pointer to the file that is mapped into the process's virtual memory */
    struct hash_elem hash_elem; /* Hash element for the mmap hash table */
};

/* Inititalization */
void mmap_init(void);

/* Controller Functions */
void mmap_unmap(mapid_t);
mapid_t mmap_map(int, void *);
struct mmap_entry *mmap_search_mapping(struct hash *mmap_table, mapid_t mapid);
void mmap_write_back_data(struct mmap_entry *entry, void *src, size_t offset, size_t length);

#endif
