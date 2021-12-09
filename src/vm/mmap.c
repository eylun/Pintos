#include "vm/mmap.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "lib/kernel/hash.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"

static unsigned mmap_table_hash_func(const struct hash_elem *, void *UNUSED);
bool mmap_table_less_func(const struct hash_elem *,
                          const struct hash_elem *, void *UNUSED);

void mmap_init(void)
{
    struct thread *cur = thread_current();
    hash_init(&cur->mmap_table, mmap_table_hash_func, mmap_table_less_func, NULL);
    cur->next_mmapid = 0;
}

/* Memory mapping. This is called during the system call 'mmap'. */
mapid_t mmap_map(int fd, void *addr)
{

    /* Pintos assumes virtual page 0 is not mapped and fd = 0 and fd = 1 is not mappable */
    if (addr == 0 || fd == 0 || fd == 1)
    {
        return MMAP_ERROR;
    }

    /* Checks that addr is a user virtual address */
    if (!is_user_vaddr(addr))
    {
        exit(EXIT_CODE);
    }

    /* Checks that addr is page aligned */
    if (pg_ofs(addr) != 0)
    {
        return MMAP_ERROR;
    }

    /* Access file corresponding to the given fd */
    /* Returns -1 if the given file_descriptor is not found in the process's fd_table */
    struct hash_elem *elem = get_elem(fd);

    if (!elem)
    {
        return MMAP_ERROR;
    }
    struct file_descriptor *open_descriptor = hash_entry(elem, struct file_descriptor, hash_elem);
    if (!open_descriptor)
    {
        return MMAP_ERROR;
    }

    /* Memory map stays even when original file is closed or removed.
       Need to use own file handle to the file. Done by reopening the file. */
    start_filesys_access();
    struct file *file = file_reopen(open_descriptor->file);
    off_t length = file_length(file);
    end_filesys_access();

    /* Returns -1 if file has length of zero bytes */
    if (length == 0)
    {
        return MMAP_ERROR;
    }

    int pages_to_map = length / PGSIZE;
    if (length % PGSIZE)
    {
        pages_to_map++;
    }

    /* Checks that the range of pages to be mapped does not overlap an existing set of mapped pages */
    for (int i = 0; i < pages_to_map; i++)
    {
        if (sp_search_page_info(thread_current(), addr + i * PGSIZE))
        {
            return MMAP_ERROR;
        }
    }
    struct thread *cur = thread_current();

    struct mmap_entry *entry = malloc(sizeof(struct mmap_entry));
    if (!entry)
    {
        exit(EXIT_CODE);
    }

    entry->mapid = cur->next_mmapid++;
    entry->file = file;
    entry->upage = addr;

    size_t bytes_into_file = 0;
    void *upage = addr;
    size_t accumulator = 0;

    for (int i = 0; i < pages_to_map; i++)
    {
        accumulator = length - i * PGSIZE > PGSIZE ? PGSIZE : length - i * PGSIZE;
        struct page_info *page_info = malloc(sizeof(struct page_info));
        if (!page_info)
        {
            exit(EXIT_CODE);
        }
        page_info->file = file;
        page_info->writable = true;
        page_info->page_status = PAGE_MMAP;
        page_info->upage = upage;
        page_info->page_read_bytes = accumulator;
        page_info->start = bytes_into_file;
        page_info->mapid = entry->mapid;
        sp_insert_page_info(page_info);
        bytes_into_file += PGSIZE;
        upage += PGSIZE;
    }

    hash_insert(&cur->mmap_table, &entry->hash_elem);

    return entry->mapid;
}

/* Memory unmapping. This is called during the system call 'munmap'. */
void mmap_unmap(mapid_t mapid)
{
    struct hash *mmap_table = &thread_current()->mmap_table;
    struct mmap_entry *entry = mmap_search_mapping(mmap_table, mapid);

    if (!entry)
    {
        return;
    }

    start_filesys_access();
    size_t file_size = file_length(entry->file);
    end_filesys_access();

    int num_pages = file_size / PGSIZE;
    if (file_size % PGSIZE != 0)
    {
        num_pages++;
    }

    void *upage = entry->upage;

    struct hash *sp_table = &thread_current()->sp_table;

    for (int i = 0; i < num_pages; i++)
    {
        struct page_info *page_info = sp_search_page_info(thread_current(), upage);

        if (!page_info)
        {
            return;
        }
        if (page_info->page_status == PAGE_MMAP)
        {
            void *kpage = pagedir_get_page(thread_current()->pagedir, upage);

            if (pagedir_is_dirty(thread_current()->pagedir, page_info->upage))
            {
                mmap_write_back_data(entry, kpage, page_info->start, page_info->page_read_bytes);
            }
        }

        /* Free user page in sp_table */
        struct page_info temp_page_info;
        temp_page_info.upage = upage;
        hash_delete(sp_table, &temp_page_info.elem);

        upage += PGSIZE;
    }

    /* Finds and deletes the mmap_entry*/
    struct mmap_entry temp_entry;
    temp_entry.mapid = entry->mapid;
    hash_delete(&thread_current()->mmap_table, &temp_entry.hash_elem);

    start_filesys_access();
    file_close(entry->file);
    end_filesys_access();

    free(entry);
}

struct mmap_entry *mmap_search_mapping(struct hash *mmap_table, mapid_t mapid)
{
    struct mmap_entry entry;
    entry.mapid = mapid;

    struct hash_elem *e = hash_find(mmap_table, &entry.hash_elem);

    if (!e)
    {
        return NULL;
    }

    return hash_entry(e, struct mmap_entry, hash_elem);
};

static unsigned mmap_table_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
    const struct mmap_entry *mapping = hash_entry(e, struct mmap_entry, hash_elem);
    return hash_int((unsigned)mapping->mapid);
}

bool mmap_table_less_func(const struct hash_elem *e1,
                          const struct hash_elem *e2, void *aux UNUSED)
{
    return hash_entry(e1, struct mmap_entry, hash_elem)->mapid <
           hash_entry(e2, struct mmap_entry, hash_elem)->mapid;
}

void mmap_write_back_data(struct mmap_entry *entry, void *src, size_t offset, size_t length)
{
    start_filesys_access();
    file_seek(entry->file, offset);
    file_write(entry->file, src, length);
    end_filesys_access();
}
