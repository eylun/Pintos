#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "lib/kernel/hash.h"

#define EXIT_CODE -1
#define ONE_ARG 1
#define TWO_ARG 2
#define THREE_ARG 3
/* FILE_MAX is set to 15 because it is 14 characters + terminating character */
#define FILE_MAX 15
/* Structure of a file descriptor. Used for mapping fd to files. */

struct file_descriptor
{
    struct hash_elem hash_elem; /* Hash elem for hash table of file descriptors */
    struct file *file;          /* File corresponding to the fd. */
    int fd;                     /* Non-negative integer handle for files. */
};

void syscall_init(void);

void start_filesys_access(void);
void end_filesys_access(void);
void check_and_end_filesys_access(void);
struct hash_elem *get_elem(struct file_descriptor *, int);

void exit(int);

#endif /* userprog/syscall.h */
