#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "threads/thread.h"
#include <list.h>
#include "threads/synch.h"

/* lock to control access to files with multiple threads */
struct lock file_lock;

/* structure to store information about file descriptors */
struct fd_element {
    int fd;                        /* unique file descriptor ID */
    struct file *myfile;           /* the actual file */
    struct list_elem element;      /* element to be added to fd_list */
};

/* initialize system calls */
void syscall_init(void);

/* halt system */
void halt(void);

/* exit process with specified status */
void exit(int status);

/* execute command line with specified executable name */
tid_t exec(const char *cmd_line);

/* wait for specified process to finish */
int wait(tid_t pid);

/* create new file with specified name and initial size */
bool create(const char *file, unsigned initial_size);

/* remove specified file */
bool remove(const char *file);

/* open specified file and return file descriptor */
int open(const char *file);

/* return size of specified file descriptor */
int filesize(int fd);

/* read data from specified file descriptor into buffer */
int read(int fd, void *buffer, unsigned size);

/* write data from buffer into specified file descriptor */
int write(int fd, const void *buffer, unsigned size);

/* change position of specified file descriptor */
void seek(int fd, unsigned position);

/* return current position of specified file descriptor */
unsigned tell(int fd);

/* close specified file descriptor */
void close(int fd);

/* close all file descriptors in specified list */
void close_all(struct list *fd_list);

/* return child element with specified tid from specified list */
struct child_element* get_child(tid_t tid, struct list *mylist);

#endif /* userprog/syscall.h */

