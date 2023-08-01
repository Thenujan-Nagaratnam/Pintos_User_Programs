#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/synch.h"

struct child_element* get_child(tid_t tid,struct list *mylist);
struct fd_element* get_fd(int fd);
static void syscall_handler (struct intr_frame *);

// function to verify the validity of a user pointer
void check_ptr_validation(const void *user_ptr)
{
    //check if the pointer is within the user virtual address space
    if (!is_user_vaddr(user_ptr))
    {
        exit(-1);
    }
    //get the physical page associated with the virtual address
    void *page = pagedir_get_page(thread_current()->pagedir, user_ptr);

    //if the page is not found, the pointer is invalid
    if (page == NULL)
    {
        exit(-1);
    }

}

void
syscall_init (void)
{
    intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
    lock_init(&file_lock);
}


void run_syscall_3 (struct intr_frame *intr_f, int SYSCALL, void *ptr)
{
    int fd = *((int*) ptr);
    ptr += 4;
    int buffer = *((int*) ptr);
    ptr += 4;
    int size = *((int*) ptr);
    ptr += 4;

    check_ptr_validation((const void*) buffer);
    void * temp = ((void*) buffer)+ size ;
    check_ptr_validation((const void*) temp);
    if (SYSCALL == SYS_WRITE)
    {
        intr_f->eax = write (fd,(void *) buffer,(unsigned) size);
    }
    else intr_f->eax = read (fd,(void *) buffer, (unsigned) size);
}


void run_syscall_2(struct intr_frame *intr_f, int SYSCALL, void *ptr)
{
    int fd = *((int*) ptr);
    ptr += 4;
    int buffer = *((int*) ptr);
    ptr += 4;

    if (SYSCALL == SYS_CREATE)
    {
        check_ptr_validation((const void*) fd);
        intr_f -> eax = create((const char *) fd, (unsigned) buffer);
    }
    else if(SYSCALL == SYS_SEEK)
    {
        seek(fd, (unsigned)buffer);
    }
}

void run_syscall_1(struct intr_frame *intr_f, int SYSCALL, void *ptr)
{
    int fd = *((int*) ptr);
    ptr += 4;

    if (SYSCALL == SYS_EXIT)
    {
        exit(fd);
    }
    else if (SYSCALL == SYS_TELL)
    {
        intr_f -> eax = tell(fd);
        close(fd);
    }
    else if (SYSCALL == SYS_EXEC)
    {
        check_ptr_validation((const void*) fd);
        intr_f -> eax = exec((const char *)fd);
    }
    else if(SYSCALL == SYS_OPEN)
    {
        check_ptr_validation((const void*) fd);
        intr_f -> eax = open((const char *) fd);
    }
    else if (SYSCALL == SYS_WAIT)
    {
        intr_f -> eax = wait(fd);
    }
    else if (SYSCALL == SYS_REMOVE)
    {
        check_ptr_validation((const void*) fd);
        intr_f -> eax = remove((const char *) fd);
    }
    else if (SYSCALL == SYS_FILESIZE)
    {
        intr_f -> eax = filesize(fd);
    }
}


static void
syscall_handler (struct intr_frame *intr_fr )
{
    int sys_code = 0;
    check_ptr_validation((const void*) intr_fr -> esp);
    void *ptr = intr_fr -> esp;
    sys_code = *( (int *) intr_fr -> esp);
    ptr+=4;
    check_ptr_validation((const void*) ptr);
    switch(sys_code)
    {
    case SYS_HALT:               
        halt();
        break;
    case SYS_CREATE:                
        run_syscall_2(intr_fr, SYS_CREATE,ptr);
        break;
    case SYS_REMOVE:                
        run_syscall_1(intr_fr, SYS_REMOVE,ptr);
        break;
    case SYS_EXEC:                  
        run_syscall_1(intr_fr, SYS_EXEC,ptr);
        break;
    case SYS_TELL:                   
        run_syscall_1(intr_fr, SYS_TELL,ptr);
        break;
    case SYS_WAIT:                  
        run_syscall_1(intr_fr, SYS_WAIT,ptr);
        break;
    case SYS_SEEK:                   
        run_syscall_2(intr_fr, SYS_SEEK,ptr);
        break;
    case SYS_EXIT:                  
        run_syscall_1(intr_fr, SYS_EXIT,ptr);
        break;
    case SYS_CLOSE:                 
        run_syscall_1(intr_fr, SYS_CLOSE,ptr);
        break;
    case SYS_READ:                  
        run_syscall_3(intr_fr, SYS_READ,ptr);
        break;
    case SYS_FILESIZE:               
        run_syscall_1(intr_fr, SYS_FILESIZE,ptr);
        break;
    case SYS_WRITE:                 
        run_syscall_3(intr_fr, SYS_WRITE,ptr);
        break;
    case SYS_OPEN:                 
        run_syscall_1(intr_fr, SYS_OPEN,ptr);
        break;
    default:
        exit(-1);
        break;
    }
}

void exit (int status)
{
    // Get the current thread
    struct thread *curr_thread = thread_current();
    // Print the thread name and exit status
    printf ("%s: exit(%d)\n", curr_thread -> name, status);

    // Get the child element for the current thread
    struct child_element *child = get_child(curr_thread->tid, &curr_thread -> parent -> child_list);

    // Set the exit status for the child element
    child -> exit_status = status;

    // Check if the exit status is -1
    if (status == -1)
    {
        // If yes, change the status to "WAS_KILLED"
        child -> cur_status = WAS_KILLED;
    }
    else
    {
        // If no, change the status to "HAD_EXITED"
        child -> cur_status = HAD_EXITED;
    }

    // Exit the current thread
    thread_exit();
}

void halt (void)
{
    shutdown_power_off();
}


/* 
 * exec - Executes the program specified by the given cmd_line 
 *
 * @cmd_line: command line string containing the program name
 *
 * Returns:
 *  - pid of the newly created process if execution is successful
 *  - -1 otherwise
 */
tid_t
exec (const char *cmd_line)
{
    // Get the parent thread
    struct thread* parent_thread = thread_current();
    tid_t process_id = -1;

    // Execute the program specified by cmd_line
    process_id = process_execute(cmd_line);

    // Get the child element of the parent thread
    struct child_element *child_process = get_child(process_id, &parent_thread->child_list);
    
    // Wait for the child process to finish loading
    sema_down(&child_process->real_child->sema_exec);

    // Check if the child process was loaded successfully
    if (!child_process->loaded_success)
    {
        return -1;   // Loading failed
    }

    return process_id;
}


// create a new file with a specified initial size
bool create (const char *file, unsigned initial_size)
{
    // Acquire the file lock to prevent multiple threads from accessing the file system simultaneously
    lock_acquire(&file_lock);
    // Call the file system's create function, passing the file name and initial size as arguments
    bool status = filesys_create(file, initial_size);
    // Release the file lock
    lock_release(&file_lock);
    // Return the result of the create function
    return status;
}


/*
  remove a file
*/
bool remove (const char *file)
{
    // Acquire the file lock to ensure mutual exclusion while removing a file
    lock_acquire(&file_lock);

    // Remove the file using the filesys_remove function
    bool removal_status = filesys_remove(file);

    // Release the file lock
    lock_release(&file_lock);

    // Return the result of the file removal
    return removal_status;
}

// open a file
int open (const char *file)
{
    int status = -1;  // initialize status to -1

    // Acquire lock to prevent multiple threads from accessing the file system at the same time
    lock_acquire(&file_lock);

    // Get the current thread
    struct thread *cur = thread_current ();

    // Open the file using the file system
    struct file * opened_file = filesys_open(file);

    // Release lock after accessing the file system
    lock_release(&file_lock);

    // If the file is successfully opened
    if(opened_file != NULL)
    {
        // Increase the file descriptor size of the current thread
        cur->fd_size = cur->fd_size + 1;
        status = cur->fd_size;  // Set status to the new file descriptor size

        /* Allocate memory for a new file descriptor element */
        struct fd_element *file_d = (struct fd_element*) malloc(sizeof(struct fd_element));
        file_d->fd = status;  // Set the file descriptor of the new file descriptor element to the current file descriptor size
        file_d->myfile = opened_file;  // Set the file pointer of the new file descriptor element to the opened file

        // Add the new file descriptor element to the current thread's file descriptor list
        list_push_back(&cur->fd_list, &file_d->element);
    }

    // Return the file descriptor size
    return status;
}

// Function to return the size of the file
int filesize (int fd)
{
    // Get the file associated with the file descriptor
    struct file *myfile = get_fd(fd)->myfile;
    // Acquire the lock before accessing the file
    lock_acquire(&file_lock);
    // Get the length of the file
    int file_size = file_length(myfile);
    // Release the lock after accessing the file
    lock_release(&file_lock);
    // Return the size of the file
    return file_size;
}


// read data from a file or keyboard
int read (int file_descriptor, void *buf, unsigned size)
{
    int num_bytes_read = -1;
    if(file_descriptor == 0)
    {
        // read input from keyboard
        num_bytes_read = input_getc();
    }
    else if(file_descriptor > 0)
    {
        //read from file
        //get the file descriptor element
        struct fd_element *fd_elem = get_fd(file_descriptor);
        if(fd_elem == NULL || buf == NULL)
        {
            return -1;
        }
        //get the file
        struct file *f = fd_elem->myfile;
        lock_acquire(&file_lock);
        num_bytes_read = file_read(f, buf, size);
        lock_release(&file_lock);
        if(num_bytes_read < (int)size && num_bytes_read != 0)
        {
            //some error happened
            num_bytes_read = -1;
        }
    }
    return num_bytes_read;
}


// wait for the child process to finish running
int wait (tid_t pid)
{
    return process_wait(pid);      
}


// write data to a file
int write (int file_descriptor, const void *write_buffer, unsigned write_size)
{
    uint8_t * buffer = (uint8_t *) write_buffer;
    int result = -1;
    if (file_descriptor == 1)
    {
        // write to the console
        putbuf( (char *)buffer, write_size);
        return (int)write_size;
    }
    else
    {
        //write to file
        //get the fd_element
        struct fd_element *file_descriptor_element = get_fd(file_descriptor);
        if(file_descriptor_element == NULL || write_buffer == NULL )
        {
            return -1;
        }
        //get the file
        struct file *target_file = file_descriptor_element->myfile;
        lock_acquire(&file_lock);
        result = file_write(target_file, write_buffer, write_size);
        lock_release(&file_lock);
    }
    return result;
}

// Move file position to a specific offset
void seek (int fd, unsigned position)
{
    // Get the file descriptor element associated with the given file descriptor.
    struct fd_element *fd_element = get_fd(fd);

    // If the file descriptor element is not found, return.
    if(fd_element == NULL)
    {
        return;
    }   

    // Get the file associated with the file descriptor element.
    struct file *file = fd_element->myfile;

    // Acquire the lock for the file system operations.
    lock_acquire(&file_lock);

    // Seek to the specified position in the file.
    file_seek(file, position);

    // Release the lock for the file system operations.
    lock_release(&file_lock);
}


// getting the current position in a file
unsigned tell (int fd)
{
    // get the file descriptor element
    struct fd_element *fd_elem = get_fd(fd);
    if(fd_elem == NULL)
    {
        // return -1 if fd_element is not found
        return -1;
    }

    // get the file from the file descriptor element
    struct file *myfile = fd_elem->myfile;
    // lock the file
    lock_acquire(&file_lock);
    // get the current position in the file
    unsigned position = file_tell(myfile);
    // release the lock
    lock_release(&file_lock);
    return position;
}


// Close an opened file
void close (int file_descriptor)
{
    // Get the file descriptor element
    struct fd_element *desc_elem = get_fd(file_descriptor);
    if (desc_elem == NULL)
    {
        // Return if the file descriptor element is invalid
        return;
    }

    // Get the file
    struct file *myfile = desc_elem->myfile;

    // Acquire the file lock to ensure thread safety
    lock_acquire(&file_lock);
    // Close the file
    file_close(myfile);
    // Release the file lock
    lock_release(&file_lock);

}

/* Close all files in the list of file descriptors
Parameters:

fd_list: Pointer to the list of file descriptors
*/
void close_all(struct list *fd_list)
{
    // get the first element in the list
    struct list_elem *curr_elem = list_begin(fd_list);

    while(!list_empty(fd_list))
    {
        // remove the first element
        curr_elem = list_pop_front(fd_list);

        // get the file descriptor element from the list
        struct fd_element *fd_elem = list_entry (curr_elem, struct fd_element, element);

        // close the associated file
        file_close(fd_elem->myfile);

        // remove the element from the list
        list_remove(curr_elem);

        // free the memory of the file descriptor element
        free(fd_elem);
    }

}

/* Get the file descriptor element based on the given file descriptor (fd)
Input: int fd - the file descriptor of the file
Output: Returns a pointer to the file descriptor element associated with the given file descriptor,
if there exists one.
Returns NULL otherwise.
*/
struct fd_element*
get_fd(int fd)
{
    // loop through the file descriptor list of the current thread
    struct list_elem *elem;
    for (elem = list_begin (&thread_current()->fd_list); elem != list_end (&thread_current()->fd_list); elem = list_next (elem))
    {
        // get the file descriptor element from the list
        struct fd_element *fd_elem = list_entry (elem, struct fd_element, element);
        // check if the file descriptor of the element matches the given fd
        if(fd_elem->fd == fd)
        {
            // return the file descriptor element
            return fd_elem;
        }
    }
    // if no match found, return NULL
    return NULL;
}



// Function to retrieve a child thread based on its tid
struct child_element* get_child(tid_t tid, struct list *children_list)
{
    // Iterate through the list of children
    struct list_elem* e;
    for (e = list_begin(children_list); e != list_end(children_list); e = list_next(e))
    {
        struct child_element *curr_child = list_entry(e, struct child_element, child_elem);
        // Check if the current child's tid matches the specified tid
        if (curr_child->child_pid == tid)
        {
            return curr_child;
        }
    }
}
