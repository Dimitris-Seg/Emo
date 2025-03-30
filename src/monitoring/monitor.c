/**
 * Implementation of an execution monitor for PHAs
 *
 *@author Dimitris Segkesser, A.M.: 5006
 *@date 28/03/2025
 *
 *@brief This is an implementation of an execution monitor
 * for PHAs, tracing the execution of a child process and
 * logging crucial accesses to system calls/files as well as
 * monitoring unencrypted network connections the latter may establish.
 *
 *@file monitor.c
 *
 * Computer Science Department, University Of Crete
 */

#define _GNU_SOURCE
 
#include "monitor.h"
#include "../utils/general_types.h"
#include "../utils/syscalls.h"
#include "../utils/logging.h"
#include "../utils/hashtableIS.h"
//
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/syscall.h> // For cross-compatibility with syscalls
//

void monitor_execution(pid_t pid){
    if(pid==0){
        ERROR("Cannot monitor execution of self");
        exit(EXIT_FAILURE);
    }

    DEBUG("Started monitoring process '%d'", pid);

    int execution_status;
    hashtable_IS_t fd_hashtable = new_hashtable_IS();

    // Default file streams (open from parent)
    hashtable_IS_put(fd_hashtable, 0, "stdin");
    hashtable_IS_put(fd_hashtable, 1, "stdout");
    hashtable_IS_put(fd_hashtable, 2, "stderr");

    // Registers
    long orig_eax;
    bool in_system_call = FALSE;
    long argument; // We only monitor one argument for the deep-inspection system calls
    string open_filename;
    
    while(TRUE){
        wait(&execution_status);

        if(WIFEXITED(execution_status)){
            // Tracee exited
            INFO("Subprocess (%d) exited", pid);
            break; 
        }

        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &regs); // Retrieve user register struct

        orig_eax = REG_SYSCALL(regs);

        if(!SYSCALL_VALID(orig_eax)){
            ERROR("Received invalid system call '%ld'", orig_eax);
            exit(EXIT_FAILURE);
        }

        // Monitor open/close syscall returns to keep track of file names
        if(orig_eax == SYS_open || orig_eax == SYS_openat){
            if(!in_system_call){
                char filename_buffer[MAX_FILE_PATH_LEN];
                long filename_addr = (orig_eax == SYS_open?REG_ARG1(regs):REG_ARG2(regs));
                // Split string fetch in chunks for better performance
                for(size_t i=0;i<sizeof(filename_buffer);i+=sizeof(long)){
                    long data = ptrace(PTRACE_PEEKDATA, pid, filename_addr+i, NULL); // Read user data
                    memcpy(filename_buffer + i, &data, sizeof(long));
                    if(memchr(&data, '\0', sizeof(long)))break; // If \0 is found in this chunk break
                }
                filename_buffer[255] = '\0'; // Guard
                open_filename = strdup(filename_buffer); // Store in a safe string
            }else{
                int fd = REG_RETURN(regs);
                hashtable_IS_put(fd_hashtable, fd, open_filename);
                DEBUG("Created hashtable entry for fd %d, file: %s", fd, open_filename);
                open_filename = NULL;\
                free(open_filename); // 'put' performs a deep copy of the string anyways
            }
        }
        //
        if(orig_eax == SYS_close){
            if(!in_system_call){
                int fd = REG_ARG1(regs);
                hashtable_IS_remove(fd_hashtable, fd);
                DEBUG("Removed hashtable entry for fd %d", fd);
            }
        }

        // First the deep-inspection system calls
        if(orig_eax == SYS_read || orig_eax == SYS_write){
            if(!in_system_call){
                // The first argument to read/write is the file descriptor
                argument = REG_ARG1(regs);
                string filename = hashtable_IS_find(fd_hashtable, argument);

                if(filename==NULL){
                    ERROR("Detected read/write from/to an unopened file stream (fd not found)");
                }

                if(!syscall_count[orig_eax])
                    INFO("Subprocess made file access (%s) '%s' for the first time", syscall_names[orig_eax], filename?filename:"Not found");
                else
                    INFO("Subprocess made file access (%s) '%s' (#%lu)", syscall_names[orig_eax], filename?filename:"Not found", syscall_count[orig_eax]);

                syscall_count[orig_eax]++;
            }
        }else if(orig_eax == SYS_sendto) {
            if(!in_system_call){
                // The 4th argument to sendto is the host name
                argument = REG_ARG4(regs);

                if(!syscall_count[orig_eax])
                    INFO("Subprocess interacted with host '%s' for the first time", ((string)argument));
                else
                    INFO("Subprocess interacted with host '%s' (#%lu)", ((string)argument), syscall_count[orig_eax]);

                syscall_count[orig_eax]++;
            }
        }else{
            // Rest of system calls
            if(!in_system_call){
                if(!syscall_count[orig_eax])
                    INFO("Subprocess called '%s' for the first time", syscall_names[orig_eax]);
                else
                    INFO("Subprocess called '%s' (#%lu)", syscall_names[orig_eax], syscall_count[orig_eax]);

                syscall_count[orig_eax]++;
            }
        }

        if(orig_eax!=SYS_execve || REG_RETURN(regs)<0 )in_system_call = !in_system_call; // Ignore execve if it doesn't fail (shouldn't return if it succeeds)

        ptrace(PTRACE_SYSCALL, pid, NULL, NULL); // Continue execution of subprocess
    }

    delete_hashtable_IS(fd_hashtable);
}