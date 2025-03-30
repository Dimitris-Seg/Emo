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
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <sys/syscall.h> // For cross-compatibility with syscalls
//

static string peek_subprocess_string(pid_t pid, long address){
    char filename_buffer[MAX_FILE_PATH_LEN];
    
    // Split string fetch in chunks for better performance
    for(size_t i=0;i<sizeof(filename_buffer);i+=sizeof(long)){
        long data = ptrace(PTRACE_PEEKDATA, pid, address+i, NULL); // Read user data
        memcpy(filename_buffer + i, &data, sizeof(long));
        if(memchr(&data, '\0', sizeof(long)))break; // If \0 is found in this chunk break
    }
    filename_buffer[255] = '\0'; // Guard
    return strdup(filename_buffer); // Store in a safe string
}

static struct sockaddr peek_subprocess_hostname(pid_t pid, long address){
    struct sockaddr sockaddr;
    // Split fetch in chunks for better performance
    for(size_t i=0;i<sizeof(sockaddr);i+=sizeof(long)){
        long word = ptrace(PTRACE_PEEKDATA, pid, address+i, NULL);
        *(((long*)&sockaddr)+i/sizeof(long)) = word;
    }
    return sockaddr;
}

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

        DEBUG("%s system call '%s'", in_system_call?"Returning from":"Entering", syscall_names[orig_eax]);

        // Monitor open/close syscall returns to keep track of file names
        if(orig_eax == SYS_open || orig_eax == SYS_openat){
            if(!in_system_call){
                long filename_addr = (orig_eax == SYS_open?REG_ARG1(regs):REG_ARG2(regs));
                open_filename = peek_subprocess_string(pid, filename_addr);
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
                int fd = REG_ARG1(regs);
                string filename = hashtable_IS_find(fd_hashtable, fd);

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
                char host_name[MAX_HOSTNAME_LEN] = {0}; // Buffer to store the hostname

                // The 5th argument to sendto is the host name
                long host_name_addr = REG_ARG5(regs);
                struct sockaddr host = peek_subprocess_hostname(pid, host_name_addr);
                
                int res = getnameinfo((struct sockaddr*)&host, sizeof(host), host_name, sizeof(host_name), NULL, 0, NI_NAMEREQD);

                if (res != 0) { // Name acquisition failed
                    ERROR("Failed to retrieve target host name: %s", gai_strerror(res));
                
                    if (host.sa_family == AF_INET) {
                        if (inet_ntop(AF_INET, &((struct sockaddr_in*)(&host))->sin_addr, host_name, INET_ADDRSTRLEN) == NULL) {
                            ERROR("Failed to retrieve IP address for IPv4: %s", strerror(errno));
                        }
                    } else if (host.sa_family == AF_INET6) {
                        if (inet_ntop(AF_INET6, &((struct sockaddr_in6*)(&host))->sin6_addr, host_name, INET6_ADDRSTRLEN) == NULL) {
                            ERROR("Failed to retrieve IP address for IPv6: %s", strerror(errno));
                        }
                    }
                }
                

                if(!syscall_count[orig_eax])
                    INFO("Subprocess interacted with host '%s' for the first time", (host_name[0]!='\0'?host_name:"Not found"));
                else
                    INFO("Subprocess interacted with host '%s' (#%lu)", (host_name[0]!='\0'?host_name:"Not found"), syscall_count[orig_eax]);

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