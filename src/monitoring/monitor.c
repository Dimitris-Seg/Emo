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
#include "../utils/general_utils.h"
#include "../utils/syscalls.h"
#include "../utils/logging.h"
#include "../utils/hashtableIS.h"
//
#include <stdlib.h>
#include <stddef.h>
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

static bool peek_http_header(pid_t pid, long address, size_t len){
    const string http_methods[] = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"};
    const int methods_len = sizeof(http_methods)/sizeof(http_methods[0]);
    char request_buffer[MAX_HTTP_METHOD_LEN + 1] = {0};

    int bytes_read = 0;
    int bytes_remaining = len; // Ensures no buffer overrun

    while(bytes_read < MAX_HTTP_METHOD_LEN){
        long data = ptrace(PTRACE_PEEKDATA, pid, address+bytes_read, NULL);
        const int nbytes = min(bytes_remaining, MAX_HTTP_METHOD_LEN - bytes_read);
        if(nbytes <= 0)break;
        memcpy(request_buffer, &data, min(sizeof(data), nbytes));

        bytes_read += sizeof(data);
        bytes_remaining -= sizeof(data);
    }

    request_buffer[bytes_read] = '\0';

    for(int method = 0; method < methods_len; ++method){
        if(!strncmp(request_buffer, http_methods[method], strlen(http_methods[method]))){
            DEBUG("Detected http request %s", http_methods[method]);
            return TRUE;
        }
    }

    return FALSE;
}

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

static sa_family_t peek_subprocess_internet_protocol(pid_t pid, long address){
    long family_offset = offsetof(struct sockaddr, sa_family);
    long word = ptrace(PTRACE_PEEKDATA, pid, address+family_offset, NULL);
    sa_family_t family;
    memcpy(&family, &word, sizeof(sa_family_t));
    DEBUG("Family: %d", family);
    return family;
}

static struct sockaddr_in peek_subprocess_hostname_ipv4(pid_t pid, long address){
    struct sockaddr_in sockaddr;
    // Split fetch in chunks
    for(size_t i=0;i<sizeof(sockaddr);i+=sizeof(long)){
        long word = ptrace(PTRACE_PEEKDATA, pid, address+i, NULL);
        *(((long*)&sockaddr)+i/sizeof(long)) = word;
    }
    return sockaddr;
}

static struct sockaddr_in6 peek_subprocess_hostname_ipv6(pid_t pid, long address){
    struct sockaddr_in6 sockaddr;
    // Split fetch in chunks
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
                open_filename = NULL;
                free(open_filename); // 'put' performs a deep copy of the string anyway
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
        // 
        if(orig_eax == SYS_connect){ // Under TCP, the address is established during connect(), unlike UDP
            if(!in_system_call){
                int fd = REG_ARG1(regs);
                long host_sockaddr = REG_ARG2(regs);
                char host_name[MAX_HOSTNAME_LEN] = {0}; // Buffer to store the hostname

                int res = 1;

                if(host_sockaddr){
                    sa_family_t fam = peek_subprocess_internet_protocol(pid, host_sockaddr);
                        if(fam==AF_INET){
                            DEBUG("connect initiated using ipv4");
                            struct sockaddr_in host_ipv4 = peek_subprocess_hostname_ipv4(pid, host_sockaddr);
                            res = getnameinfo((struct sockaddr*)&host_ipv4, sizeof(host_ipv4), host_name, sizeof(host_name), NULL, 0, NI_NAMEREQD);
                        }else if(fam==AF_INET6){
                            DEBUG("connect initiated using ipv6");
                            struct sockaddr_in6 host_ipv6 = peek_subprocess_hostname_ipv6(pid, host_sockaddr);
                            res = getnameinfo((struct sockaddr*)&host_ipv6, sizeof(host_ipv6), host_name, sizeof(host_name), NULL, 0, NI_NAMEREQD);
                        }else{
                            DEBUG("connect receive host with unsupported internet protocol");
                        }
                }

                if(res==0){
                    hashtable_IS_put(fd_hashtable, fd, host_name);
                    DEBUG("Created hashtable entry for fd %d, file: %s", fd, host_name);
                }
            }
        }
        //

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
                string host_name_ptr = host_name;

                // The 5th argument to sendto is the host name
                long fd = REG_ARG1(regs);

                long buffer = REG_ARG2(regs);
                long buffer_len = REG_ARG3(regs);
                long host_sockaddr = REG_ARG5(regs);

                bool is_http_request = buffer && peek_http_header(pid, buffer, buffer_len);

                if(is_http_request){
  
                    // In case it's empty we don't bother peeking any memory
                    if(host_sockaddr){
                        int res = 1;

                        sa_family_t fam = peek_subprocess_internet_protocol(pid, host_sockaddr);
                        if(fam==AF_INET){
                            DEBUG("sendto communicates with host using ipv4");
                            struct sockaddr_in host_ipv4 = peek_subprocess_hostname_ipv4(pid, host_sockaddr);
                            res = getnameinfo((struct sockaddr*)&host_ipv4, sizeof(host_ipv4), host_name, sizeof(host_name), NULL, 0, NI_NAMEREQD);
                        }else if(fam==AF_INET6){
                            DEBUG("sendto communicates with host using ipv6");
                            struct sockaddr_in6 host_ipv6 = peek_subprocess_hostname_ipv6(pid, host_sockaddr);
                            res = getnameinfo((struct sockaddr*)&host_ipv6, sizeof(host_ipv6), host_name, sizeof(host_name), NULL, 0, NI_NAMEREQD);
                        }else{
                            DEBUG("sendto uses host with unsupported internet protocol");
                        }
                        
                        if (res != 0) { // Name acquisition failed
                            ERROR("Failed to retrieve target host name: %s", gai_strerror(res));
                        }
                    }
                    bool supported_ip = (host_name[0]!=0);

                    if(!supported_ip){
                        host_name_ptr = hashtable_IS_find(fd_hashtable, fd); // Backup in case it's not found using reverse DNS lookup
                    }

                    if(!syscall_count[orig_eax])
                        INFO("Subprocess interacted with host '%s' for the first time %s", (host_name_ptr?host_name_ptr:"Not found"), (host_name_ptr?"":"[unsupported internet protocol]"));
                    else
                        INFO("Subprocess interacted with host '%s' (#%lu) %s", 
                            (host_name_ptr?host_name_ptr:"Not found"), syscall_count[orig_eax], 
                            (host_name_ptr?"":"[unsupported internet protocol]"));

                }else{
                    INFO("Subprocess interacted with a host (non-http, ignored)");
                }
                        
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