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

static string peek_http_header(pid_t pid, long address, size_t len){
    const string http_methods[] = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "};
    const int methods_len = sizeof(http_methods)/sizeof(http_methods[0]);
    char request_buffer[MAX_HTTP_METHOD_LEN + 1] = {0};

    int bytes_read = 0;
    int max_bytes = min(MAX_HTTP_METHOD_LEN, len);

    while(bytes_read < max_bytes){
        const long data = ptrace(PTRACE_PEEKDATA, pid, address+bytes_read, NULL);
        const int nbytes = min(sizeof(data), max_bytes - bytes_read);
        if(nbytes <= 0)break;
        memcpy(request_buffer+bytes_read, &data, nbytes);

        bytes_read += nbytes;
    }

    request_buffer[bytes_read] = '\0';

    for(int method = 0; method < methods_len; ++method){
        if(!strncmp(request_buffer, http_methods[method], strlen(http_methods[method]))){ // Http request detected

            char temp_buffer[sizeof(long)+1] = {0};
            resizable_string_t header_buffer = INIT_RESIZABLE_STRING;
            const string host_label = "Host: ";
            const size_t host_label_size = strlen(host_label);
            size_t hostname_offset = 0;
            bool reading_hostname = FALSE;

            while(bytes_read<(int)len){
                const long data = ptrace(PTRACE_PEEKDATA, pid, address+bytes_read, NULL);
                const int nbytes = min(sizeof(data), len - bytes_read);
                if(nbytes <= 0)break;
                memcpy(temp_buffer, &data, nbytes);

                if(reading_hostname){
                    char* newline_p = memchr(temp_buffer, '\r', sizeof(temp_buffer));
                    if(newline_p){
                        resizable_string_append(&header_buffer, temp_buffer, newline_p-temp_buffer);
                        string string_tail = resizable_string_get(&header_buffer) + hostname_offset;
                        string final_string = strdup(string_tail);
                        resizable_string_destroy(&header_buffer);
                        return final_string;
                    }
                }

                resizable_string_append(&header_buffer, temp_buffer, sizeof(long));

                if(!reading_hostname){
                    string read_data = resizable_string_get(&header_buffer);
                    string string_tail = read_data + resizable_string_len(&header_buffer)
                        -host_label_size - sizeof(long); // No need to search the entire string

                    if(!reading_hostname && string_tail>=read_data){
                        string host_start;
                        if((host_start = strstr(string_tail, host_label))){
                            hostname_offset = host_start-read_data+host_label_size;
                            reading_hostname = TRUE;
                        }
                    }
                }

                bytes_read+=nbytes;
            }

            return NULL;
        }
    }

    return NULL;
}

static void record_http_data(statistics_t* stats, string hostname, pid_t pid, long address, long len){
    if(len<=0)return; // Abort

    string buffer = (string)safe_malloc(len+1);

    for(long i=0;i<len;i+=sizeof(long)){
        long data = ptrace(PTRACE_PEEKDATA, pid, address+i, NULL);
        memcpy(buffer+i, &data, sizeof(long));
    }
    buffer[len] = '\0';

    if(hostname)stats->longest_hostname = max(stats->longest_hostname, strlen(hostname));
    record_list_append(stats->http_content, hostname, buffer);

    safe_free(buffer); // Not needed anymore
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

statistics_t monitor_execution(pid_t pid){
    if(pid==0){
        ERROR("Cannot monitor execution of self");
        exit(EXIT_FAILURE);
    }

    DEBUG("Started monitoring process '%d'", pid);

    int execution_status;
    hashtable_IS_t fd_hashtable = new_hashtable_IS();

    // Statistics
    statistics_t stats;
    stats.file_accesses = new_hashtable_SS();
    stats.http_content = new_record_list();
    stats.longest_filename = 0;
    stats.longest_hostname = 0;

    INFO("Initialized data structures");
    //

    // Default file streams (open from parent)
    hashtable_IS_put(fd_hashtable, 0, "stdin");
    hashtable_IS_put(fd_hashtable, 1, "stdout");
    hashtable_IS_put(fd_hashtable, 2, "stderr");

    // Registers
    long orig_eax;
    bool in_system_call = FALSE;
    string open_filename;
    
    INFO("Running...");

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
                if(fd != -1 && open_filename){
                    hashtable_IS_put(fd_hashtable, fd, open_filename);
                    timestamp_t timestamp = {strdup(get_current_date()), strdup(get_current_time()), FALSE};
                    DEBUG("Created hashtable entry for fd %d, file: %s", fd, open_filename);
                    hashtable_SS_put(stats.file_accesses, open_filename, timestamp);
                    stats.longest_filename = max(stats.longest_filename, strlen(open_filename));
                    open_filename = NULL;
                    free(open_filename); // 'put' performs a deep copy of the string anyway
                }
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

        // First the deep-inspection system calls
        if(orig_eax == SYS_read || orig_eax == SYS_write){
            if(!in_system_call){
                // The first argument to read/write is the file descriptor
                int fd = REG_ARG1(regs);
                string filename = hashtable_IS_find(fd_hashtable, fd);

                if(filename==NULL){
                    ERROR("Detected read/write from/to an unopened file stream (fd '%d' not found)", fd);
                }else{
                    timestamp_t retrieved;
                    timestamp_t timestamp = {strdup(get_current_date()), strdup(get_current_time()), FALSE};
                    if((retrieved = hashtable_SS_find(stats.file_accesses, filename)).valid){
                        safe_free(retrieved.date);
                        safe_free(retrieved.time);
                        hashtable_SS_modify(stats.file_accesses, filename, timestamp);
                        stats.longest_filename = max(stats.longest_filename, strlen(filename));
                    }
                }

                if(!syscall_count[orig_eax])
                    INFO("Subprocess made file access (%s) '%s' for the first time", syscall_names[orig_eax], filename?filename:"Not found");
                else
                    INFO("Subprocess made file access (%s) '%s' (#%lu)", syscall_names[orig_eax], filename?filename:"Not found", syscall_count[orig_eax]);

                syscall_count[orig_eax]++;
            }
        }else if(orig_eax == SYS_sendto) {
            if(!in_system_call){
                string host_name;
                long buffer = REG_ARG2(regs);
                long buffer_len = REG_ARG3(regs);

                bool is_http_request = buffer && (host_name = peek_http_header(pid, buffer, buffer_len));

                if(is_http_request){
                    record_http_data(&stats, host_name, pid, buffer, buffer_len);

                    if(!syscall_count[orig_eax])
                        INFO("Subprocess interacted with host '%s' for the first time", host_name);
                    else
                        INFO("Subprocess interacted with host '%s' (#%lu)", host_name, syscall_count[orig_eax]);

                    safe_free(host_name); // Not needed anymore
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

    return stats;
}