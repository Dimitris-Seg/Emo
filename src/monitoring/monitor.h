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
 *@file monitor.h
 *
 * Computer Science Department, University Of Crete
 */

#ifndef MONITOR_H
#define MONITOR_H

#include "../utils/record_list.h"
#include "../utils/hashtableSS.h"
//
#include <fcntl.h>
//

typedef struct statistics statistics_t;

statistics_t monitor_execution(pid_t pid);

struct statistics{
    hashtable_SS_t file_accesses;
    record_list_t http_content;
    size_t longest_filename;
    size_t longest_hostname;
};

#endif