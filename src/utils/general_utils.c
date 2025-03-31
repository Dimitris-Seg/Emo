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
 *@file general_utils.c
 *
 * Computer Science Department, University Of Crete
 */

#include "general_utils.h"
#include "logging.h"
//
#include <stdio.h>
#include <string.h>
//

void* safe_malloc(size_t size)
{
    void* allocated = malloc(size);
    if (allocated == NULL)
    {
        ERROR("Malloc: Unable to allocate memory.");
        exit(EXIT_FAILURE);
    }
    return allocated;
}

void* deepCopy(const void* src, size_t size) {
    // Allocate memory for the new object
    void* copy = safe_malloc(size);

    // Copy the contents of the original object
    memcpy(copy, src, size);

    return copy;
}

void safe_free(void* mem)
{
    if(!mem){
        ERROR("Free: Invalid memory pointer 'NULL'");
        exit(EXIT_FAILURE);
    }

    free(mem);
}

size_t hash_int(int value, size_t length){
    return value%length;
}

int min(int a, int b){
    return (a<b?a:b);
}