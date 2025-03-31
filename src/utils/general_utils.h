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
 *@file general_utils.h
 *
 * Computer Science Department, University Of Crete
 */

#ifndef GENERAL_UTILS_H
#define GENERAL_UTILS_H

#include <stdlib.h>

void* safe_malloc(size_t size);
void* deepCopy(const void* src, size_t size);
void safe_free(void* mem);
size_t hash_int(int value, size_t length);
int min(int a, int b);

#endif