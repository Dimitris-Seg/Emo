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
 *@file hashtableIS.h
 *
 * Computer Science Department, University Of Crete
 */

#ifndef HASHTABLEIS_H
#define HASHTABLEIS_H

#include "../utils/general_types.h"
#include "../utils/constants.h"
//
#include <stdio.h>
#include <stdlib.h>
//
 
typedef struct hashtable_entry *hashtable_entry_t;
typedef struct hashtable_IS *hashtable_IS_t;
struct hashtable_entry* new_hashtable_entry(int _key, string _value);
void delete_hashtable_entry(struct hashtable_entry* obj);
struct hashtable_IS* new_hashtable_IS();
void delete_hashtable_IS(struct hashtable_IS* obj);

void hashtable_IS_put(hashtable_IS_t hashtable, int key, string value);
string hashtable_IS_find(hashtable_IS_t hashtable, int key);
void hashtable_IS_modify(hashtable_IS_t hashtable, int key, string value);
void hashtable_IS_remove(hashtable_IS_t hashtable, int key);

#endif