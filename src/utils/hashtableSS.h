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
 *@file hashtableSS.h
 *
 * Computer Science Department, University Of Crete
 */

#ifndef HASHTABLESS_H
#define HASHTABLESS_H

#include "../utils/general_types.h"
#include "../utils/constants.h"
//
#include <stdio.h>
#include <stdlib.h>
//
  
typedef struct hashtable_SS_entry *hashtable_SS_entry_t;
typedef struct hashtable_SS *hashtable_SS_t;
struct hashtable_SS_entry* new_hashtable_SS_entry(string _key, timestamp_t _value);
void delete_hashtable_SS_entry(struct hashtable_SS_entry* obj);
struct hashtable_SS* new_hashtable_SS();
void delete_hashtable_SS(struct hashtable_SS* obj);

void hashtable_SS_put(hashtable_SS_t hashtable, string key, timestamp_t value);
timestamp_t hashtable_SS_find(hashtable_SS_t hashtable, string key);
void hashtable_SS_modify(hashtable_SS_t hashtable, string key, timestamp_t value);
void hashtable_SS_remove(hashtable_SS_t hashtable, string key);
void hashtable_SS_map(hashtable_SS_t hashtable, void (*mapping)(hashtable_SS_entry_t, void*), void* args);
 
struct hashtable_SS_entry {
    string key;
    timestamp_t value;
    hashtable_SS_entry_t next;
};

struct hashtable_SS {
    hashtable_SS_entry_t* table;
};

#endif