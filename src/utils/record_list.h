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
 *@file record_list.h
 *
 * Computer Science Department, University Of Crete
 */


#ifndef RECORD_LIST_H
#define RECORD_LIST_H

#include "general_types.h"
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//

typedef struct record_entry *record_entry_t;
typedef struct record_list *record_list_t;
struct record_entry* new_record_entry(string _name, string _value);
void delete_record_entry(struct record_entry* obj);
struct record_list* new_record_list();
void delete_record_list(struct record_list* obj);
void record_list_append(record_list_t list, string name, string value);
void record_list_map(record_list_t list, void (*mapping)(record_entry_t, void*), void* args);
bool record_list_empty(record_list_t list);

struct record_entry {
    string name;
    string value;
    record_entry_t next;
};

struct record_list {
    record_entry_t head;
};

#endif