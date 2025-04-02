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
 *@file record_list.c
 *
 * Computer Science Department, University Of Crete
 */

#include "record_list.h"
#include "general_utils.h"
//
#include <assert.h>
//

record_entry_t new_record_entry(string _name, string _value){
    record_entry_t new_obj = (record_entry_t)safe_malloc(sizeof(struct record_entry));
    new_obj->name = _name?(string)deepCopy(_name, (strlen(_name))*sizeof(string)):NULL;
    new_obj->value = _value?(string)deepCopy(_value, (strlen(_value))*sizeof(string)):NULL;
    new_obj->next = NULL;
    return new_obj;
}

void delete_record_entry(record_entry_t obj){
    assert(obj);

    if(obj->name)safe_free(obj->name);
    if(obj->value)safe_free(obj->value);
}

record_list_t new_record_list(){
    record_list_t new_obj = (record_list_t)safe_malloc(sizeof(struct record_list));
    new_obj->head = NULL;
    return new_obj;
}

void delete_record_list(record_list_t obj){
    assert(obj);

    record_entry_t p = obj->head;
    record_entry_t prev = NULL;
    while(p){
        prev = p;
        p = p->next;
        delete_record_entry(prev);
    }
    safe_free(obj);
}

void record_list_append(record_list_t list, string name, string value){
    assert(list && value);

    record_entry_t new_entry = new_record_entry(name, value);
    new_entry->next = list->head;
    list->head = new_entry;
}

bool record_list_empty(record_list_t list){
    assert(list);
    
    return (list->head==NULL);
}

void record_list_map(record_list_t list, void (*mapping)(record_entry_t, void*), void* args){
    assert(list);

    if(mapping!=NULL){
        record_entry_t p = list->head;
        while(p){
            mapping(p, args);
            p = p->next;
        }
    }
}