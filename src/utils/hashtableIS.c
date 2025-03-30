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
 *@file hashtableIS.c
 *
 * Computer Science Department, University Of Crete
 */

#include "hashtableIS.h"
#include "../utils/general_utils.h"
//
#include <string.h>
#include <assert.h>
//

struct hashtable_entry {
    int key;
    string value;
    hashtable_entry_t next;
};

hashtable_entry_t new_hashtable_entry(int _key, string _value){
    hashtable_entry_t new_obj = (hashtable_entry_t)safe_malloc(sizeof(struct hashtable_entry));
    new_obj->key = _key;
    new_obj->value = (string)deepCopy(_value, (strlen(_value))*sizeof(string));
    new_obj->next = NULL;
    return new_obj;
}

void delete_hashtable_entry(hashtable_entry_t obj){
    safe_free(obj->value);
    safe_free(obj);
}

struct hashtable_IS {
    hashtable_entry_t* table;
};

hashtable_IS_t new_hashtable_IS(){
    hashtable_IS_t new_obj = (hashtable_IS_t)safe_malloc(sizeof(struct hashtable_IS));
    new_obj->table = (hashtable_entry_t*)calloc(DEFAULT_IS_HASHTABLE_LEN, sizeof(hashtable_entry_t));
    return new_obj;
}

void delete_hashtable_IS(hashtable_IS_t obj){
    for (size_t i = 0; i < DEFAULT_IS_HASHTABLE_LEN; i++) {
        hashtable_entry_t entry = obj->table[i];
        while (entry) {
            hashtable_entry_t temp = entry;
            entry = entry->next;
            delete_hashtable_entry(temp);
        }
    }
    safe_free(obj);
}

void hashtable_IS_put(hashtable_IS_t hashtable, int key, string value){
    assert(hashtable && value);

    size_t hash = hash_int(key, DEFAULT_IS_HASHTABLE_LEN);
    hashtable_entry_t new_entry = new_hashtable_entry(key, value);
    new_entry->next = hashtable->table[hash];
    hashtable->table[hash] = new_entry;
}

string hashtable_IS_find(hashtable_IS_t hashtable, int key){
    assert(hashtable);

    size_t hash = hash_int(key, DEFAULT_IS_HASHTABLE_LEN);
    hashtable_entry_t bucket_p = hashtable->table[hash];

    while(bucket_p && bucket_p->key!=key)bucket_p = bucket_p->next; // Search

    return (bucket_p?bucket_p->value:NULL);
}

void hashtable_IS_modify(hashtable_IS_t hashtable, int key, string value){
    assert(hashtable);

    size_t hash = hash_int(key, DEFAULT_IS_HASHTABLE_LEN);
    hashtable_entry_t bucket_p = hashtable->table[hash];

    while(bucket_p && bucket_p->key!=key)bucket_p = bucket_p->next; // Search

    if(bucket_p)bucket_p->value = value;
}

void hashtable_IS_remove(hashtable_IS_t hashtable, int key){
    assert(hashtable);

    size_t hash = hash_int(key, DEFAULT_IS_HASHTABLE_LEN);
    hashtable_entry_t bucket_p = hashtable->table[hash];
    hashtable_entry_t prev_p = NULL;

    while(bucket_p && bucket_p->key!=key){ // Search
        prev_p = bucket_p;
        bucket_p = bucket_p->next;
    }

    if(bucket_p){
        if(prev_p){
            prev_p->next = bucket_p->next;
        }else{
            hashtable->table[hash] = bucket_p->next;
        }

        delete_hashtable_entry(bucket_p);
    }
}