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
 *@file hashtableSS.c
 *
 * Computer Science Department, University Of Crete
 */

 #include "hashtableSS.h"
 #include "../utils/general_types.h"
 #include "../utils/general_utils.h"
 //
 #include <string.h>
 #include <assert.h>
 //
 
hashtable_SS_entry_t new_hashtable_SS_entry(string _key, timestamp_t _value){
    hashtable_SS_entry_t new_obj = (hashtable_SS_entry_t)safe_malloc(sizeof(struct hashtable_SS_entry));
    new_obj->key = _key;
    new_obj->value = _value;
    new_obj->next = NULL;
    return new_obj;
}

void delete_hashtable_SS_entry(hashtable_SS_entry_t obj){
    safe_free(obj);
}

hashtable_SS_t new_hashtable_SS(){
    hashtable_SS_t new_obj = (hashtable_SS_t)safe_malloc(sizeof(struct hashtable_SS));
    new_obj->table = (hashtable_SS_entry_t*)calloc(DEFAULT_SS_HASHTABLE_LEN, sizeof(hashtable_SS_entry_t));
    return new_obj;
}

void delete_hashtable_SS(hashtable_SS_t obj){
    for (size_t i = 0; i < DEFAULT_SS_HASHTABLE_LEN; i++) {
        hashtable_SS_entry_t entry = obj->table[i];
        while (entry) {
            hashtable_SS_entry_t temp = entry;
            entry = entry->next;
            delete_hashtable_SS_entry(temp);
        }
    }
    safe_free(obj);
}

void hashtable_SS_put(hashtable_SS_t hashtable, string key, timestamp_t value){
    assert(hashtable && key);

    size_t hash = hash_string(key, DEFAULT_SS_HASHTABLE_LEN);
    hashtable_SS_entry_t new_entry = new_hashtable_SS_entry(key, value);
    new_entry->next = hashtable->table[hash];
    hashtable->table[hash] = new_entry;
}

timestamp_t hashtable_SS_find(hashtable_SS_t hashtable, string key){
    assert(hashtable);

    size_t hash = hash_string(key, DEFAULT_SS_HASHTABLE_LEN);
    hashtable_SS_entry_t bucket_p = hashtable->table[hash];

    while(bucket_p && strcmp(bucket_p->key, key))bucket_p = bucket_p->next; // Search

    return (bucket_p?bucket_p->value:INVALID_TIMESTAMP);
}

void hashtable_SS_modify(hashtable_SS_t hashtable, string key, timestamp_t value){
    assert(hashtable);

    size_t hash = hash_string(key, DEFAULT_SS_HASHTABLE_LEN);
    hashtable_SS_entry_t bucket_p = hashtable->table[hash];

    while(bucket_p && strcmp(bucket_p->key, key))bucket_p = bucket_p->next; // Search

    if(bucket_p)bucket_p->value = value;
}

void hashtable_SS_remove(hashtable_SS_t hashtable, string key){
    assert(hashtable);

    size_t hash = hash_string(key, DEFAULT_SS_HASHTABLE_LEN);
    hashtable_SS_entry_t bucket_p = hashtable->table[hash];
    hashtable_SS_entry_t prev_p = NULL;

    while(bucket_p && strcmp(bucket_p->key, key)){ // Search
        prev_p = bucket_p;
        bucket_p = bucket_p->next;
    }

    if(bucket_p){
        if(prev_p){
            prev_p->next = bucket_p->next;
        }else{
            hashtable->table[hash] = bucket_p->next;
        }

        delete_hashtable_SS_entry(bucket_p);
    }
}

void hashtable_SS_map(hashtable_SS_t hashtable, void (*mapping)(hashtable_SS_entry_t, void*), void* args){
    assert(hashtable);

    for(size_t i=0;i<DEFAULT_SS_HASHTABLE_LEN; ++i){
        hashtable_SS_entry_t p = hashtable->table[i];
        while(p){
            mapping(p, args);
            p = p->next;
        }
    }
}