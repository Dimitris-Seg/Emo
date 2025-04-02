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
 *@file general_types.h
 *
 * Computer Science Department, University Of Crete
 */

#ifndef GENERAL_TYPES_H
#define GENERAL_TYPES_H

typedef char* string;
typedef enum{FALSE, TRUE}bool;
typedef struct timestamp timestamp_t;
typedef struct resizable_string resizable_string_t;

void resizable_string_require(resizable_string_t* rs, long remaining);
void resizable_string_append(resizable_string_t* rs, void* buff, long len);
string resizable_string_get(resizable_string_t* rs);
void resizable_string_destroy(resizable_string_t* rs);

#define INVALID_TIMESTAMP \
    (timestamp_t){.date="", .time="", .valid=FALSE}

#define INIT_RESIZABLE_STRING \
    (resizable_string_t){.content=NULL, .length=0, .size=0};

struct timestamp{
    string date;
    string time;
    bool valid;
};

// Not used for now
struct resizable_string{
    string content;
    long size;
    long length;
};

#endif