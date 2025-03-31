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

#ifndef TYPES_H
#define TYPES_H

typedef char* string;
typedef enum{FALSE, TRUE}bool;
typedef struct timestamp timestamp_t;

#define INVALID_TIMESTAMP \
    (timestamp_t){.date="", .time="", .valid=FALSE}

struct timestamp{
    string date;
    string time;
    bool valid;
};

#endif