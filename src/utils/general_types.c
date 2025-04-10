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
 *@file general_types.c
 *
 * Computer Science Department, University Of Crete
 */

#include "general_types.h"
#include "general_utils.h"
#include "logging.h"
#include "constants.h"
//
#include <stdlib.h>
#include <assert.h>
#include <string.h>
//

void resizable_string_require(resizable_string_t* rs, long remaining){
    assert(rs);

    if(!rs->content){
        rs->size = RS_STRING_DEFAULT_SIZE;
        rs->content = (string)safe_malloc(rs->size * sizeof(char));
    }

    if(rs->length + remaining + 1 > rs->size){ // Resizing needed (+1 to ensure '\0' at the end)
        while (rs->length + remaining + 1 > rs->size) {
            rs->size += RS_STRING_GROWTH_RATE;
        }
        string new_string = (string)realloc(rs->content, rs->size * sizeof(char));
        if(!new_string){
            ERROR("Resizable string failed to allocate memory");
            exit(EXIT_FAILURE);
        }
        rs->content = new_string;
    }

    rs->content[rs->size-1] = '\0';
}

void resizable_string_append(resizable_string_t* rs, void* buff, long len){
    assert(rs && buff);

    resizable_string_require(rs, len);
    memcpy(rs->content+rs->length, buff, len);
    rs->length+=len;
    rs->content[rs->length] = '\0';
}

size_t resizable_string_len(resizable_string_t* rs){
    return rs->length;
}

string resizable_string_get(resizable_string_t* rs){
    return rs->content;
}

void resizable_string_destroy(resizable_string_t* rs){
    if(rs->content)free(rs->content);
}

