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
 *@file cryptohash.c
 *
 * Computer Science Department, University Of Crete
 */

#include "cryptohash.h"
#include "../utils/constants.h"
#include "../utils/logging.h"
//
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
//

// Hashing API //

// MD5
void init_md5_hashvalue(md5_hashvalue_t* hv){
    MD5_Init(&(hv->md5_ctx));
}

void update_md5_hashvalue(md5_hashvalue_t* hv, const string data, size_t len){
    MD5_Update(&(hv->md5_ctx), data, len);
}

void finalize_md5_hashvalue(md5_hashvalue_t* hv){
    MD5_Final(hv->md5_hash, &(hv->md5_ctx));
}

string retrieve_md5_hashvalue(md5_hashvalue_t* hv){
    static char md5_readable[2*MD5_DIGEST_LENGTH+1];
    for(int i=0;i<MD5_DIGEST_LENGTH;++i){
        sprintf(md5_readable + i * 2, "%02x", hv->md5_hash[i]);
    }
    return md5_readable;
}

// SHA256

void init_sha256_hashvalue(sha256_hashvalue_t* hv){
    SHA256_Init(&(hv->sha256_ctx));
}

void update_sha256_hashvalue(sha256_hashvalue_t* hv, const string data, size_t len){
    SHA256_Update(&(hv->sha256_ctx), data, len);
}

void finalize_sha256_hashvalue(sha256_hashvalue_t* hv){
    SHA256_Final(hv->sha256_hash, &(hv->sha256_ctx));
}

string retrieve_sha256_hashvalue(sha256_hashvalue_t* hv){
    static char sha256_readable[2*SHA256_DIGEST_LENGTH+1];
    for(int i=0;i<SHA256_DIGEST_LENGTH;++i){
        sprintf(sha256_readable + i * 2, "%02x", hv->sha256_hash[i]);
    }
    return sha256_readable;
}

//

// MD5
string md5_hash_file(const string filename){
    assert(INPUT_BUFFER_SIZE && filename);

    FILE* file = fopen(filename, "rb");
    if(!file){
        ERROR("Error opening file '%s' for reading: %s", filename, strerror(errno));
        exit(EXIT_FAILURE);
    }
    
    md5_hashvalue_t md5_hv;
    init_md5_hashvalue(&md5_hv);


    char buffer[INPUT_BUFFER_SIZE];
    size_t bytes_read;

    while((bytes_read = fread(buffer, sizeof(buffer[0]), INPUT_BUFFER_SIZE, file))>0){
        update_md5_hashvalue(&md5_hv, buffer, bytes_read);
    }

    if(ferror(file)){
        ERROR("Error reading file '%s': %s", filename, strerror(errno));
        fclose(file);
        exit(EXIT_FAILURE);
    }

    fclose(file);

    finalize_md5_hashvalue(&md5_hv);
    string hash = retrieve_md5_hashvalue(&md5_hv);
    return hash;
}

// SHA256
string sha256_hash_file(const string filename){
    assert(INPUT_BUFFER_SIZE && filename);

    FILE* file = fopen(filename, "rb");
    if(!file){
        ERROR("Error opening file '%s' for reading: %s", filename, strerror(errno));
        exit(EXIT_FAILURE);
    }
    
    sha256_hashvalue_t sha256_hv;
    init_sha256_hashvalue(&sha256_hv);


    char buffer[INPUT_BUFFER_SIZE];
    size_t bytes_read;

    while((bytes_read = fread(buffer, sizeof(buffer[0]), INPUT_BUFFER_SIZE, file))>0){
        update_sha256_hashvalue(&sha256_hv, buffer, bytes_read);
    }

    if(ferror(file)){
        ERROR("Error reading file '%s': %s", filename, strerror(errno));
        fclose(file);
        exit(EXIT_FAILURE);
    }

    fclose(file);

    finalize_sha256_hashvalue(&sha256_hv);
    string hash = retrieve_sha256_hashvalue(&sha256_hv);
    return hash;
}