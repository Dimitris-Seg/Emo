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
 *@file cryptohash.h
 *
 * Computer Science Department, University Of Crete
 */

#ifndef CRYPTOHASH_H
#define CRYPTOHASH_H

#include "./general_types.h"
//
#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
//

string compute_stream_MD5(const string data){
    static unsigned char md5_hash[MD5_DIGEST_LENGTH]; // Stores the raw hash
    MD5_CTX md5_ctx;

    MD5_Init(&md5_ctx);
    MD5_Update(&md5_ctx, data, strlen(data));
    MD5_Final(md5_hash, &md5_ctx);

    static char md5_readable[2*MD5_DIGEST_LENGTH+1]; // Readable format
    for(int i=0;i<MD5_DIGEST_LENGTH;i++){
        sprintf(md5_readable + i * 2, "%02x", md5_hash[i]);
    }

    return md5_readable;
}

string compute_stream_SHA256(const string data){
    static unsigned char sha256_hash[SHA256_DIGEST_LENGTH]; // Stores the raw hash
    SHA256_CTX sha256_ctx;

    SHA256_Init(&sha256_ctx);
    SHA256_Update(&sha256_ctx, data, strlen(data));
    SHA256_Final(sha256_hash, &sha256_ctx);

    static char sha256_readable[2*SHA256_DIGEST_LENGTH+1]; // Readable format
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++){
        sprintf(sha256_readable + i * 2, "%02x", sha256_hash[i]);
    }

    return sha256_readable;
}

string compute_file_MD5(const string filename){
    // TODO: Hash the file contents
    return filename;
}

string compute_file_SHA256(const string filename){
    // TODO: Hash the file contents
    return filename;
}

#endif