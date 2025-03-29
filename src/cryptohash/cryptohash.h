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

#include "../utils/general_types.h"
//
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
//

// MD5 Hash //
typedef struct md5_hashvalue md5_hashvalue_t;

void    init_md5_hashvalue(md5_hashvalue_t* hv);
void    update_md5_hashvalue(md5_hashvalue_t* hv, const string data, size_t len);
void    finalize_md5_hashvalue(md5_hashvalue_t* hv);
string  retrieve_md5_hashvalue(md5_hashvalue_t* hv);

string md5_hash_file(const string filename);

struct md5_hashvalue{
    unsigned char md5_hash[MD5_DIGEST_LENGTH];
    MD5_CTX md5_ctx;
};
//

// SHA256 Hash //
typedef struct sha256_hashvalue sha256_hashvalue_t;

void    init_sha256_hashvalue(sha256_hashvalue_t* hv);
void    update_sha256_hashvalue(sha256_hashvalue_t* hv, const string data, size_t len);
void    finalize_sha256_hashvalue(sha256_hashvalue_t* hv);
string  retrieve_sha256_hashvalue(sha256_hashvalue_t* hv);

string sha256_hash_file(const string filename);

struct sha256_hashvalue{
    unsigned char sha256_hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_ctx;
};
//

#endif