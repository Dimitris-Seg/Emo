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
 *@file constants.h
 *
 * Computer Science Department, University Of Crete
 */

#define FORK_FAIL -1
#define FORK_CHILD 0

// File reading
#define INPUT_BUFFER_SIZE 4112

// File writing
#define OUTPUT_BUFFER_SIZE 32

// Child process output redirection
#define CHILD_STDOUT_REDIRECTION 1
#define CHILD_STDOUT_REDIRECT_NAME "./filedumps/stdout_dump.txt"
#define CHILD_STERR_REDIRECTION 1
#define CHILD_STDERR_REDIRECT_NAME "./filedumps/stderr_dump.txt"

// String dump
#define STRING_DUMP_FILE_NAME "./filedumps/string_dump.txt"
#define MIN_STRING_SEQUENCE 4

// IS (Int-String) hashtable default size
#define DEFAULT_IS_HASHTABLE_LEN 256

// SS (String-String) hashtable default size
#define DEFAULT_SS_HASHTABLE_LEN 256

// Resizable string 
#define RS_STRING_DEFAULT_SIZE 64
#define RS_STRING_GROWTH_RATE 64

// File path
#define MAX_FILE_PATH_LEN 256

// Hostname length
#define MAX_HOSTNAME_LEN 256

// Http methods
#define MAX_HTTP_METHOD_LEN 8

// Range of printable characters is 32-126 (including SPACE, excluding DEL)
#define IS_CHAR_READABLE(c) (((c)>=32 && (c)<=126) || (c)==9)