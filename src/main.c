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
 *@file main.c
 *
 * Computer Science Department, University Of Crete
 */

#include "./launcher/launcher.h"
#include "./utils/general_types.h"
#include "./utils/general_utils.h"
#include "./utils/logging.h"
#include "./utils/constants.h"
#include "./cryptohash/cryptohash.h"
#include "./statstrings/statstrings.h"
#include "./monitoring/monitor.h"
//
#include <sys/types.h>
#include <stdlib.h>
//

void print_file_access(hashtable_SS_entry_t e, void* args){
    size_t largest_filename = *((size_t*)args);
    PRINTLN("|  %-*s |  [%s %s]  |", (int)largest_filename+1, e->key, e->value.date, e->value.time);
}

void print_file_accesses(statistics_t stats){
    const int column_size[] = {(int)stats.longest_filename+4, 24};
    const int row_size = column_size[0]+column_size[1] + 4;
    const string labels[] = {"STATISTICS", "Files Accessed", "Last Accessed"};
    for(int i=0;i<row_size;++i)PRINT("=");PRINT("\n");
    PRINTLN("|%-*s%s%-*s|", 
    (myfloor(row_size / 2.f) - myfloor(strlen(labels[0]) / 2.f) - 1), "", 
    labels[0],
    (myceil(row_size / 2.f) - myceil(strlen(labels[0]) / 2.f) - 1), "");
    for(int i=0;i<row_size;++i)PRINT("=");PRINT("\n");

    PRINTLN("|%-*s%s%-*s|%-*s%s%-*s  |", 
        (myfloor(column_size[0] / 2.f) - myfloor(strlen(labels[1]) / 2.f)), "", 
        labels[1],
        (myceil(column_size[0] / 2.f) - myceil(strlen(labels[1]) / 2.f)), "", 
        7, "", 
        labels[2],
        (column_size[1] / 2) - (int)strlen(labels[2]) / 2 - 3, ""
    );
    

    for(int i=0;i<row_size;++i)PRINT("=");PRINT("\n");
    hashtable_SS_map(stats.file_accesses, print_file_access, &stats.longest_filename);
    for(int i=0;i<row_size;++i)PRINT("=");PRINT("\n");
}

void print_statistics(statistics_t stats){
    print_file_accesses(stats);
}

int main(int argc, string* argv){

    if(argc<2){
        ERROR("Missing command-line argument for 'tracee' executable");
        exit(EXIT_FAILURE);
    }

    PRINT_WATERMARK();

    // CLI(s) should be valid by this point
    string pname = argv[1];

    INFO("Application started with argument '%s'", pname);
    INFO("MD5 hash:    %s", md5_hash_file(pname));
    INFO("SHA256 hash: %s", sha256_hash_file(pname));
    find_and_store_file_strings(pname, STRING_DUMP_FILE_NAME, MIN_STRING_SEQUENCE);

    pid_t res = tryLaunch(pname, argc-2, argv+2);

    if(res!=FORK_FAIL){
        statistics_t stats = monitor_execution(res);
        print_statistics(stats);
    }

    return 0;
}