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
#include "./utils/logging.h"
#include "./utils/constants.h"
#include "./cryptohash/cryptohash.h"
#include "./statstrings/statstrings.h"
#include "./monitoring/monitor.h"
//
#include <sys/types.h>
#include <stdlib.h>
//

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
        monitor_execution(res);
    }

    return 0;
}