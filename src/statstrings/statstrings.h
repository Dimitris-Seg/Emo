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
 *@file statstrings.h
 *
 * Computer Science Department, University Of Crete
 */

#ifndef STATSTRINGS_H
#define STATSTRINGS_H

#include "../utils/general_types.h"
//
#include <string.h>
//

/**
 * Finds and stores all (potential) user-readable strings of 
 * minimum length 'min_sequence' within the
 * file (filename) and dumps them in dump_file
 * 
 * Basically replicates some of the functionality of the 'strings' UNIX utility
 */
void find_and_store_file_strings(const string filename, const string dump_file, size_t min_sequence);

#endif