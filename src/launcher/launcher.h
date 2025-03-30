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
 *@file launcher.h
 *
 * Computer Science Department, University Of Crete
 */

#ifndef LAUNCHER_H
#define LAUNCHER_H

#include "../utils/general_types.h"
//
#include <sys/types.h>
//

/**
 *@brief Attempts to launch the executable specified by 'ename',
 * 
 *@param ename The name of the target executable
 *@return The result of fork()
 */
pid_t tryLaunch(string ename, int argc, string* argv);

#endif