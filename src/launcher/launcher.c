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
 *@file launcher.c
 *
 * Computer Science Department, University Of Crete
 */

#include "./launcher.h"
#include "../utils/constants.h"
#include "../utils/logging.h"
//
#include <stdlib.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <assert.h>
//

pid_t tryLaunch(string ename){
    assert(ename);

    pid_t res = fork();
    switch (res){
    case FORK_FAIL:
        ERROR("Failed to launch executable '%s'", ename);
        break;
    case FORK_CHILD:
        // Change process here
        DEBUG("Child process with pid (%d) created", getpid());

        //ptrace(PTRACE_TRACEME, getpid()); // Start tracing self

        // Switch to the executable specified by 'ename'
        string exec_argv[] = {ename, NULL};
        string exec_env[] = {NULL};
        execve(ename, exec_argv, exec_env); // This should not return if all goes well
        ERROR("Failed to run executable '%s'", ename);
        exit(EXIT_FAILURE);
    default:
        DEBUG("Parent process %d successfully created subprocess with pid %d", getpid(), res);
    }

    return res;
}