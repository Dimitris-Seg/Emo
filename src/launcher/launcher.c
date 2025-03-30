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
#include "../utils/general_utils.h"
#include "../utils/constants.h"
#include "../utils/logging.h"
//
#include <stdlib.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
//

pid_t tryLaunch(string ename, int argc, string* argv){
    assert(ename);

    pid_t res = fork();
    switch (res){
    case FORK_FAIL:
        ERROR("Failed to launch executable '%s'", ename);
        break;
    case FORK_CHILD:
        // Change process here
        DEBUG("Child process with pid (%d) created", getpid());

        // Redirect child output if option selected
        #if CHILD_STDOUT_REDIRECTION
        int dump_fd = open(CHILD_STDOUT_REDIRECT_NAME, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (dump_fd == -1) {
            ERROR("Error opening child stdout dump file '%s': %s", CHILD_STDOUT_REDIRECT_NAME, strerror(errno));
            exit(EXIT_FAILURE);
        }
        dup2(dump_fd, STDOUT_FILENO);
        close(dump_fd);
        #endif

        ptrace(PTRACE_TRACEME, getpid()); // Start tracing self
        
        // Create new argument list for subprocess (self now)
        string* exec_argv = (string*)safe_malloc((argc+2)*sizeof(string)); // Name and NULL as last element are required
        exec_argv[0] = ename;
        if(argc>0 && argv!=NULL){
            memcpy(exec_argv+1, argv, argc * sizeof(string));
        }
        exec_argv[argc+1] = NULL;
        //

        string exec_env[] = {NULL};

        // Switch to the executable specified by 'ename'
        execve(ename, exec_argv, exec_env); // This should not return if all goes well
        ERROR("Failed to run executable '%s': %s", ename, strerror(errno));
        exit(EXIT_FAILURE);
    default:
        DEBUG("Parent process %d successfully created subprocess with pid %d", getpid(), res);
    }

    return res;
}