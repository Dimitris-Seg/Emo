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
 *@file syscalls.h
 *
 * Computer Science Department, University Of Crete
 */

#ifndef SYSCALLS_H
#define SYSCALLS_H

#include "general_types.h"
//
#include <sys/syscall.h>
#include <sys/user.h>
//

#ifdef __x86_64__
// 64-bit

#define REG_SYSCALL(regs)   (regs.orig_rax)
#define REG_ARG1(regs)      (regs.rdi)
#define REG_ARG2(regs)      (regs.rsi)
#define REG_ARG3(regs)      (regs.rdx)
#define REG_ARG5(regs)      (regs.r8)
#define REG_RETURN(regs)   ((long)(regs.rax))

extern const string syscall_names[333];

#else
// 32-bit

#define REG_SYSCALL(regs)   (regs.orig_eax)
#define REG_ARG1(regs)      (regs.ebx)
#define REG_ARG2(regs)      (regs.ecx)
#define REG_ARG3(regs)      (regs.edx)
#define REG_ARG5(regs)      (regs.edi)
#define REG_RETURN(regs)    (regs.eax)

extern const string syscall_names[385];

#endif

#define SYSCALL_VALID(x) ((x)>=0 && (x)<(long int)(sizeof(syscall_names)/sizeof(syscall_names[0])))

#endif

extern unsigned long syscall_count[sizeof(syscall_names)/sizeof(syscall_names[0])];