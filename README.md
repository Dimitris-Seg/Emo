# Assignment 1 – Part 1: Executable Monitor

- Course: HY-457
- Computer Science Department, University Of Crete
- Author: Dimitris Segkesser, A.M.: 5006

# Brief

'Emo' (Executable MOnitor) is an implementation of an executable monitor
for PHAs, useful for tracking basic but crucial system calls, file accesses and
network communications the executable might perform during its execution.

# Options

'Emo' can be configured to redirect the child process's output to dump files by modifying the 
`CHILD_STDOUT_REDIRECTION` and `CHILD_STDERR_REDIRECTION` macros in `constants.h`.


Command-line arguments to the tracee can be passed normally as extra arguments to the program

# Output

With the default configuration, Emo will dump the stdout and stderr output streams to
/filedumps/stdout_dump.txt and /filedumps/stderr_dump.txt respectively, to ensure the
output of the monitor remains fully readable. Also, it will perform a string lookup in
the executable, dumping strings that are likely human-readable in /filedumps/string_dump.txt,
much like the 'strings' utility.

# Execution and testing

The provided Makefile can be used to build the executable, and run the provided tests.
The following targets are supported:
 1) all
 2) clean
 3) clean-dumps
 4) iotest
 5) httptest1
 6) httptest2 
 7) mixedtest
 8) simpletest

Supported Makefile targets:

1. `all` – Builds the application  
2. `clean` – Removes the build directory  
3. `clean-dumps` – Removes all files in `./filedumps`  
4. `iotest` – Reads from an input file and writes to an output file  
5. `httptest1` – Sends an HTTP request to google.com  
6. `httptest2` – Sends HTTP requests to 3 different hosts  
7. `mixedtest` – Sends an HTTP request and a malformed TCP message to example.com  
8. `simpletest` – Basic Hello World program for string dump observation  
