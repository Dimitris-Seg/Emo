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
 *@file statstrings.c
 *
 * Computer Science Department, University Of Crete
 */

#include "statstrings.h"
#include "../utils/constants.h"
#include "../utils/logging.h"
//
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
//

/**
 * File should be open for writing
 */
static void dump_buffer(string buffer, size_t len, FILE* file){
    assert(len>0 && buffer && file);
    fwrite(buffer, sizeof(buffer[0]), len, file);
}

void find_and_store_file_strings(const string filename, const string dump_file, size_t min_sequence){
    assert(INPUT_BUFFER_SIZE && filename && dump_file && min_sequence);

    if(OUTPUT_BUFFER_SIZE < min_sequence){
        ERROR("Min valid sequence too large for output buffer to handle, got(%zu), max(%d)", min_sequence, OUTPUT_BUFFER_SIZE);
        exit(EXIT_FAILURE);
    }

    if(INPUT_BUFFER_SIZE < min_sequence){
        ERROR("Min valid sequence too large for input buffer to handle, got(%zu), max(%d)", min_sequence, INPUT_BUFFER_SIZE);
        exit(EXIT_FAILURE);
    }

    FILE* in_file = fopen(filename, "rb");
    if(!in_file){
        ERROR("Error opening file '%s' for reading: %s", filename, strerror(errno));
        exit(EXIT_FAILURE);
    }

    FILE* out_file = fopen(dump_file, "w");
    if(!out_file){
        ERROR("Error opening file '%s' for writing: %s", dump_file, strerror(errno));
        fclose(in_file);
        exit(EXIT_FAILURE);
    }

    char input_buffer[INPUT_BUFFER_SIZE];
    char output_buffer[INPUT_BUFFER_SIZE];

    size_t out_buffer_fill_level = 0;
    size_t bytes_read;
    size_t leftover = 0; // Characters that were not flushed not rejected in the last pass
    size_t prev_accepted = 0;
    size_t word_start = 0; // Index of current valid string

    while((bytes_read = fread(input_buffer + leftover, sizeof(input_buffer[0]), INPUT_BUFFER_SIZE - leftover, in_file))){
        bytes_read += leftover;
        word_start = 0;

        for(size_t i = 0; i<bytes_read; ++i){
            if(!IS_CHAR_READABLE(input_buffer[i])){
                // If there's been a sufficiently long string, save it
                if(i+prev_accepted>=word_start+min_sequence){
                    if(out_buffer_fill_level + (i-word_start) + 1 >= OUTPUT_BUFFER_SIZE){ // +1 for the new line that will be added
                        // Flush the buffer and refill
                        dump_buffer(output_buffer, out_buffer_fill_level, out_file);
                        out_buffer_fill_level = 0; // Reset level (empty)
                    }
                    memcpy(output_buffer+out_buffer_fill_level, input_buffer+word_start, (i-word_start));
                    out_buffer_fill_level += (i-word_start); // Increase fill level by size of word
                    output_buffer[out_buffer_fill_level] = '\n';
                    ++out_buffer_fill_level; // Account for '\n'
                }
                word_start = i+1; // Ignore current unreadable character
                prev_accepted = 0;
            }
        }

        leftover = 0; // Entire buffer cleared

        // Handle unflushed characters
        if(word_start + min_sequence<=bytes_read+prev_accepted){ // If there's a valid word still in the buffer
            const size_t remaining = bytes_read - word_start;
            if(out_buffer_fill_level + remaining >= OUTPUT_BUFFER_SIZE){
                dump_buffer(output_buffer, out_buffer_fill_level, out_file);
                out_buffer_fill_level = 0; // Reset fill level (empty)
            }
            memcpy(output_buffer+out_buffer_fill_level, input_buffer+word_start, remaining);
            out_buffer_fill_level += remaining;
            prev_accepted = remaining;
        }else if(word_start < bytes_read){ // If there's unflushed content in input_buffer
            leftover = bytes_read - word_start;
            memmove(input_buffer, input_buffer+word_start, leftover);
        }
    }

    if (out_buffer_fill_level > 0) {
        dump_buffer(output_buffer, out_buffer_fill_level, out_file);
    }

    if(ferror(in_file)){
        ERROR("Error reading file '%s': %s", filename, strerror(errno));
        fclose(in_file);
        exit(EXIT_FAILURE);
    }

    if(ferror(out_file)){
        ERROR("Error writing file '%s': %s", dump_file, strerror(errno));
        fclose(out_file);
        exit(EXIT_FAILURE);
    }

    fclose(out_file);
    fclose(in_file);
}