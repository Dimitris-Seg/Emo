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
#include "./utils/syscalls.h"
#include "./cryptohash/cryptohash.h"
#include "./statstrings/statstrings.h"
#include "./monitoring/monitor.h"
//
#include <sys/types.h>
#include <stdlib.h>
#include <errno.h>
//

typedef struct map_data{
    FILE* out_stream;
    void* extra;
}map_data_t;

void print_file_access(hashtable_SS_entry_t e, void* args){
    map_data_t* data = (map_data_t*)args;
    FILE* out_stream = data->out_stream;
    size_t largest_filename = *((size_t*)data->extra);

    fprintf(out_stream, "|  %-*s |  [%s %s]  |\n", (int)largest_filename+1, e->key, e->value.date, e->value.time);
}

void print_file_accesses(statistics_t stats, FILE* out_stream){
    const int column_size[] = {(int)stats.longest_filename+4, 24};
    const int row_size = column_size[0]+column_size[1] + 4;
    const string labels[] = {"File Access Statistics", "Files Accessed", "Last Accessed"};
    for(int i=0;i<row_size;++i)
        fprintf(out_stream, "=");
    fprintf(out_stream, "\n");
    fprintf(out_stream, "|%-*s%s%-*s|\n", 
    (myfloor(row_size / 2.f) - myfloor(strlen(labels[0]) / 2.f) - 1), "", 
    labels[0],
    (myceil(row_size / 2.f) - myceil(strlen(labels[0]) / 2.f) - 1), "");
    for(int i=0;i<row_size;++i)
        fprintf(out_stream, "=");
    fprintf(out_stream, "\n");

    fprintf(out_stream, "|%-*s%s%-*s|%-*s%s%-*s  |\n", 
        (myfloor(column_size[0] / 2.f) - myfloor(strlen(labels[1]) / 2.f)), "", 
        labels[1],
        (myceil(column_size[0] / 2.f) - myceil(strlen(labels[1]) / 2.f)), "", 
        7, "", 
        labels[2],
        (column_size[1] / 2) - (int)strlen(labels[2]) / 2 - 3, ""
    );

    for(int i=0;i<row_size;++i)
        fprintf(out_stream, "=");
    fprintf(out_stream, "\n");
    map_data_t data = {.out_stream=out_stream, .extra=&stats.longest_filename};
    hashtable_SS_map(stats.file_accesses, print_file_access, &data);
    for(int i=0;i<row_size;++i)
        fprintf(out_stream, "=");
    fprintf(out_stream, "\n");
}

/**
 * Only for percentages
 */
int length_of_int(int num){
    char buff[4] = {0}; 
    sprintf(buff, "%d", num);
    return strlen(buff);
}

void print_syscalls(FILE* out_stream){
    const string title = "System call frequencies";

    const int max_syscall_len = 32; // A little extra for padding
    const int syscalls_len = sizeof(syscall_names)/sizeof(syscall_names[0]);

    int total_syscalls = 0;
    int total_included_syscalls = 0;
    for(int i=0;i<syscalls_len;++i){
        total_syscalls+=(syscall_count[i]); // Calculate true count
        total_included_syscalls+=(syscall_count[i]!=0);
    }

    if(!total_syscalls)return;

    int current_col = 1;
    int curr_syscall_count = 0;
    const int num_columns = 2;
    const int table_padding = 2;
    
    const float row_size = (num_columns*(39+2*table_padding + 3) + 1);
    const float title_center = row_size/2.f - strlen(title)/2.f - 1;

    for(int i=0;i<(int)row_size;++i)
        fprintf(out_stream, "=");
    fprintf(out_stream, "\n");
    fprintf(out_stream, "|%-*s%s%-*s|\n", myfloor(title_center), "", title, myceil(title_center), "");
    for(int i=0;i<(int)row_size;++i)
        fprintf(out_stream, "=");
    fprintf(out_stream, "\n");

    for(int i=0;i<syscalls_len;++i){
        if(syscall_count[i]==0)continue; // Skip unused entry

        ++curr_syscall_count;

        float percentage = (syscall_count[i] * 100.0) / total_syscalls;
        int percentage_len = length_of_int((int)percentage)+1;

        fprintf(out_stream, "|%-*s", table_padding, ""); // Padding before entry

        fprintf(out_stream, "%-*s[%-3.1f%%]%-*s",
            max_syscall_len, syscall_names[i],
            percentage, // Percentage calculation
            table_padding + (5-percentage_len), "");

        if(current_col == num_columns){
            current_col = 0; // End current row
            fprintf(out_stream, "|\n"); // Padding at the end

            if(curr_syscall_count<total_included_syscalls){ // Only if not in the last row
                fprintf(out_stream, "|"); for(int i=0;i<(int)row_size-2;++i)fprintf(out_stream, "-");fprintf(out_stream, "|\n");
            }
        }


        ++current_col;
    }

    bool unfinished = FALSE;

    while(current_col > 1 && current_col <= num_columns){
        fprintf(out_stream, "|%-*s", max_syscall_len + 9 + 2 * table_padding, "");
        unfinished = TRUE;
        ++current_col;
    }

    if(unfinished)fprintf(out_stream, "|\n");

    for(int i=0;i<(int)row_size;++i)
        fprintf(out_stream, "=");
    fprintf(out_stream, "\n");
}

void print_content(record_entry_t re, void* args){
    map_data_t* data = (map_data_t*)args;
    FILE* out_stream = data->out_stream;
    int padding = *((int*)data->extra);
    int largest_hostname = *(((int*)data->extra)+1);
    const string labels[] = {"Host: ", " HTTP request start ", " HTTP request end "};
    int row_size = largest_hostname + 2*padding + 2 + strlen(labels[0]);

    // Host name
    if(re->name){
        fprintf(out_stream, " ");
        for(int i=0;i<row_size-1;++i)
            fprintf(out_stream, "_");
        fprintf(out_stream, "\n");
        fprintf(out_stream, "|%-*s%s%-*s|\n", padding, "", labels[0], (int)(largest_hostname + padding + 1), re->name);
        fprintf(out_stream, " ");
        for(int i=0;i<row_size-1;++i)
            fprintf(out_stream, "-");
        fprintf(out_stream, "\n\n");

        for(int i=0;i<myfloor(row_size/2.f-strlen(labels[1])/2.f);++i)
            fprintf(out_stream, "*");
        fprintf(out_stream, "%s", labels[1]);
        for(int i=0;i<myceil(row_size/2.f-strlen(labels[1])/2.f);++i)
            fprintf(out_stream, "*");

        fprintf(out_stream, "\n\n");    

        // Content
        fprintf(out_stream, "%s", re->value);

        for(int i=0;i<myfloor(row_size/2.f-strlen(labels[2])/2.f);++i)
            fprintf(out_stream, "*");
        fprintf(out_stream, "%s", labels[2]);
        for(int i=0;i<myceil(row_size/2.f-strlen(labels[2])/2.f);++i)
            fprintf(out_stream, "*");

        fprintf(out_stream, "\n\n");  
    }
}

void print_http_content_sent(statistics_t stats, FILE* out_stream){

    if(record_list_empty(stats.http_content))return; // Do nothing if empty

    const int padding = 2;
    int args[] = {padding, stats.longest_hostname};
    map_data_t data = {.out_stream=out_stream, .extra=&args};
    const int width = stats.longest_hostname + 2*padding + 8;
    const string title = "HTTP content sent";
    fprintf(out_stream, " ");
    for(int i=0;i<width;++i)
            fprintf(out_stream, "=");
    fprintf(out_stream, "\n");
    fprintf(out_stream, "|%-*s%s%-*s|\n", myfloor(width/2.f-strlen(title)/2.f), "", title, myceil(width/2.f-strlen(title)/2.f), "");
    fprintf(out_stream, " ");
    for(int i=0;i<width;++i)
            fprintf(out_stream, "=");
    fprintf(out_stream, "\n");
    record_list_map(stats.http_content, print_content, &data);
}

void print_statistics(statistics_t stats, FILE* out_stream){
    fprintf(out_stream, "\n");
    print_syscalls(out_stream);
    fprintf(out_stream, "\n");
    print_file_accesses(stats, out_stream);
    fprintf(out_stream, "\n");
    print_http_content_sent(stats, out_stream);
}

void print_help(string name){
    PRINTLN("Usage: %s <executable filepath> <...executable args>", name);
}

int main(int argc, string* argv){

    if(argc<2){
        ERROR("Missing command-line argument for 'tracee' executable");
        print_help(argv[0]);
        exit(EXIT_FAILURE);
    }

    string stat_output_filename = "./filedumps/report.txt";

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

        FILE* stat_out_file = fopen(stat_output_filename, "w");
        if(stat_out_file){
            print_statistics(stats, stat_out_file);
            INFO("Stored report in '%s'", stat_output_filename);
            fclose(stat_out_file);
        }else{
            ERROR("Could not open output file '%s' for writing: %s", stat_output_filename, strerror(errno));
        }
    }

    return 0;
}