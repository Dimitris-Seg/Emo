#include <stdio.h>
#include <stdlib.h>

#define IN_FILE "./tests/test_in.txt"
#define OUT_FILE "./test_out.txt"

int main(){
    printf("Hello, Emo!\n");

    FILE* myinfile = fopen(IN_FILE, "r");
    if(!myinfile){
        fprintf(stderr, "Uh-oh, I don't know how to read... :(\n");
        exit(EXIT_FAILURE);
    }
    FILE* myoutfile = fopen(OUT_FILE, "w");
    if(!myoutfile){
        fprintf(stderr, "Uh-oh, I don't know how to write... :(\n");
        exit(EXIT_FAILURE);
    }

    // Read first (at most) 100 characters
    char mybuff[100];
    int bytes_read = fread(mybuff, sizeof(char), 100, myinfile);
    fclose(myinfile);
    fwrite(mybuff, sizeof(char), bytes_read, myoutfile);
    fclose(myoutfile);

    printf("Goodbye, Emo!\n");
}