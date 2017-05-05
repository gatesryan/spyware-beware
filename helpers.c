#include <string.h>
#include <stdlib.h>
#include <stdio.h>

char * join_strings(char *output_str_array[])
{
    char * final_str = malloc(strlen(output_str_array[0]));
    final_str = output_str_array[0];


    size_t length_of_prev_strings = strlen(output_str_array[0]);
    for (int i = 1; i < 1000; i++){
        final_str = realloc(final_str, strlen(final_str)+strlen(output_str_array[i]));
        // char * end_of_string = final_str + strlen(final_str);
        if (final_str && output_str_array[i] != NULL){
            strcat(final_str, output_str_array[i]);
        }

        // length_of_prev_strings += strlen(output_str_array[i-1]);
    }

    return final_str;
}
