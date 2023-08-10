#include <stdio.h>

#include "magnolia.h"

void read_html(char *filename, char *str)
{
    FILE *file;

    file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Error opening file\n");
    }

    fgets(str, BUFFER_SIZE, file);
}
