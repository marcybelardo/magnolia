#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "magnolia.h"

int get_file(char *filename, struct response *resp)
{
    char buf[1024];
    size_t count = 0;
    size_t bytes;

    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        perror("reader (file open)");
        return -1;
    }

    do {
        bytes = fread(buf, sizeof(char), 1024, fp);
        size_t adj = count * 1024;
        memcpy(resp->content + adj, buf, bytes);
        count++;
    } while (bytes == 1024);

    fclose(fp);
    
    return 0;
}
