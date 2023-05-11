#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "magnolia.h"

int get_html(char *filename, struct response *resp)
{
    char buf[1024];
    size_t count = 0;

    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        perror("reader (file open)");
        return -1;
    }

    while (fread(buf, sizeof(char), 1024, fp) == sizeof(buf)) {
        size_t adj = count * 1024;
        memcpy(resp->content + adj, buf, 1024);
        count++;
    }

    fclose(fp);
    printf("DATA: %s\n", resp->content);
    
    return 0;
}
