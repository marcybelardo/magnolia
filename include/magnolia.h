#ifndef MAGNOLIA
#define MAGNOLIA

#define PORT 8080
#define BUFFER_SIZE 65536

struct response {
    char *header;
    char *content;
};

#endif
