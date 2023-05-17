#ifndef SERVE
#define SERVE 

enum HTTP_methods 
{
    GET,
    POST,
    PUT,
    HEAD,
    PATCH,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
};

struct HTTP_request 
{
    int method;
    char *uri;
    double HTTP_version;
};

void parse_request_line(char *request_string, struct HTTP_request *request);

int get_file(char *filename, struct response *resp);

#endif
