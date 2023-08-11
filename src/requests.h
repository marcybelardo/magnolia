#ifndef REQUESTS_H
#define REQUESTS_H

#include "magnolia.h"

struct Request {
	char method[BUFFER_SIZE];
	char uri[BUFFER_SIZE];
	char version[BUFFER_SIZE];
};

struct Request *new_request_headers(char *buffer);

#endif
