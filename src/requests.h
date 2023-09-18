#ifndef REQUESTS_H
#define REQUESTS_H

#include "magnolia.h"
#include "dict.h"

#define BUF_SIZE 512

struct Request {
	struct Dictionary *request_line;
	struct Dictionary *headers;
};

struct Request *new_request(char *buffer);

#endif
