#ifndef SERVE_h
#define SERVE_h

#include "dict.h"

enum HTTP_methods {
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

struct HTTP_request {
	int method;
	char *uri;
	double HTTP_version;
	struct Dictionary header_fields;
};

void parse_request(char *request_string, struct HTTP_request *request);
int get_file(char *filename, struct response *resp);

#endif
