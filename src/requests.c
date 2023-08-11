#include <stdio.h>
#include <stdlib.h>

#include "requests.h"

struct Request *new_request_headers(char *buffer)
{
	struct Request *req = malloc(sizeof(struct Request));

	sscanf(buffer, "%s %s %s", req->method, req->uri, req->version);

	return req;
}
