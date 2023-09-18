#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "requests.h"
#include "dict.h"

struct Dictionary *parse_request_line(char *request_line_buffer);
struct Dictionary *parse_headers(char *header_buffer);

struct Request *new_request(char *buffer)
{
	char *request_line_buffer, *headers_buffer, *saveptr;
	struct Request *req = malloc(sizeof(struct Request));

	request_line_buffer = strtok_r(buffer, "\n", &saveptr);
	headers_buffer = strtok_r(NULL, "\0", &saveptr);

	req->request_line = parse_request_line(request_line_buffer);
	req->headers = parse_headers(headers_buffer);

	return req;
}

struct Dictionary *parse_request_line(char *request_line_buffer)
{
	char *method, *uri, *version_num, *saveptr;
	struct Dictionary *request_line = new_dictionary();

	method = strtok_r(request_line_buffer, " ", &saveptr);
	uri = strtok_r(NULL, " ", &saveptr);
	strtok_r(NULL, "/", &saveptr);
	version_num = strtok_r(NULL, " ", &saveptr);

	add_entry_to_dict(request_line, "Method", method);
	add_entry_to_dict(request_line, "URI", uri);
	add_entry_to_dict(request_line, "Version", version_num);

	return request_line;
}

struct Dictionary *parse_headers(char *header_buffer)
{
	char *line, *header, *value, *saveptr_l, *saveptr_h;
	struct Dictionary *headers = new_dictionary();

	for (
		line = strtok_r(header_buffer, "\n", &saveptr_l); 
		line != NULL;
		line = strtok_r(NULL, "\n", &saveptr_l)
	) {
		header = strtok_r(line, ":", &saveptr_h);
		value = strtok_r(NULL, "\n", &saveptr_h);

		add_entry_to_dict(headers, header, value);
	}

	return headers;
}

