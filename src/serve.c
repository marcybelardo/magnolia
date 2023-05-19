#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dict.h"
#include "magnolia.h"
#include "queue.h"
#include "serve.h"

int method_select(char *method)
{
	if (strcmp(method, "GET") == 0) {
		return GET;
	} else if (strcmp(method, "POST") == 0) {
		return POST;
	} else if (strcmp(method, "PUT") == 0) {
		return PUT;
	} else if (strcmp(method, "HEAD") == 0) {
		return HEAD;
	} else if (strcmp(method, "PATCH") == 0) {
		return PATCH;
	} else if (strcmp(method, "DELETE") == 0) {
		return DELETE;
	} else if (strcmp(method, "CONNECT") == 0) {
		return CONNECT;
	} else if (strcmp(method, "OPTIONS") == 0) {
		return OPTIONS;
	} else if (strcmp(method, "TRACE") == 0) {
		return TRACE;
	} else {
		return -1;
	}
}

void parse_request(char *request_string, struct HTTP_request *request)
{
	char requested[strlen(request_string)];
	memcpy(requested, request_string, strlen(request_string));

	for (int i = 0; i < strlen(requested) - 2; i++) {
		if (requested[i] == '\n' && requested[i + 1] == '\n') {
			request_string[i + 1] = '|';
		}
	}

	char *request_line = strtok(request_string, "\n");
	char *header_fields = strtok(NULL, "|");
	char *body = strtok(NULL, "|");

	char *method = strtok(request_line, " ");
	request->method = method_select(method);
	if (request->method < 0) {
		perror("parse request line (method select)");
		return;
	}

	char *uri = strtok(NULL, " ");
	request->uri = uri;

	char *version = strtok(NULL, "/");
	version = strtok(NULL, "\n");
	request->HTTP_version = atof(version);

	request->header_fields = dict_construct(compare_string_keys);
	struct Queue headers = queue_construct();

	char *token = strtok(header_fields, "\n");
	while (token) {
		headers.push(&headers, token, sizeof(*token));
		token = strtok(NULL, "\n");
	}

	char *header = headers.peek(&headers);
	while (header) {
		char *key = strtok(header, ":");
		char *value = strtok(NULL, "|");
		request->header_fields.insert(&request->header_fields, key,
					      sizeof(*key), value,
					      sizeof(*value));
	}
}

int get_file(char *uri, struct response *resp)
{
	char source[1024];
	char buf[1024];
	size_t count = 0;
	size_t bytes;

	char *dir = "../public";

	memcpy(source, dir, strlen(dir));
	memcpy(source + strlen(dir), uri, strlen(uri));

	printf("SOURCE: %s\n", source);

	FILE *fp = fopen(source, "rb");
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
