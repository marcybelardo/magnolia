#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "magnolia.h"
#include "httpserver.h"
#include "requests.h"
#include "files.h"
#include "dict.h"
#include "dict_entry.h"

int main(void)
{
	struct HttpServer *server = init_httpserver(PORT);	

	if (open_connection(server) != 0) {
		return -1;
	}

	for (;;) {
		struct SocketReader sockread;

		if (read_socket(server, &sockread) != 0) {
			return -1;
		}

		struct Request *req = new_request(sockread.buffer);

		printf("[%s:%u] %s %s %s\n", inet_ntoa(server->client_addr.sin_addr), 
			ntohs(server->client_addr.sin_port), req->method, req->uri, req->version);

		char full_uri[BUFFER_SIZE] = "../public";
		strcat(full_uri, req->uri);
		
		char out[BUFFER_SIZE];
		if (read_html(full_uri, out) != 0) {
			perror("webserver (read file)");
			continue;
		}

		char full_resp[BUFFER_SIZE] = "HTTP/1.1 200 OK\r\nServer: magnolia\r\nContent-Type: text/html\r\n\r\n";
		strcat(full_resp, out);
		printf("resp: %s\n", full_resp);

		int valwrite = write(sockread.newsockfd, full_resp, BUFFER_SIZE);
		if (valwrite < 0) {
			perror("webserver (write)");
			continue;
		}

		close(sockread.newsockfd);
	}

	return 0;
}
