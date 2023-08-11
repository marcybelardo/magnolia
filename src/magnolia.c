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

int main(void)
{
	char buffer[BUFFER_SIZE];
	struct HttpServer *server = init_httpserver(PORT);	

	if (open_connection(server) != 0) {
		return -1;
	}

	for (;;) {
		// Accept incoming connection
		int newsockfd = accept(server->sockfd, (struct sockaddr *)&server->host_addr, 
					(socklen_t *)&server->host_addrlen);

		if (newsockfd < 0) {
			perror("webserver (accept)");
			continue; 
		}
		printf("Connection accepted!\n");

		// Get client address
		int sockn = getsockname(newsockfd, (struct sockaddr *)&server->client_addr, 
				(socklen_t *)&server->client_addrlen);
		if (sockn < 0) {
			perror("webserver (getsockname)");
			continue;
		}

		// Read from the socket
		int valread = read(newsockfd, buffer, BUFFER_SIZE);
		if (valread < 0) {
			perror("webserver (read)");
			continue;
		}

		struct Request *req = new_request_headers(buffer);

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

		int valwrite = write(newsockfd, full_resp, BUFFER_SIZE);
		if (valwrite < 0) {
			perror("webserver (write)");
			continue;
		}

		close(newsockfd);
	}

	return 0;
}
