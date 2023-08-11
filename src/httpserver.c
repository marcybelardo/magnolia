#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>

#include "httpserver.h"

struct HttpServer *init_httpserver(int port)
{
	struct HttpServer *server = malloc(sizeof(struct HttpServer));

	// Create address to bind the socket to
	server->host_addrlen = sizeof(server->host_addr);

	server->host_addr.sin_family = AF_INET;
	server->host_addr.sin_port = htons(port);
	server->host_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	// Create client address
	server->client_addrlen = sizeof(server->client_addr);

	return server;
}

int open_connection(struct HttpServer *server)
{
	// Create socket
	server->sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (server->sockfd == -1) {
		perror("webserver (socket)");
		return 1;
	}
	printf("Socket created successfully!\n");

	// Bind socket to address
	if (bind(server->sockfd, (struct sockaddr *)&server->host_addr, 
		server->host_addrlen) != 0) {
		perror("webserver (bind)");
		return 1;
	}
	printf("Socket successfully bound to address!\n");

	// Listen for incoming connections
	if (listen(server->sockfd, SOMAXCONN) != 0) {
		perror("webserver (listen)");
		return 1;
	}
	printf("Server listening for connections...\n");

	return 0;
}
