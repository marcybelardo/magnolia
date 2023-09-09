#ifndef HTTPSERVER_H
#define HTTPSERVER_H

#include <arpa/inet.h>

#include "magnolia.h"

struct HttpServer {
	int sockfd;
	struct sockaddr_in host_addr;
	int host_addrlen;
	struct sockaddr_in client_addr;
	int client_addrlen;
};

struct SocketReader {
	int newsockfd;
	int sock_name;
	int valread;
	char buffer[BUFFER_SIZE];
};

struct HttpServer *init_httpserver(int port);
int open_connection(struct HttpServer *server);
int read_socket(struct HttpServer *server, struct SocketReader *sockread);
void close_httpserver(struct HttpServer *server);

#endif
