#ifndef HTTPSERVER_H
#define HTTPSERVER_H

#include <arpa/inet.h>

struct HttpServer {
	int sockfd;
	struct sockaddr_in host_addr;
	int host_addrlen;
	struct sockaddr_in client_addr;
	int client_addrlen;
};

struct HttpServer *init_httpserver(int port);
int open_connection(struct HttpServer *server);

#endif
