#ifndef MAGNOLIA
#define MAGNOLIA

#define PORT 8080
#define BUFFER_SIZE 8192

struct connection {
	int sockfd;
	struct sockaddr_in *host_addr;
	struct sockaddr_in *client_addr;
	int host_addrlen;
	int client_addrlen;
};

struct response {
	char *header;
	char *content;
};

#endif
