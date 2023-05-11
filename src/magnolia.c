#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "magnolia.h"
#include "reader.h"

int main(void)
{
    char buffer[BUFFER_SIZE];

    struct response resp;
    resp.header = "HTTP/1.0 200 OK\r\n"
                  "Server: magnolia\r\n"
                  "Content-type: text/html\r\n\r\n";
    resp.content = malloc(sizeof(char) * BUFFER_SIZE);
    
    char *filename = "../public/index.html";
    if (get_html(filename, &resp) != 0) {
        perror("webserver (parser)");
        return 1;
    }

    // Create a socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("webserver (socket)");
        return 1;
    }
    printf("socket created successfully\n");

    // Create the address to bind the socket to
    struct sockaddr_in host_addr;
    int host_addrlen = sizeof(host_addr);

    host_addr.sin_family = AF_INET;
    host_addr.sin_port = htons(PORT);
    host_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    // Create client address
    struct sockaddr_in client_addr;
    int client_addrlen = sizeof(client_addrlen);

    // Bind the socket to the address
    if (bind(sockfd, (struct sockaddr *)&host_addr, host_addrlen) != 0) {
        perror("webserver (bind)");
        return 1;
    }
    printf("socket successfully bound to address\n");

    // Listen for incoming connections
    if (listen(sockfd, SOMAXCONN) != 0) {
        perror("webserver (listen)");
        return 1; 
    }
    printf("server listening for connections\n");

    for (;;) {
        // Accept incoming connections
        int newsockfd = accept(sockfd, (struct sockaddr *)&host_addr, (socklen_t *)&host_addrlen);
        if (newsockfd < 0) {
            perror("webserver (accept)");
            continue;
        }
        printf("connection accepted\n");

        // Get client address
        int sockn = getsockname(newsockfd, (struct sockaddr *)&client_addr, (socklen_t *)&client_addrlen);
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

        // Read the request
        char method[BUFFER_SIZE], uri[BUFFER_SIZE], version[BUFFER_SIZE];
        sscanf(buffer, "%s %s %s", method, uri, version);
        printf("[%s:%u] %s %s %s\n", inet_ntoa(client_addr.sin_addr), 
                ntohs(client_addr.sin_port), method, version, uri);

        // Format response
        int head_len = strlen(resp.header);
        int cont_len = strlen(resp.content);

        char *combine_resp = malloc(head_len + cont_len + 1);
        if (combine_resp) {
            memcpy(combine_resp, resp.header, head_len);
            memcpy(combine_resp + head_len, resp.content, cont_len + 1);
        }

        // Write to the socket
        int valwrite = write(newsockfd, combine_resp, strlen(combine_resp));
        if (valwrite < 0) {
            perror("webserver (write)");
            continue;
        }

        free(combine_resp);
        close(newsockfd);
    }

    free(resp.content);

    return 0;
}
