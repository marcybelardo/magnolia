#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../include/magnolia.h"
#include "../include/serve.h"
#include "../include/network.h"

int main(void)
{
    char buffer[BUFFER_SIZE];

    struct response resp;
    resp.header = "HTTP/1.1 200 OK\r\n"
                  "Server: magnolia\r\n"
                  "Content-type: text/html\r\n\r\n";
    resp.content = malloc(sizeof(char) * BUFFER_SIZE);
    
    char *filename = "../public/index.html";
    if (get_file(filename, &resp) != 0) {
        perror("webserver (read_file)");
        return 1;
    }

    struct connection conn;
    conn.host_addrlen = sizeof(struct sockaddr_in);
    conn.client_addrlen = sizeof(struct sockaddr_in);
    conn.host_addr = malloc(conn.host_addrlen);
    conn.client_addr = malloc(conn.client_addrlen);

    if (open_conn(&conn) != 0) {
        perror("Connection could not be established\n");
        return 1;
    }

    for (;;) {
        // Accept incoming connections
        int newsockfd = accept(conn.sockfd, (struct sockaddr *)conn.host_addr, (socklen_t *)&conn.host_addrlen);
        if (newsockfd < 0) {
            perror("webserver (accept)");
            continue;
        }
        printf("connection accepted\n");

        // Get client address
        int sockn = getsockname(newsockfd, (struct sockaddr *)conn.client_addr, (socklen_t *)&conn.client_addrlen);
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
        printf("[%s:%u] %s %s %s\n", inet_ntoa(conn.client_addr->sin_addr), 
                ntohs(conn.client_addr->sin_port), method, version, uri);

        // Format response
        size_t head_len = strlen(resp.header);
        size_t cont_len = strlen(resp.content);

        char *combine_resp = malloc(head_len + cont_len + 1);
        if (combine_resp) {
            memcpy(combine_resp, resp.header, head_len);
            memcpy(combine_resp + head_len, resp.content, cont_len + 1);
        }

        // Write to the socket
        int valwrite = write(newsockfd, combine_resp, head_len + cont_len + 1);
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
