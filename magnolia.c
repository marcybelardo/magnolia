/*
 *
 *  magnolia
 *  a little http server
 *
 */
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <signal.h>

static const char PKG_NAME[] = "magnolia v 0.0.1";

#define MAX_EVENTS 16
#define MAX_CONNS 64

static int SOCKFD = -1;
static char *PORT = "8888";
static char *ROOT_DIR = NULL;
static const char *INDEX_NAME = "index.html";
static int run_daemon = 0;

void sigchld_handler(int s)
{
    // waitpid() might overwrite errno, so we save and restore it:
    int saved_errno = errno;

    while (waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}

struct m_conn {
    int socket;
    enum {
        RECV_REQ,
        SEND_HEAD,
        SEND_RESP,
        DONE
    } state;
    char *req;
    size_t req_len;
    char *method;
    char *uri;
    char *header;
    size_t header_len;
    char *resp;
    size_t resp_len;
};

struct m_conn *m_init_conn(int fd)
{
    struct m_conn *new_conn = malloc(sizeof(struct m_conn));
    new_conn->socket = fd;
    new_conn->req = malloc(sizeof(char) * 1024);
    new_conn->req_len = 0;
    new_conn->method = malloc(sizeof(char) * 8);
    new_conn->uri = malloc(sizeof(char) * 128);
    new_conn->header = malloc(sizeof(char) * 512);
    new_conn->header_len = 0;
    new_conn->resp = malloc(sizeof(char) * 1024);
    new_conn->resp_len = 0;
    new_conn->state = RECV_REQ;

    return new_conn;
}

typedef struct {
    const char *ext;
    const char *type;
} mime_map;

mime_map MIME_TYPES [] = {
    {".css", "text/css"},
    {".gif", "image/gif"},
    {".htm", "text/html"},
    {".html", "text/html"},
    {".jpeg", "image/jpeg"},
    {".jpg", "image/jpeg"},
    {".ico", "image/x-icon"},
    {".js", "application/javascript"},
    {".pdf", "application/pdf"},
    {".mp4", "video/mp4"},
    {".png", "image/png"},
    {".svg", "image/svg+xml"},
    {".xml", "text/xml"},
    {NULL, NULL},
};

char *DEFAULT_MIME_TYPE = "text/plain";

void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in *)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

void m_init_socket()
{
    struct addrinfo hints, *ai, *p;
    int yes = 1;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((rv = getaddrinfo(NULL, PORT, &hints, &ai)) != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        exit(EXIT_FAILURE);
    }

    for (p = ai; p != NULL; p = p->ai_next) {
        SOCKFD = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (SOCKFD < 0) {
            continue;
        }

        setsockopt(SOCKFD, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

        if (bind(SOCKFD, p->ai_addr, p->ai_addrlen) == -1) {
            close(SOCKFD);
            perror("[MAGNOLIA] bind");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "[MAGNOLIA] failed to bind\n");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(ai);

    if (listen(SOCKFD, MAX_EVENTS) == -1) {
        perror("[MAGNOLIA] listen");
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on port %s...\n", PORT);
    return;
}

static const char *get_mime_type(char *filename)
{
    char *p = strrchr(filename, '.');

    if (p) {
        mime_map *map = MIME_TYPES;
        while (map->ext) {
            if (strcmp(map->ext, p) == 0) {
                return map->type;
            }
            map++;
        }
    }

    return DEFAULT_MIME_TYPE;
}

void m_send_head(struct m_conn *conn)
{
    size_t sent;

    assert(conn->state == SEND_HEAD);
    assert(conn->header_len == strlen(conn->header));

    sent = send(conn->socket, conn->header, conn->header_len, 0);
    if (sent < 1) {
        if (sent == -1) {
            fprintf(stderr, "[ERROR] send header %d, %s\n",
                    conn->socket, strerror(errno));
        }
        conn->state = DONE;
        return;
    }

    assert(sent > 0);

    free(conn->header);
    conn->header = NULL;
}

void m_send_resp(struct m_conn *conn)
{
    size_t sent;

    assert(conn->state == SEND_RESP);
    sent = send(conn->socket, conn->resp, conn->resp_len, 0);
    if (sent < 1) {
        if (sent == -1) {
            fprintf(stderr, "[ERROR] send resp %d: %s\n",
                    conn->socket, strerror(errno));
        }
        conn->state = DONE;
        return;
    }

    conn->state = DONE;

    free(conn->resp);
    free(conn->method);
    free(conn->uri);
    conn->resp = NULL;
    conn->method = NULL;
    conn->uri = NULL;
}

void m_reply(struct m_conn *conn, int code, const char *msg)
{
    conn->header_len = snprintf(conn->header, 512,
            "HTTP/1.1 %d %s\r\n"
            "Server: magnolia\r\n"
            "Content-Length: %lu\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "\r\n",
            code, msg, conn->resp_len);

    conn->resp_len = snprintf(conn->resp, 1024,
            "<!DOCTYPE html><head><title>%d %s</title></head><body>\n"
            "<h1>%d %s</h1>\n"
            "<hr>\n"
            "</body></html>\n",
            code, msg, code, msg); 

    conn->state = SEND_HEAD;
    m_send_head(conn);
    conn->state = SEND_RESP;
    m_send_resp(conn);
}

void m_get(struct m_conn *conn)
{
    m_reply(conn, 404, "Not Found");
}

void m_parse_req(struct m_conn *conn)
{
    char *p;

    assert(conn->req_len == strlen(conn->req));

    // method
    for (p = conn->req; *p != ' '; p++);
    *p++ = '\0';
    conn->method = conn->req;
    conn->req = p;

    // uri
    for (; *p != ' '; p++);
    *p++ = '\0';
    conn->uri = conn->req;
    conn->req = p;

    // get pointer to headers
    for (; (*p != ' ') &&
            (*(p + 1) != '\r') &&
            (*(p + 2) != '\n');
            p++);
    p += 3;
    conn->req = p;

    return;
}

void m_process_req(struct m_conn *conn)
{
    m_parse_req(conn);

    printf("[conn %d] Method: %s URI: %s\n",
            conn->socket, conn->method, conn->uri);

    if (strcmp(conn->method, "GET") == 0) {
        m_get(conn);
    } else {
        m_reply(conn, 501, "Not Implemented");
    }

    conn->state = SEND_HEAD;
    free(conn->req);
    conn->req = NULL;
}

void m_recv_req(struct m_conn *conn)
{
    printf("[MAGNOLIA] m_recv_req starting\n");

    char buf[1024];
    size_t recvd;

    assert(conn->state == RECV_REQ);
    recvd = recv(conn->socket, buf, sizeof buf, 0);
    if (recvd < 1) {
        if (recvd == -1) {
            fprintf(stderr, "[ERROR] recv %d: %s\n",
                    conn->socket, strerror(errno));
        }
        conn->state = DONE;
        return;
    }

    assert(recvd > 0);
    conn->req = realloc(conn->req, conn->req_len + recvd + 1);
    memcpy(conn->req + conn->req_len, buf, recvd);
    conn->req_len += recvd;
    conn->req[conn->req_len] = '\0';

    printf("[conn %d] Received request:\n", conn->socket);
    printf("%s\n", conn->req);

    m_process_req(conn);
}

void m_http_process()
{
    int newfd;
    struct sockaddr_storage client_addr;
    socklen_t addrlen;
    char clientIP[INET6_ADDRSTRLEN];

    if (SOCKFD == -1) {
        fprintf(stderr, "[ERROR] couldn't get listening socket\n");
        exit(EXIT_FAILURE);
    }

    for (;;) {
        addrlen = sizeof client_addr;
        newfd = accept(SOCKFD, (struct sockaddr *)&client_addr, &addrlen);
        if (newfd == -1) {
            perror("[MAGNOLIA] accept");
            continue;
        }

        printf("[MAGNOLIA] new connection from %s on "
                "socket %d\n",
                inet_ntop(client_addr.ss_family,
                    get_in_addr((struct sockaddr *)&client_addr),
                    clientIP, INET6_ADDRSTRLEN),
                newfd);

        if (!fork()) {
            close(SOCKFD);
            struct m_conn *newconn = m_init_conn(newfd);
            m_recv_req(newconn);
            close(newfd);
            free(newconn);
        }

        close(newfd);
    }
}

static void usage(const char *argv0)
{
    printf("%s\n", PKG_NAME);
    printf("a little HTTP server\n\n");
    printf("USAGE:\t%s <site root>\n\n", argv0);
    printf("Flags:\t--port <number> (default: %s)\n", PORT);
    printf("\t\tPort to listen on for connections.\n");
}

static int fd_null = -1;

static void m_daemon_start()
{
    pid_t f;

    fd_null = open("/dev/null", O_RDWR, 0);
    if (fd_null == -1) {
        fprintf(stderr, "[ERROR] m_daemon_start fd_null open\n");
        exit(errno);
    }

    if ((f = fork()) == -1) {
        fprintf(stderr, "[ERROR] m_daemon_start fork\n");
        exit(errno);
    } else if (f != 0) {
        pid_t w;
        int status;

        if ((w = waitpid(f, &status, WNOHANG)) == -1) {
            fprintf(stderr, "[ERROR] m_daemon_start waitpid\n");
            exit(errno);
        } else if (w == 0) {
            exit(EXIT_SUCCESS);
        } else {
            exit(WEXITSTATUS(status));
        }
    }
}

void m_daemon_finish()
{
    if (fd_null == -1)
        return;

    if (setsid() == -1)
        fprintf(stderr, "[ERROR] m_daemon_finish setsid\n");

    if (dup2(fd_null, STDIN_FILENO) == -1)
        fprintf(stderr, "[WARN] m_daemon_finish dup2 stdin");
    if (dup2(fd_null, STDOUT_FILENO) == -1)
        fprintf(stderr, "[WARN] m_daemon_finish dup2 stdout");
    if (dup2(fd_null, STDERR_FILENO) == -1)
        fprintf(stderr, "[WARN] m_daemon_finish dup2 stderr");

    if (fd_null > 2)
        close(fd_null);
}

void parse_commands(const int argc, char *argv[])
{
    int i;
    size_t len;

    if ((argc < 2) || (argc == 2 && strcmp(argv[1], "--help") == 0)) {
        usage(argv[0]);
        exit(EXIT_SUCCESS);
    }

    ROOT_DIR = strdup(argv[1]);
    len = strlen(ROOT_DIR);
    if (len == 0) {
        fprintf(stderr, "Root directory cannot be empty\n");
        exit(EXIT_FAILURE);
    }
    if (len > 1) {
        if (ROOT_DIR[len - 1] == '/')
            ROOT_DIR[len - 1] = '\0';
    }

    for (i = 2; i < argc; i++) {
        if ((strcmp(argv[i], "--port") == 0) ||
                (strcmp(argv[i], "-p") == 0)) {
            if (++i >= argc) {
                fprintf(stderr, "Please supply a port number\n");
                exit(EXIT_FAILURE);
            }
            PORT = argv[i];
        }

        if ((strcmp(argv[i], "--daemon") == 0) ||
                (strcmp(argv[i], "-d") == 0)) {
            run_daemon = 1;
        }
    }
}

int main(int argc, char *argv[])
{
    struct sigaction sa;
    parse_commands(argc, argv);
    m_init_socket();

    if (run_daemon)
        m_daemon_start();

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        return 1;
    }

    if (run_daemon)
        m_daemon_finish();

    for (;;)
        m_http_process();

    close(SOCKFD);

    return 0;
}
