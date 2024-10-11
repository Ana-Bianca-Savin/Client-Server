#include <stddef.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <math.h>

#define IP_LENGTH 11
#define STDINFD 0
#define MAX_INPUT 1501
#define MAX_TOPIC_LENGTH 51
#define REALLOC_THRESHOLD 100
#define MAX_CONNECTIONS 32

//  Message used for holding data
//  Defined with specified sizes + 1 to account for null terminating character
struct message {
    char topic[MAX_TOPIC_LENGTH];
    char data_type;
    char content[MAX_INPUT];
};

//  Message received from udp clients by server
//  It contains the specified sizes
struct message_for_udp {
    char topic[MAX_TOPIC_LENGTH - 1];
    char data_type;
    char content[MAX_INPUT - 1];
};

//  Message used for communication between server and clients
struct tcp_message {
    int ip_sender;
    int port_sender;
    struct message payload;
};

//  Holds information about a client
struct client {
    int socket_fd;
    char id[12];
    char **topics;
    int nr_topics;
    int nr_max_topics;
    int isOn;
};

//  Function headers
int send_all(int sockfd, void *buff, size_t len);
int recv_all(int sockfd, void *buff, size_t len);
struct message *build_message(char *topic, char data_type, char *content);
int build_and_send(int sockfd, int ip_sender, int port_sender, struct message *msg);
char **allocate_topics();
char **reallocate_topics(char **topics, int nr_max_topics);
void free_topics(char **topics, int nr_max_topics);

//  Macro for error checking
#define DIE(assertion, call_description)                                       \
  do {                                                                         \
    if (assertion) {                                                           \
      fprintf(stderr, "(%s, %d): ", __FILE__, __LINE__);                       \
      perror(call_description);                                                \
      exit(EXIT_FAILURE);                                                      \
    }                                                                          \
  } while (0)
