#include "common.h"

//  Print message received from a topic that the client is subscribed to
void print_message(struct tcp_message *tcp_msg) {
    //  Extract payload and print general information
    struct message msg = tcp_msg->payload;
    uint8_t *ip_as_bytes = (uint8_t *)&tcp_msg->ip_sender;
    printf("%d.%d.%d.%d:%d - %s - ", ip_as_bytes[0], ip_as_bytes[1],
        ip_as_bytes[2], ip_as_bytes[3], tcp_msg->port_sender, msg.topic);

    //  Print type of content
    switch (msg.data_type) {
        case 0:
            printf("INT");
            break;
        case 1:
            printf("SHORT_REAL");
            break;
        case 2:
            printf("FLOAT");
            break;
        case 3:
            printf("STRING");
            break;
    }

    //  Print content
    printf(" - %s\n", msg.content);
}

void run_client(int tcpfd) {
    //  Remember file descriptors
    struct pollfd *file_descriptors = malloc(REALLOC_THRESHOLD * sizeof(struct pollfd));
    DIE(!file_descriptors, "memory");

    //  Put stdin file descriptor in struct pollfd
    file_descriptors[0].fd = STDINFD;
    file_descriptors[0].events = POLLIN;

    //  Put TCP socket file descriptor in struct pollfd
    file_descriptors[1].fd = tcpfd;
    file_descriptors[1].events = POLLIN;

    //  Current number of file descriptors in struct pollfd
    int nr_fd = 2;

    //  Flag to check if client wants to close
    int hasClosed = 0;

    //  Client loop
    while (!hasClosed) {
        //  Wait for changes
        int rc = poll(file_descriptors, nr_fd, -1);
        DIE(rc < 0, "poll");

        //  Find where the change was made
        for (int i = 0; i < nr_fd; i++)
            if (file_descriptors[i].revents & POLLIN) {
                //  File descriptor found
                if (file_descriptors[i].fd == STDINFD) {
                    //  If a message was received by standard input
                    char *str = malloc(MAX_INPUT * sizeof(char));
                    char *res = fgets(str, MAX_INPUT, stdin);
                    DIE(!res, "fgets");

                    //  Replace new line character
                    if (str[strlen(str)-1] == '\n')
                        str[strlen(str)-1] = '\0';

                    //  Check what the client wants
                    if (strncmp(str, "exit", 5) == 0) {
                        //  Close client
                        hasClosed = 1;

                        //  Send message to server about closing
                        rc = build_and_send(tcpfd, 0, 0, (void *)NULL);
                        DIE(rc < 0, "build_and_send");
                    } else if (strncmp(str, "subscribe", 9) == 0) {
                        //  Read desired topic from stdin
                        char topic[MAX_TOPIC_LENGTH];
                        strncpy(topic, str + 10, strlen(str) - 9);
                        //  Padding with terminating character
                        for (int j = strlen(str) - 9; j < MAX_TOPIC_LENGTH; j++)
                            topic[j] = '\0';

                        //  Build message and send it to server
                        struct message *msg = build_message(topic, 4, NULL);
                        rc = build_and_send(tcpfd, 1, 0, msg);
                        DIE(rc < 0, "build_and_send");

                        //  Print confirmation message
                        printf("Subscribed to topic %s\n", topic);
                        free(msg);
                    } else if (strncmp(str, "unsubscribe", 11) == 0) {
                        //  Read desired topic from stdin
                        char topic[MAX_TOPIC_LENGTH];
                        strncpy(topic, str + 12, strlen(str) - 11);
                        //  Padding with terminating character
                        for (int j = strlen(str) - 11; j < MAX_TOPIC_LENGTH; j++)
                            topic[j] = '\0';

                        //  Build message and send it to server
                        struct message *msg = build_message(topic, 4, NULL);
                        rc = build_and_send(tcpfd, 0, 1, msg);
                        DIE(rc < 0, "build_and_send");

                        //  Print confirmation message
                        printf("Unsubscribed to topic %s\n", topic);
                        free(msg);
                    }

                    free(str);
                } else if (file_descriptors[i].fd == tcpfd) {
                    //  If a message was received from the server

                    //  Declare tcp message
                    struct tcp_message *tcp_msg = malloc(sizeof(struct tcp_message));
                    DIE(!tcp_msg, "memory");

                    //  Get tcp message
                    rc = recv_all(tcpfd, (void *)tcp_msg, sizeof(struct tcp_message));
                    DIE(rc < 0, "recv_all");

                    //  Check what the server wants
                    if (tcp_msg->ip_sender == 0 && tcp_msg->port_sender == 0) {
                        //  The server is closing, close client
                        hasClosed = 1;
                    } else {
                        //  Print message from topic
                        print_message(tcp_msg);
                    }

                    free(tcp_msg);
                }
            }
    }

    free(file_descriptors);
}

int main(int argc, char *argv[]) {
    //  Stop buffering
    setvbuf(stdout, NULL, _IONBF, BUFSIZ);

    //  Get client's id, ip address and server port
    char id[IP_LENGTH], ip[IP_LENGTH];
    strncpy(id, argv[1], IP_LENGTH);
    id[IP_LENGTH] = '\0';
    strncpy(ip, argv[2], IP_LENGTH);
    int port = atoi(argv[3]);

    //  Get a TCP socket for connecting to the server
    int tcpfd = socket(AF_INET, SOCK_STREAM, 0);
    DIE(tcpfd < 0, "socket");

    //  Deactivate Nagle
    int one = 1;
    DIE(setsockopt(tcpfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0, "Failed setsockopt\n");

    //  Declare struct that retains server's address, family of addresses
    //  and port for connection
    struct sockaddr_in serv_addr;
    socklen_t socket_len = sizeof(struct sockaddr_in);

    //  Set data
    memset(&serv_addr, 0, socket_len);
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    int rc = inet_pton(AF_INET, ip, &serv_addr.sin_addr.s_addr);
    DIE(rc <= 0, "inet_pton");

    //  Connect to server
    rc = connect(tcpfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    DIE(rc < 0, "connect");

    //  Send client's id to server
    rc = send_all(tcpfd, (void *)id, IP_LENGTH);
    DIE(rc < 0, "send_all");

    //  Run client
    run_client(tcpfd);

    //  Close connection and created socket
    close(tcpfd);

    return 0;
}
