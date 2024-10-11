#include "common.h"

int is_subscriber(char *recv, char *cli) {
    //  Iterate through both topics to check if they match
    int a = 0, b = 0, ok = 1;
    while (cli[a] != '\0' && recv[b] != '\0') {
        if (cli[a] == '+') {
            //  Wildcard +
            //  Get to start of word
            a += 2;

            //  Skip a word and get to start of next one
            while (recv[b] != '/' && recv[b] != '\0')
                b++;
            b++;

            //  Case where + is last word
            if (recv[b] == '\0' && cli[a] == '\0')
                break;
        } else if (cli[a] == '*') {
            //  Wildcard *
            //  Get to start of word
            a += 2;

            //  Remember position a
            int ca = a;

            //  While received topic has not finished
            while (recv[b] != '\0') {
                //  If two letters do not match, find the begging of
                //  the next word and start over
                if (cli[a] != recv[b]) {
                    while (recv[b] != '/' && recv[b] != '\0')
                        b++;
                    b++;
                    a = ca;
                } else {
                    a++;
                    b++;
                }

                //  If both letters are / a full word has matched
                if (cli[a] == '/' && recv[b] == '/')
                    break;
            }

            //  Case where * is last word
            if (recv[b] == '\0' && cli[a] == '\0')
                break;
        }

        //  If two letters do not match go to next topic
        if (cli[a] != recv[b]) {
            ok = 0;
            break;
        }

        //  Increment
        b++;
        a++;
    }
    if (ok == 1 && cli[a] == '\0' && recv[b] == '\0')
        return 1;
    else
        return 0;
}

void decode_message(char *payload, struct message_for_udp *msg) {
    //  Check what type of message it is
    switch(msg->data_type) {
        case 0:
            //  Extract 4 bytes value
            uint32_t num0 = ntohl(*(uint32_t *)((uint8_t *)msg->content + 1));
            if (msg->content[0] == 1)
                num0 *= -1;
            
            //  Write final value in payload
            sprintf(payload, "%d", num0);
            break;
        case 1:
            //  Extract 2 bytes value
            uint16_t num1 = ntohs(*(uint16_t *)msg->content);
            double fnum1 = num1 / 100.0;

            //  Write final value in payload
            sprintf(payload, "%.2f", fnum1);
            break;
        case 2:
            //  Extract first 4 bytes
            double num2 = ntohl(*(uint32_t *)((uint8_t *)msg->content + 1));
            if (msg->content[0] == 1)
                num2 *= -1;

            //  Extract absolute value of power of 10
            uint8_t val = *(uint8_t *)((uint8_t *)msg->content + 5);
            double multiplier = pow(10, val);

            //  Write final value in payload
            sprintf(payload, "%lf", num2 / multiplier);
            break;
        case 3:
            //  Copy the string message
            strncpy(payload, msg->content, MAX_INPUT - 1);
            break;
    }
}

void run_server(int tcpfd, int udpfd) {
    //  Remember file descriptors
    struct pollfd *file_descriptors = malloc(REALLOC_THRESHOLD * sizeof(struct pollfd));
    DIE(!file_descriptors, "memory");

    //  Array of clients
    struct client *clients = malloc(REALLOC_THRESHOLD * sizeof(struct client));
    DIE(!clients, "memory");
    int nr_clients = 0;
    int nr_max_clients = REALLOC_THRESHOLD;

    //  Put stdin file descriptor in struct pollfd
    file_descriptors[0].fd = STDINFD;
    file_descriptors[0].events = POLLIN;

    //  Put TCP socket file descriptor in struct pollfd
    file_descriptors[1].fd = tcpfd;
    file_descriptors[1].events = POLLIN;

    //  Put UDP socket file descriptor in struct pollfd
    file_descriptors[2].fd = udpfd;
    file_descriptors[2].events = POLLIN;

    //  Listen on tcp socket
    int rc = listen(tcpfd, MAX_CONNECTIONS);
    DIE(rc < 0, "listen");

    //  Current number of file descriptors in struct pollfd
    int nr_fd = 3;
    int nr_max_fd = REALLOC_THRESHOLD;

    //  Flag to check if server wants to close
    int hasClosed = 0;

    //  Server loop
    while (!hasClosed) {
        //  Listen for changes
        rc = poll(file_descriptors, nr_fd, -1);
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

                    if (str[strlen(str)-1] == '\n')
                        str[strlen(str)-1] = '\0';

                    //  Check if it is exit
                    if (strncmp(str, "exit", 5) == 0) {
                        //  Server is closing, exit loop
                        hasClosed = 1;

                        //  Close clients that are on
                        for (int j = 0; j < nr_clients; j++)
                            if (clients[j].isOn == 1) {
                                //  Client is off
                                clients[j].isOn = 0;

                                //  Build and send a message to client
                                //  in order to close it
                                rc = build_and_send(clients[j].socket_fd, 0, 0, (void *)NULL);
                                DIE(rc < 0, "build_and_send");

                                //  Close socket
                                close(clients[j].socket_fd);
                            }
                    }

                    free(str);
                } else if (file_descriptors[i].fd == tcpfd) {
                    //  Only when a client wants to connect or reconnect
                    char *client_id = malloc(IP_LENGTH * sizeof(char));
                    DIE(!client_id, "memory");

                    //  Initialize sockaddr_in structure
                    struct sockaddr_in serv_addr;
                    socklen_t socket_len = sizeof(struct sockaddr_in);
                    memset(&serv_addr, 0, socket_len);

                    //  Accept the connection
                    int fd = accept(tcpfd, (struct sockaddr *)&serv_addr, &socket_len);
                    DIE(fd < 0, "accept");

                    //  Get client's id
                    rc = recv_all(fd, (void *)client_id, IP_LENGTH);
                    DIE(rc < 0, "recv_all");

                    //  Check if client with this id already exists
                    int exists = 0;

                    for (int j = 0; j < nr_clients; j++)
                        if (strncmp(clients[j].id, client_id, IP_LENGTH) == 0) {
                            //  Client exists
                            exists = 1;
                            if (clients[j].isOn == 1) {
                                //  Client with id is already connected
                                //  Print message
                                printf("Client %s already connected.\n", clients[j].id);

                                //  Send message to signal the client that it needs to close
                                build_and_send(fd, 0, 0, (void *)NULL);
                            } else if (clients[j].isOn == 0) {
                                //  Print message
                                uint8_t *ip_as_bytes = (uint8_t *)&serv_addr.sin_addr.s_addr;
                                printf("New client %s connected from %d.%d.%d.%d:%d\n",
                                    client_id, ip_as_bytes[0], ip_as_bytes[1],
                                    ip_as_bytes[2], ip_as_bytes[3], serv_addr.sin_port);

                                //  Client wants to reconnect
                                clients[j].isOn = 1;
                                clients[j].socket_fd = fd;

                                //  Check if there is enough space in poll for a new fd
                                if (nr_fd + 1 == nr_max_fd) {
                                    struct pollfd *aux = realloc(file_descriptors, nr_max_fd + REALLOC_THRESHOLD);
                                    DIE(!aux, "memory");
                                    file_descriptors = aux;
                                    nr_max_fd += REALLOC_THRESHOLD;
                                }

                                //  Add its socket fd to poll
                                file_descriptors[nr_fd].fd = fd;
                                file_descriptors[nr_fd].events = POLLIN;
                                //  Increment number of file descriptors;
                                nr_fd++;
                            }
                        }

                    //  New client wants to connect
                    if (!exists) {
                        //  Print message
                        uint8_t *ip_as_bytes = (uint8_t *)&serv_addr.sin_addr.s_addr;
                        printf("New client %s connected from %d.%d.%d.%d:%d\n",
                            client_id, ip_as_bytes[0], ip_as_bytes[1],
                            ip_as_bytes[2], ip_as_bytes[3], serv_addr.sin_port);

                        //  Check if there is enough space for one mare client in array
                        if (nr_clients + 1 == nr_max_clients) {
                            struct client *aux = realloc(clients, nr_max_clients + REALLOC_THRESHOLD);
                            DIE(!aux, "memory");
                            clients = aux;
                            nr_max_clients += REALLOC_THRESHOLD;
                        }

                        //  Check if there is enough space in poll for a new fd
                        if (nr_fd + 1 == nr_max_fd) {
                            struct pollfd *aux = realloc(file_descriptors, nr_max_fd + REALLOC_THRESHOLD);
                            DIE(!aux, "memory");
                            file_descriptors = aux;
                            nr_max_fd += REALLOC_THRESHOLD;
                        }

                        //  Initialize new client
                        struct client cli;
                        cli.socket_fd = fd;
                        strncpy(cli.id, client_id, IP_LENGTH);
                        cli.nr_topics = 0;
                        cli.isOn = 1;

                        //  Allocate topics
                        cli.topics = allocate_topics();
                        cli.nr_max_topics = REALLOC_THRESHOLD;

                        //  Add a new client in clients array
                        clients[nr_clients] = cli;
                        //  Increment number of clients
                        nr_clients++;

                        //  Add client's socket_fd in poll
                        file_descriptors[nr_fd].fd = fd;
                        file_descriptors[nr_fd].events = POLLIN;
                        //  Increment number of file descriptors;
                        nr_fd++;
                    }

                    free(client_id);
                } else if (file_descriptors[i].fd == udpfd) {
                    //  Receive message from udp client
                    //  Declare message
                    struct message_for_udp *msg = malloc(sizeof(struct message_for_udp));
                    DIE(!msg, "memory");

                    //  Initialize sockaddr structure
                    struct sockaddr_in serv_addr;
                    socklen_t socket_len = sizeof(struct sockaddr_in);
                    memset(&serv_addr, 0, socket_len);

                    //  Receive message
                    rc = recvfrom(udpfd, (void *)msg, sizeof(struct message_for_udp), 0,
                        (struct sockaddr *)&serv_addr, &socket_len);
                    DIE(rc < 0, "recvfrom");

                    //  Write message in payloadbased on data type
                    char payload[MAX_INPUT];
                    decode_message(payload, msg);

                    //  Iterate through all clients and send the message
                    //  if the client is a subscriber of this topic
                    for (int i = 0; i < nr_clients; i++)
                        //  Iterate through client's topics
                        for (int j = 0; j < clients[i].nr_topics; j++)
                            //  Check if the client is a subscriber of the topic
                            if (is_subscriber(msg->topic, clients[i].topics[j])
                                && clients[i].isOn == 1) {
                                //  Build message and send it to the client
                                struct message *msg_to_send = build_message(msg->topic, msg->data_type, payload);
                                rc = build_and_send(clients[i].socket_fd,
                                    serv_addr.sin_addr.s_addr, serv_addr.sin_port, msg_to_send);
                                DIE(rc < 0, "build_and_send");

                                free(msg_to_send);
                                break;
                            }

                    free(msg);
                } else {
                    //  Get corresponding client
                    int j;
                    for (j = 0; j < nr_clients; j++)
                        if (file_descriptors[i].fd == clients[j].socket_fd)
                            break;

                    //  Declare tcp message
                    struct tcp_message *tcp_msg = malloc(sizeof(struct tcp_message));
                    DIE(!tcp_msg, "memory");

                    //  Get tcp message
                    rc = recv_all(clients[j].socket_fd, (void *)tcp_msg, sizeof(struct tcp_message));
                    DIE(rc < 0, "recv_all");

                    //  Check what the client wants
                    if (tcp_msg->ip_sender == 0 && tcp_msg->port_sender == 0) {
                        //  The client wants to disconnect
                        clients[j].isOn = 0;
                        //  Close client's socket
                        close(clients[j].socket_fd);

                        //  Delete client's socket fd from poll
                        for (int k = i; k < nr_fd; k++)
                            file_descriptors[k] = file_descriptors[k + 1];
                        nr_fd--;

                        printf("Client %s disconnected.\n", clients[j].id);
                    } else if (tcp_msg->ip_sender == 1 && tcp_msg->port_sender == 0) {
                        //  Client wants to subscribe to a topic

                        //  If array of topics does not have enough space
                        if (clients[j].nr_topics + 1 == clients[j].nr_max_topics) {
                            //  Realloc array with more space
                            clients[j].topics = reallocate_topics(clients[j].topics, clients[j].nr_max_topics);
                            clients[j].nr_max_topics += REALLOC_THRESHOLD;
                        }

                        //  Extract topic and add it to client's topics list
                        struct message msg = tcp_msg->payload;
                        strncpy(clients[j].topics[clients[j].nr_topics], msg.topic, MAX_TOPIC_LENGTH);
                        clients[j].nr_topics++;

                    } else if (tcp_msg->ip_sender == 0 && tcp_msg->port_sender == 1) {
                        //  Client wants to unsubscribe from a topic
                        //  Delete topic from client's topics list
                        struct message msg = tcp_msg->payload;

                        //  Search for topic
                        for (int k = 0; k < clients[j].nr_topics; k++)
                            if (strncmp(msg.topic, clients[j].topics[k], MAX_TOPIC_LENGTH) == 0) {
                                //  Delete topic
                                for (int t = k; t < clients[j].nr_topics - 1; t++)
                                    strncpy(clients[j].topics[t], clients[j].topics[t + 1],
                                            MAX_TOPIC_LENGTH);

                                //  Decrement number of topics
                                clients[j].nr_topics--;
                                break;
                            }
                    }

                    free(tcp_msg);
                }
            }
    }

    //  Free used memory
    for (int i = 0; i < nr_max_clients; i++)
        free_topics(clients[i].topics, clients[i].nr_max_topics);
    free(clients);
    free(file_descriptors);
}

int create_socket(char type, int port) {
    int fd = 0;

    //  Create tcp or udp socket
    if (type == 't')
        fd = socket(AF_INET, SOCK_STREAM, 0);
    else if (type == 'u')
        fd = socket(AF_INET, SOCK_DGRAM, 0);
    DIE(fd < 0, "socket");

    //  Declare struct that retains server's address, family of addresses
    //  and port for connection
    struct sockaddr_in serv_addr;
    socklen_t socket_len = sizeof(struct sockaddr_in);

    //  Make socket's address be reusable, so there will not be an error in case
    //  we compile more times rapidly
    int enable = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
        perror("setsockopt(SO_REUSEADDR) failed");

    //  Set data
    memset(&serv_addr, 0, socket_len);
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    //  Bind tcp socket
    int rc = bind(fd, (const struct sockaddr *)&serv_addr, sizeof(serv_addr));
    DIE(rc < 0, "bind");

    return fd;
}

int main(int argc, char *argv[]) {
    //  Stop buffering
    setvbuf(stdout, NULL, _IONBF, BUFSIZ);

    //  Get the port the server starts on
    //  and parse it as a number
    int port = atoi(argv[1]);

    //  Get a TCP socket for receiving connections
    int tcpfd = create_socket('t', port);

    //  Deactivate Nagle
    int one = 1;
    DIE(setsockopt(tcpfd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)) < 0, "Failed setsockopt\n");

    //  Udp socket
    int udpfd = create_socket('u', port);

    //  Run the server
    run_server(tcpfd, udpfd);

    //  Close connection and created socket
    close(tcpfd);
    close(udpfd);

    return 0;
}
