#include "common.h"

//  Wrapper for recv
int recv_all(int sockfd, void *buffer, size_t len) {
    //  Use a buffer to check if all data was received
    size_t bytes_received = 0;
    size_t bytes_remaining = len;
    char *buff = buffer;

    while(bytes_remaining) {
        int bytes = recv(sockfd, buff, bytes_remaining, 0);
        if(bytes < 0) {
            return -1;
        }
        
        bytes_received += bytes;
        bytes_remaining -= bytes;
        buff += bytes;
    }

    return bytes_received;
}

//  Wrapper for send
int send_all(int sockfd, void *buffer, size_t len) {
    //  Use a buffer to check if all data was sent
    size_t bytes_sent = 0;
    size_t bytes_remaining = len;
    char *buff = buffer;

    while(bytes_remaining) {
        int bytes = send(sockfd, buff, bytes_remaining, 0);
        if(bytes < 0) {
            return -1;
        }

        bytes_sent += bytes;
        bytes_remaining -= bytes;
        buff += bytes;
    }

    return bytes_sent;
}

//  Returns a message
struct message *build_message(char *topic, char data_type, char *content) {
    //  Alloc message
    struct message *msg = malloc(sizeof(struct message));
    DIE(!msg, "memory");

    //  Initialize data
    if (topic) {
        strncpy(msg->topic, topic, MAX_TOPIC_LENGTH);
        msg->topic[MAX_TOPIC_LENGTH - 1] = '\0';
    }
    msg->data_type = data_type;
    if (content) {
        strncpy(msg->content, content, MAX_INPUT);
        msg->content[MAX_INPUT - 1] = '\0';
    }

    return msg;
}

//  Builds a tcp message and send it to specified socketfd
int build_and_send(int sockfd, int ip_sender, int port_sender, struct message *msg) {
    //  Prepare tcp message
    struct tcp_message *tcp_msg = malloc(sizeof(struct tcp_message));
    DIE(!tcp_msg, "memory");
    tcp_msg->ip_sender = ip_sender;
    tcp_msg->port_sender = port_sender;
    if (msg) {
        //  Copy fields only if they are not NULL
        if (msg->topic)
            strncpy(tcp_msg->payload.topic, msg->topic, MAX_TOPIC_LENGTH);
        tcp_msg->payload.data_type = msg->data_type;
        if (msg->content)
            strncpy(tcp_msg->payload.content, msg->content, MAX_INPUT);
    }

    //  Send tcp message to subscriber
    int rc = send_all(sockfd, (void *)tcp_msg, sizeof(struct tcp_message));
    DIE(rc < 0, "send_all");

    return rc;
}

char *format_ip(int ip) {
    uint8_t *ip_as_bytes = (uint8_t *)&ip;
	char *ip_as_string = malloc(20);
	snprintf(ip_as_string, 20, "%d.%d.%d.%d", ip_as_bytes[0], ip_as_bytes[1],
        ip_as_bytes[2], ip_as_bytes[3]);
    return ip_as_string;
}

//  Allocate array of topics that each client has
char **allocate_topics() {
    char **topics = (char **)malloc(REALLOC_THRESHOLD * sizeof(char *));
    DIE(!topics, "memory");

    for (int i = 0; i < REALLOC_THRESHOLD; i++) {
        topics[i] = (char *)malloc(MAX_TOPIC_LENGTH * sizeof(char));
        DIE(!topics[i], "memory");
    }

    return topics;
}

//  Reallocate space by adding 100 more topics in matrix
char **reallocate_topics(char **topics, int nr_max_topics) {
    char **rtopics = (char **)realloc(topics, nr_max_topics + REALLOC_THRESHOLD);
    DIE(!rtopics, "memory");

    for (int i = nr_max_topics; i < nr_max_topics + REALLOC_THRESHOLD; i++) {
        rtopics[i] = (char *)malloc(MAX_TOPIC_LENGTH * sizeof(char));
        DIE(!rtopics[i], "memory");
    }

    return rtopics;
}

//  Free topics matrix
void free_topics(char **topics, int nr_max_topics) {
    for (int i = 0; i < nr_max_topics; i++)
        free(topics[i]);
    free(topics);
}