CC = gcc
CFLAGS = -Wall -Werror -lm

build: server subscriber

server: server.o common.o
	$(CC) server.o common.o -o server $(CFLAGS)

subscriber: subscriber.o common.o
	$(CC) subscriber.o common.o  -o subscriber $(CFLAGS)

subscriber.o: subscriber.c
	$(CC) -c subscriber.c -o subscriber.o $(CFLAGS)

server.o: server.c
	$(CC) -c server.c -o server.o $(CFLAGS)

common.o: common.c
	$(CC) -c common.c -o common.o $(CFLAGS)

clean:
	rm -f server subscriber common.o server.o subscriber.o