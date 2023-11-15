CC=g++
CFLAGS=-I.

client: client.cpp buffer.cpp buffer.hpp json.hpp
	$(CC) -o client client.cpp buffer.cpp buffer.hpp json.hpp -Wall

run: client
	./client

clean:
	rm -f *.o client
