CC= gcc
CFLAGS= -g -O2 -Wall -Werror
LDFLAGS= -lssl -lcrypto
OBJECTS= main.o

all: filesec

filesec: main.o
	$(CC) -o filesec $(CFLAGS) $(OBJECTS) $(LDFLAGS)

main.o: main.c
	$(CC) -c $(CFLAGS) main.c

tests: clean all run_tests

run_tests:
	./test1.sh
	./test2.sh
	./test3.sh

clean:
	rm -f *.o filesec
