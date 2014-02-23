CC = gcc
CFLAGS = -Wall -Wextra
LFLAGS = -lpthread

.PHONY: clean

all: show_status

show_status.o: show_status.c
	${CC} ${CFLAGS} -c show_status.c

show_status: show_status.o
	${CC} ${CFLAGS} show_status.o -o show_status ${LFLAGS}
	strip show_status

clean:
	rm -f *.o show_status
