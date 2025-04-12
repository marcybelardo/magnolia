CFLAGS = -Wall -O2

all: magnolia

magnolia: magnolia.c
	$(CC) $(CFLAGS) -o magnolia magnolia.c

clean:
	rm magnolia
