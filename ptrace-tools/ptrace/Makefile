CC=cc
CFLAGS=-Wall

all:
	./scl
	$(CC) $(CFLAGS) scm.c -o scm
	$(CC) $(CFLAGS) idioteque.c -o idioteque
	$(CC) $(CFLAGS) onelove.c -o onelove
	$(CC) $(CFLAGS) sstrip.c -o sstrip
	$(CC) $(CFLAGS) -s -nostartfiles -nostdlib bind.s -o bind
	./sstrip bind
	wc -c bind
clean:
	rm -f scl.h scm idioteque onelove sstrip bind
