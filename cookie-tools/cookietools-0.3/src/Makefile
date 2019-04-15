# src Makefile.

include ../VERSION

CC       = cc
CFLAGS   = -Wall -O3  # debug: put -ggdb instead of -O3
LIBS     = -lpcap -lnet -lnids 
DEFS     = 

all: header
	$(CC) -c -DVERSION=\"$(VERSION)\" $(CFLAGS) $(DEFS) main.c
	$(CC) -c $(CFLAGS) $(DEFS) common.c
	$(CC) -c $(CFLAGS) $(DEFS) net.c
	$(CC) $(LIBS) main.o common.o net.o -o cookiesniffer 
	@echo "%"

header:
	@echo "%"
	@echo "%  Compiling cookiesniffer of cookietools v$(VERSION)"
	@echo "%"
	@echo "%  CC...................: $(CC)"
	@echo "%  CFLAGS...............: $(CFLAGS)"
	@echo "%  LIBS.................: $(LIBS)"
	@echo "%  DEFS.................: $(DEFS)"
	@echo "%"

indent:
	astyle --convert-tabs --style=gnu *.[hc]

clean:
	@rm -f cookiesniffer *.[hc].orig *.o

