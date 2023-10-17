# iotrace project Makefile.

include VERSION

# the diet path (used only with 'make tiny-linux') 
DIET = diet
CC        = gcc
# set the following to increase debugging messages
CFLAGS    = -DVER=\"$(VERSION).\" #-DDEBUG
DEST      = iotrace

all: help

help:
	@echo "%"
	@echo "%  I/O-TRACE PACK v$(VERSION) Makefile"
	@echo "%"
	@echo "%  USAGE: make TARGET"
	@echo "%"
	@echo "%  recognized targets:"
	@echo "%"
	@echo "%   linux"
	@echo "%   tiny-linux"
	@echo "%   osf1_v40"
	@echo "%   osf1_v5x"
	@echo "%   openbsd"
	@echo "%   freebsd"
	@echo "%"
	@echo "%  other things.."
	@echo "%"
	@echo "%   idioteque -- simple I/O logger for linux"
	@echo "%   pcat -- breaks a logfile into possible passwords"
	@echo "%"
	@echo "% ** the README is not optional **"
	@echo "%"

linux: clean
	$(CC) $(CFLAGS) iotrace-Linux.c -o $(DEST)

tiny-linux: clean
	$(DIET) $(CC) -static $(CFLAGS) iotrace-Linux.c -o $(DEST)
	$(CC) $(CFLAGS) elftrunc.c -o elftrunc
	./elftrunc ./$(DEST)
	@mv ./$(DEST).trunc ./$(DEST)
	@echo packing it with upx..
	@upx ./$(DEST) 2> /dev/null || echo upx not found. 

# on OSF1 V4.0 an OS-supplied snprintf can be found in libdb,
# on 5.x it's in libc..

osf1_v40: clean 
	$(CC) $(CFLAGS) -lrt -ldb iotrace-OSF1.c -o $(DEST) 

osf1_v5x: clean
	$(CC) $(CFLAGS) -lrt iotrace-OSF1.c -o $(DEST)

openbsd: clean
	$(CC) $(CFLAGS) -lm -lkvm -DOPENBSD iotrace-OpenFreeBSD.c -o $(DEST) 

freebsd: clean
	$(CC) $(CFLAGS) -lm -lkvm -DFREEBSD iotrace-OpenFreeBSD.c -o $(DEST)

clean:
	rm -rf $(DEST) idioteque elftrunc pcat *.c~ $(DEST)-$(VERSION).tgz

indent:
	indent -orig *.c

srcpack: clean
	cd .. && tar cvzf $(DEST)-$(VERSION).tgz $(DEST) && mv $(DEST)-$(VERSION).tgz ./$(DEST)/
	@echo
	@ls -la $(DEST)-$(VERSION).tgz
	@echo

idioteque: 
	 $(CC) $(CFLAGS) idioteque.c -o idioteque
pcat:
	$(CC) $(CFLAGS) pcat.c -o pcat
