# -- icopy Makefile --
 
SOURCES= icopy.c

DESTS= $(SOURCES:.c=)
CC= cc # -static

CFLAGS   = $$(libnet-config --cflags)
DEFS     = $$(libnet-config --defines)
LIBS     = $$(libnet-config --libs) -lpcap

ALLOPT   = $(CFLAGS) $(DEFS)

.c:
	$(CC) $(ALLOPT) $< $(LIBS) -o $@
	strip $@
	@indent -orig $<

all: clean $(DESTS)
	@rm -f *c~ 
	du -h $(DESTS)

clean:
	@rm -f core *.c~ $(DESTS) 

