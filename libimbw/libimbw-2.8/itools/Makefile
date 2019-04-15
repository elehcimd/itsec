SOURCES= ipipe.c ishell.c inc.c
LIBIMBW= ../libimbw

DESTS= $(SOURCES:.c=)
CC= cc #-static

CFLAGS   = `${LIBIMBW}/libimbw-config --cflags`
DEFS     = `${LIBIMBW}/libimbw-config --defines`
COPTS    = -I${LIBIMBW} 
LIBS= ${LIBIMBW}/imbw.a `${LIBIMBW}/libimbw-config --libs`

ALLOPT   = $(CFLAGS) $(COPTS) $(DEFS)

.c:
	$(CC) $(ALLOPT) $< $(LIBS) -o $@
	strip $@
	@indent -orig $<

all: clean itools

itools: $(DESTS)
	@rm -f *c~ 
	du -h $(DESTS)

clean:
	@rm -f core *.c~ $(DESTS) *.log *.pid

