/*
 *
 * $Id: ech.c,v 3.0 2002/03/28 18:03:34 xenion Exp $
 *
 * ---------------------------------------------------------------------------
 * No part of this project may be used to break the law, or to cause damage of
 * any kind. And I'm not responsible for anything you do with it.
 * ---------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (by Poul-Henning Kamp, Revision 42):
 * <xenion@acidlife.com> wrote this file.  As long as you retain this notice
 * you can do whatever you want with this stuff. If we meet some day, and you
 * think this stuff is worth it, you can buy me a beer in return.
 * xenion ~ Dallachiesa Michele
 * ---------------------------------------------------------------------------
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/stat.h>

#define BUFLEN 1024
#define ECHOLEN  100
#define VERSION "3.0"

void            fatal(char *, ...);
off_t           filelen(char *);
void            update_status(off_t, off_t);
void            echize(char *, char *, int);


int
main(int argc, char **argv)
{
    FILE           *f_in,
                   *f_out;
    unsigned char   buf[BUFLEN];
    int             file_len,
                    len,
                    i,
                    count;

    if (argc < 3) {
	printf("Echize your life v%s\n", VERSION);
	printf("usage: ech <inputfile> <outputfile>\n\n");
	exit(1);
    }

    f_in = fopen(argv[1], "r");
    if (f_in == NULL)
	fatal("unable to open %s", argv[1]);
    f_out = fopen(argv[2], "w");
    if (f_out == NULL)
	fatal("unable to open %s", argv[2]);

    file_len = filelen(argv[1]);
    count = 0;

    while (!feof(f_in)) {
	len = fread(buf, 1, ECHOLEN, f_in);
	count += len;
	fprintf(f_out, "echo -ne \"");
	for (i = 0; i < len; i++)
	    fprintf(f_out, "\\%o", buf[i]);
	fprintf(f_out, "\" >> %s%c", argv[1], '\n');
	update_status(count, file_len);
    }

    fclose(f_in);
    fclose(f_out);

    printf("\ndone.\n");

    return 0;

}


off_t
filelen(char *pathname)
{

    struct stat     buf;

    if (stat(pathname, &buf) == -1)
	fatal("stat()");

    return buf.st_size;

}


void
update_status(off_t now, off_t end)
{
    printf("\rStatus: [%ld/%ld] %ld%%", now, end, now * 100 / end);
    fflush(stdout);
}


void
fatal(char *pattern, ...)
{

    va_list         ap;
    va_start(ap, pattern);

    vfprintf(stderr, pattern, ap);
    fprintf(stderr, "; exit forced.\n");

    va_end(ap);

    exit(-1);

}

// EOF
