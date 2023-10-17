#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

#define FATAL(x) do{ puts(x); exit(1); }while(0)

unsigned char   chrs[] =
    "abcdefghilmnopqrstuvzkjxABCDEFGHILMNOPQRSTUVZKJX1234567890<>;,.:-_^?=)([]!\"£$%&/\\";


void            printstr(unsigned char *str, int len);

int
main(int argc, char **argv)
{
    int             fd,
                    i,
                    len = 0;
    unsigned char   str[64];

    if (argc != 2)
	FATAL("usage: ./pcat pathname");

    if ((fd = open(argv[1], O_RDONLY)) == -1)
	FATAL("open failed");

    while (read(fd, &str[len], 1) == 1) {
	for (i = 0; chrs[i] != 0; i++) {
	    if (str[len] == chrs[i]) {
		len++;
		break;
	    }
	}
	if (len > 0 && (chrs[i] == 0 || len == (sizeof str) - 1)) {
	    printstr(str, len);
	    len = 0;
	}
    }

    close(fd);

    if (len > 0)
	printstr(str, len);
}


void
printstr(unsigned char *str, int len)
{
    int             i,
                    j;

    for (i = 0; i < len; i++)
	for (j = 1; i + j <= len; j++) {
	    write(1, str + i, j);
	    write(1, "\n", 1);
	}

}
