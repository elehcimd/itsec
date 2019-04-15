#include "../include/imbw-int.h"

IMBW_G_INLINE_FUNC u_int16_t
imbw_rand()
{
    u_int16_t       i = 0;
    int             fd;

    fd = open(RANDOM_FILE, O_RDONLY);
    if (fd < 0) {
	srand(time(NULL));
	return rand();
    }

    read(fd, &i, sizeof(u_int16_t));

    close(fd);

    return i;

}
