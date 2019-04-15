#include "../include/imbw-int.h"


void
imbw_bf_setkey(imbw_bf_session_struct * session, unsigned char *userkey,
	       size_t len)
{
    int             i;

    if (!userkey)
	userkey = "userkey";	/* uh, default passphrase! ;) */

    for (i = 0; i < 2; ++i) {
	memset(session->feedback[i].ivec, '\0', 8);
	session->feedback[i].num = 0;
    }

    BF_set_key(&session->key, len, userkey);
}


IMBW_G_INLINE_FUNC void
imbw_bf(void *buf, size_t len, imbw_bf_session_struct * session, int enc)
{
    int             i;

    i = enc == BF_ENCRYPT ? 0 : 1;

    if (len == 0)
	return;

    BF_cfb64_encrypt(buf, buf, len, &session->key,
		     session->feedback[i].ivec, &session->feedback[i].num,
		     enc);
}
