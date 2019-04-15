/*
 *
 * $Id: scm.c,v 9 2002/09/20 6:09:00 xenion Exp $
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

/*
 * occorre generare scl.h con scl 
 */

#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <linux/user.h>
#include <signal.h>
#include "scl.h"


#define VER "0.2"

#define ERR(x) { fprintf(stderr,"## %s:%d: ",__FILE__,__LINE__);\
                 perror(x); exit(1); }

#define LOG(arg...) { fprintf(stderr, "## ");\
                      fprintf(stderr,## arg); fflush(stderr); }

#define PRINT_REGS(x) { fprintf(stderr,"## eax: %8lx (orig_eax: %lx)\n",\
                        ##x.eax,##x.orig_eax);\
                        fprintf(stderr,"## ebx: %8lx\n## ecx: %8lx\n",\
                        ##x.ebx, ##x.ecx);\
                        fprintf(stderr,"## edx: %8lx\n", ##x.edx); }


int
main(int argc, char **argv)
{
    int             pid,
                    status,
                    mode,
                    i;
    char          **_argv,
                   *tmp;
    struct user_regs_struct data;

    if (argc < 2) {
	printf("SysCallMonitor v%s running here\n\n", VER);
	printf("USAGE: %s argv[0] argv[1] ..argv[N]\n\n", argv[0]);
	exit(0);
    }

    _argv = argv + 1;

    switch (pid = fork()) {
    case -1:
	ERR("fork()");
	break;

    case 0:			/* figlio */

	/*
	 * Per prima cosa facciamo un PTRACE_TRACEME: Il padre avra' quindi
	 * il pieno controllo sul figlio
	 */
	if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
	    ERR("ptrace(PTRACE_TRACME, ...)");

	/*
	 * Rendiamo le cose interessanti..
	 */
	if (execvp(*_argv, _argv) < 0) {
	    kill(getppid(), SIGTERM);
	    ERR("");
	}
	break;

    default:			/* padre */

	/*
	 * Ora il padre aspetta che il figlio si fermi alla prossima
	 * istruzione (execvp) 
	 */
	wait(&status);

	LOG("Running.. (parent:%d child:%d)\n", getpid(), pid);

	/*
	 * Nel seguente loop infinito continuiamo a rilasciare e fermare
	 * il figlio. Se mode==1 siamo al primo stop, altrimenti al
	 * secondo. Appena viene chiamata una syscall, il figlio viene
	 * fermato ed il controllo passa al padre: possiamo vedere i
	 * parametri.. al secondo stop invece e' disponibile il return
	 * value :) 
	 */
	for (mode = 1;; mode == 2 ? mode = 1 : ++mode) {

	    /*
	     * Sblocchiamo il figlio e facciamo in modo che si
	     * rifermi appena una nuova syscall verra' chiamata (oppure che
	     * quella corrente termini se mode==1).
	     */
	    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0)
		ERR("ptrace(PTRACE_SYSCALL, ...) failed");

	    /*
	     * aspettiamo.. 
	     */
	    wait(&status);

	    /*
	     * I segnali mandati al figlio vengono ricevuti dal padre che
	     * deve farsi carico di rimandarli al figlio (se diversi da 
	     * SIGTRAP)
	     */
	    if (WSTOPSIG(status) != SIGTRAP) {
		LOG("Sending signal %d\n", WSTOPSIG(status));
		ptrace(PTRACE_SYSCALL, pid, 0, WSTOPSIG(status));
	    }

	    if (mode == 1) {
		/*
		 * Siamo al primo stop, vediamo quale syscall e' stata
		 * chiamata.. 
		 */

		/*
		 * Richiediamo lo stato dei registri del figlio che
		 * verranno caricati in una struttura puntata da &data (di 
		 * tipo user_regs_struct)
		 */
		if (ptrace(PTRACE_GETREGS, pid, &data, &data) < 0)
		    ERR("ptrace(PTRACE_GETREGS, ...");
		/*
		 * in data.orig_eax troviamo il numero della syscall 
		 */
		tmp = "unknown";
		for (i = 0; SYSCALL_LIST[i].number > 0; ++i)
		    if (SYSCALL_LIST[i].number == data.orig_eax)
			tmp = SYSCALL_LIST[i].name;
		LOG("SYSCALL: %s\n", tmp);
		PRINT_REGS(data);
	    }
	}
    }
    return 0;
}

/*
 * EOF 
 */
