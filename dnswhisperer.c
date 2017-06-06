/*
 *	The code is distributed under terms of the BSD license.
 *	Copyright (c) 2016 Alex Pankratov. All rights reserved.
 *
 *	http://swapped.cc/bsd-license
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <netinet/in.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <unistd.h>

#include "log.h"
#include "dns.h"
#include "nope_list.h"

/*
 *
 */
#define sizeof_array(v) (sizeof(v)/sizeof(v[0]))

typedef struct sockaddr_in sockaddr_in;
typedef struct timeval timeval;

#define LOG_FILE   0x1
#define LOG_SERVER 0x2
static int do_log = 0;

/*
 *
 */
typedef struct app_config
{
	int          listen_port;
	const char * dns_server;
	const char * log_file;
	const char * blacklist;
	int          log_server_port;
	int          daemonize;
	int          filter_ipv6;

} app_config;

typedef struct pending_req
{
	sockaddr_in  addr;
	uint64_t     id_ext; /* doubles as age */
	uint16_t     id_int;
	int          nope_it;

} pending_req;

typedef struct srv_socket
{
	int          sk;
	pending_req  requests[1024];
	size_t       pending;
	uint64_t     next_id_ext;

} srv_socket;

typedef union io_buf
{
	char        raw[64*1024];
	dns_header  hdr;

} io_buf;

/*
 *
 */
void die(const char * format, ...)
{
	va_list m;

	va_start(m, format);
	vprintf(format, m);
	va_end(m);

	exit(1);
}

int unblock(int sk)
{
	int r = fcntl(sk, F_GETFL);
	return (r < 0) ? r : fcntl(sk, F_SETFL, r | O_NONBLOCK);
}

int sa_init(sockaddr_in * sa, const char * addr, uint16_t port)
{
	sa->sin_family = AF_INET;
	sa->sin_addr.s_addr = 0;
	sa->sin_port = htons(port);

	if (addr && ! inet_aton(addr, &sa->sin_addr))
		return -1;

	return 0;
}

/*
 *
 */
int relay_q(int sk_cli, srv_socket * srv, io_buf * buf, nope_list * nl, int filter_ipv6)
{
	sockaddr_in sa_cli = { AF_INET };
	socklen_t sa_len = sizeof sa_cli;
	int r;
	pending_req * req;
	dns_question  q;
	int nope_it;

	for (;;)
	{
		r = recvfrom(sk_cli, buf->raw, sizeof buf->raw, 0, (void*)&sa_cli, &sa_len);
		if (r < 0)
			break;

//		printf("cli > %d bytes\n", r);
		if (r < sizeof(buf->hdr))
		{
			printf("      ? malformed\n");
			continue;
		}

//		dump_dns_packet(&buf->hdr, r);

		if (DNS_GET_QR(&buf->hdr) != 0)
		{
			printf("      ? not a query\n");
			continue;
		}

		nope_it = 0;

		if (DNS_GET_OPCODE(&buf->hdr) == 0 && /* Query, RFC 1035 */
                   buf->hdr.qcount != 0)
		{
			size_t i, n = htons(buf->hdr.qcount);

			for (i=0; i<n; i++)
			{
				if (dns_get_question(&buf->hdr, r, i, &q) < 0)
				{
					printf("      ? malformed Q section\n");
					break;
				}

				if ((nl && match_nope_list(nl, q.name)) ||
						(filter_ipv6 && (q.type == 28))) {
					//printf("nope -- %s - %s ipv6\n", inet_ntoa(sa_cli.sin_addr), q.name);
					nope_it = 1;
					buf->hdr.flags &= htons(~0x000F);
					buf->hdr.flags |= htons( 0x0003);
					buf->hdr.flags |= htons(1 << 15);
					buf->hdr.flags |= htons(1 << 7);
					r = sendto(sk_cli, buf, r, 0, (void*)&sa_cli, sizeof sa_cli);
					if (r < 0) printf("cli < failed with %d\n", errno);
					continue;
				}

				//printf("%s %04lx -- %s\n", nope_it ? "nope --" : "	   ", 0xffff & srv->next_id_ext, q.name);
			}

			if (nope_it) continue;
		}

		if (srv->pending < sizeof_array(srv->requests))
			req = srv->requests + srv->pending++;
		else
			req = srv->requests; /* recycle */

		req->addr    = sa_cli;
		req->id_ext  = srv->next_id_ext++;
		req->id_int  = buf->hdr.id;
		req->nope_it = nope_it;

		buf->hdr.id = (req->id_ext & 0xffff);

		r = send(srv->sk, buf, r, 0);
		if (r < 0)
		{
			printf("srv < failed with %d\n", errno);
			break;
		}

		//printf("%s - %s (%lu)\n", inet_ntoa(sa_cli.sin_addr), q.name, req->id_ext);
	}

	return 0;
}

int relay_r(srv_socket * srv, int sk_cli, io_buf * buf)
{
	size_t i;
	int r;
	pending_req * req;

	for (;;)
	{
		r = recv(srv->sk, buf->raw, sizeof buf->raw, 0);
		if (r <= 0)
			break;

//		printf("srv > %d bytes\n", r);

		if (r < sizeof(buf->hdr))
		{
			printf("      ? malformed\n");
			continue;
		}

		if (DNS_GET_QR(&buf->hdr) != 1)
		{
			printf("      ? %04hx -- not a response\n", buf->hdr.id);
			continue;
		}

		//dump_dns_response(&buf->hdr, r);

		for (i=0, req=srv->requests; i<srv->pending; i++, req++)
			if ( (req->id_ext & 0xffff) == buf->hdr.id )
				break;

		if (i == srv->pending)
		{
			printf("      ? %04hx -- response for unknown query\n", buf->hdr.id);
			continue;
		}

		if (do_log) {
			char str[1024];
			get_dns_req_reply(&buf->hdr, r, str, sizeof(str), &req->addr.sin_addr);
			if (do_log & LOG_SERVER) log_str(str);
			if (do_log & LOG_FILE) printf("%s\n", str);
		}

		buf->hdr.id = req->id_int;

		if (req->nope_it && (DNS_GET_RCODE(&buf->hdr) == 0))
		{
			for (i=0; i<buf->hdr.acount; i++)
			{
				dns_rr a;
				if (dns_get_answer(&buf->hdr, r, i, &a) < 0)
				{
					printf("      ? %04hx -- malformed A.%lu section\n", 
						buf->hdr.id, i);
					goto drop;
				}

				if (a.type != 1)  /* A record */
					continue;

				if (a.len != 4)
				{
					printf("      ? %04hx -- malformed A.%lu section\n", 
						buf->hdr.id, i);
					goto drop;
				}

				*(uint32_t*)a.data = 0;
			}
		}

		//

		r = sendto(sk_cli, buf, r, 0, (void*)&req->addr, sizeof req->addr);
		if (r < 0)
			printf("cli < failed with %d\n", errno);
drop:
		if (i < --srv->pending)
			srv->requests[i] = srv->requests[srv->pending];
	}

	return 0;
}

/*
 *
 */
const char * get_param(int argc, char ** argv, int i, const char * what)
{
	if (i == argc)
		die("Error: %s is missing an argument\n", what);

	return argv[i];
}

void syntax()
{
	printf(
           "Syntax: dnswhisperer [-l <arg>] [-f <arg>] [-s <arg>] [-d]\n"
           "\n"
           "		 -p port  		   -  listen port\n"
           "		 -b port           -  log server port\n"
           "		 -l <file>         -  log to <file>\n"
           "		 -f <file>         -  read blacklist from <file>\n"
           "		 -s <IP4_address>  -  DNS server to use\n"
           "		 -d	               -  daemonize\n"
           "		 -6	               -  filter ipv6 queries\n"
           "		 -h, -?            -  show this message\n"
           "\n"
	);

	exit(1);
}

void parse_args(int argc, char ** argv, app_config * conf)
{
	int i;

	for (i=1; i<argc; i++)
	{
		char * arg = argv[i];
		if (! strcmp(arg, "-s"))
			conf->dns_server = get_param(argc, argv, ++i, "-s");
		else
		if (! strcmp(arg, "-p"))
			conf->listen_port = atoi(get_param(argc, argv, ++i, "-p"));
		else
		if (! strcmp(arg, "-b"))
			conf->log_server_port = atoi(get_param(argc, argv, ++i, "-b"));
		else
		if (! strcmp(arg, "-l"))
			conf->log_file = get_param(argc, argv, ++i, "-l");
		else
		if (! strcmp(arg, "-f"))
			conf->blacklist = get_param(argc, argv, ++i, "-f");
		else
		if (! strcmp(arg, "-d"))
			conf->daemonize = 1;
		else
		if (! strcmp(arg, "-6"))
			conf->filter_ipv6 = 1;
		else
			syntax();
	}
}

void daemonize(int keep_stdout)
{
	pid_t pid;

	fflush(0);
	chdir("/");

	pid = fork();
	if (pid < 0)
		die("fork() failed with %d\n", errno);

	if (pid > 0)
		exit(0);

	if (setsid() < 0)
		die("setsid() failed with %d\n", errno);

	pid = fork();
	if (pid != 0)
		exit(0);

	// stdin
	close(0);
	open("/dev/null", O_RDWR);

	// stderr
	close(2);
	dup(0);

	// stdout
	if (! keep_stdout)
	{
		close(1);
		dup(0);
	}
}

/*
 *
 */
int main(int argc, char ** argv)
{
	app_config  conf =
	{
               5333,                 /* listen port        */
               "208.67.222.222",     /* dns_server         */
               NULL,                 /* log_file -> stdout */
               "dnswhisperer.txt",   /* blacklist          */
               0,                    /* log server port    */
               0,                    /* daemonize          */
               0                     /* filter ipv6        */
	};

	nope_list * nl;
	io_buf      buf = { 0 };
	srv_socket  srv = { 0 }; /* just for one for now */
	int         sk_log = -1;
	int         sk_cli;
	int         sk_max;

	sockaddr_in sa_log = { AF_INET };
	sockaddr_in sa_cli = { AF_INET };
	sockaddr_in sa_srv = { AF_INET };

	//
	parse_args(argc, argv, &conf);

	if (conf.log_file)
	{
		close(1);
		if (open(conf.log_file, O_CREAT | O_APPEND | O_WRONLY, 0644) < 0)
			die("Failed to open %s for writing, error %d\n", conf.log_file, errno);

		setvbuf(stdout, NULL, _IONBF, 0);
		do_log |= LOG_FILE;
	}

	//
	nl = load_nope_list(conf.blacklist, 16*1024*1024);
	if (nl)
		printf("Loaded %lu patterns from %s\n", nl->size, conf.blacklist);

	//
	sk_cli = socket(AF_INET, SOCK_DGRAM, 0);
	if (sk_cli < 0)
		die("socket() failed with %d\n", errno);

	if (unblock(sk_cli) < 0)
		die("unblock() failed with %d\n", errno);

	sa_init(&sa_cli, NULL, conf.listen_port);
	if (bind(sk_cli, (void*)&sa_cli, sizeof sa_cli) < 0)
		die("bind() failed with %d\n", errno);

	//
	srv.sk = socket(AF_INET, SOCK_DGRAM, 0);
	if (srv.sk < 0)
		die("socket() failed with %d\n", errno);

	if (unblock(srv.sk) < 0)
		die("unblock() failed with %d\n", errno);

	sa_init(&sa_srv, conf.dns_server, 53);
	if (connect(srv.sk, (void*)&sa_srv, sizeof sa_srv) < 0)
		die("connect() failed with %d\n", errno);

	printf("Using %s as DNS server\n", conf.dns_server);

	if (conf.log_server_port) {
		int enable = 1;

		log_init(1024*1024);

		do_log |= LOG_SERVER;

		sk_log	= socket(AF_INET, SOCK_STREAM, 0);
		if (sk_log < 0)
			die("socket() failed with %d\n", errno);

		if (unblock(sk_log) < 0)
			die("unblock() failed with %d\n", errno);

		if (setsockopt(sk_log, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
			die("setsockopt(SO_REUSEADDR) failed with %d", errno);

		sa_init(&sa_log, NULL, conf.log_server_port);
		if (bind(sk_log, (void*)&sa_log, sizeof sa_log) < 0)
			die("bind() failed with %d\n", errno);

		if (listen(sk_log, SOMAXCONN) < 0)
			die("listen() failed with %d\n", errno);
	}


	//
	if (conf.daemonize)
	{
		printf("Daemonizing...\n");
		daemonize( conf.log_file != NULL );
	}

	//
	sk_max = (sk_cli < srv.sk) ? srv.sk : sk_cli;
	if (conf.log_server_port) sk_max = (sk_max < sk_log) ? sk_log: sk_max;

	for (;;)
	{
		timeval cycle = { 1, 0 }; /* 1 sec */
		fd_set fdr;
		int r;

		FD_ZERO(&fdr);
		FD_SET(sk_cli, &fdr);
		FD_SET(srv.sk, &fdr);
		if (conf.log_server_port) FD_SET(sk_log, &fdr);

		r = select(sk_max+1, &fdr, NULL, NULL, &cycle);
		if (r < 0 && errno != EINTR)
			die("select() failed with %d\n", errno);

		if (r <= 0)
			continue;

		if (FD_ISSET(sk_cli, &fdr))
			relay_q(sk_cli, &srv, &buf, nl, conf.filter_ipv6);

		if (FD_ISSET(srv.sk, &fdr))
			relay_r(&srv, sk_cli, &buf);

		if (conf.log_server_port && FD_ISSET(sk_log, &fdr)) {
			int log_fd = accept(sk_log, NULL, NULL);
			if (log_fd != -1) {
				log_print(log_fd);
				close(log_fd);
			}
		}
	}

	return 0;
}

