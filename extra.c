
#include <assert.h>
#include <sys/time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include "util.h" // for purple_home_dir()

#include "extra.h"


int str_to_af(const char *str)
{
	if(strcmp(str, "ipv4") == 0) {
		return AF_INET;
	} else if(strcmp(str, "ipv6") == 0) {
		return AF_INET6;
	} else {
		return -1;
	}
}

const char *af_to_str(int af)
{
	if(af == AF_INET) {
		return "ipv4";
	} else if(af == AF_INET6) {
		return "ipv6";
	} else {
		return "";
	}
}

/* Compare two ip addresses */
int addr_equal(const IP *addr1, const IP *addr2)
{
	if(addr1->ss_family != addr2->ss_family) {
		return 0;
	} else if(addr1->ss_family == AF_INET) {
		const IP4 *a1 = (IP4 *)addr1;
		const IP4 *a2 = (IP4 *)addr2;
		return (memcmp(&a1->sin_addr, &a2->sin_addr, 4) == 0) && (a1->sin_port == a2->sin_port);
	} else if(addr1->ss_family == AF_INET6) {
		const IP6 *a1 = (IP6 *)addr1;
		const IP6 *a2 = (IP6 *)addr2;
		return (memcmp(&a1->sin6_addr, &a2->sin6_addr, 16) == 0) && (a1->sin6_port == a2->sin6_port);
	} else {
		return 0;
	}
}

/*
* Resolve an IP address.
* The port must be specified separately.
*/
int addr_parse(IP *addr, const char *addr_str, const char *port_str, int af)
{
	struct addrinfo hints;
	struct addrinfo *info = NULL;
	struct addrinfo *p = NULL;

	memset(&hints, '\0', sizeof(struct addrinfo));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = af;

	if(getaddrinfo(addr_str, port_str, &hints, &info) != 0) {
		return ADDR_PARSE_CANNOT_RESOLVE;
	}

	p = info;
	while(p != NULL) {
		if(p->ai_family == AF_INET6) {
			memcpy(addr, p->ai_addr, sizeof(IP6));
			freeaddrinfo(info);
			return ADDR_PARSE_SUCCESS;
		}
		if(p->ai_family == AF_INET) {
			memcpy(addr, p->ai_addr, sizeof(IP4));
			freeaddrinfo(info);
			return ADDR_PARSE_SUCCESS;
		}
	}

	freeaddrinfo(info);
	return ADDR_PARSE_NO_ADDR_FOUND;
}

/*
* Parse various string representations of
* IPv4/IPv6 addresses and optional port.
* An address can also be a domain name.
* A port can also be a service  (e.g. 'www').
*
* "<address>"
* "<ipv4_address>:<port>"
* "[<address>]"
* "[<address>]:<port>"
*/
int addr_parse_full(IP *addr, const char *full_addr_str, const char *default_port, int af)
{
	char addr_buf[256];

	char *addr_beg, *addr_tmp;
	char *last_colon;
	const char *addr_str = NULL;
	const char *port_str = NULL;
	int len;

	len = strlen(full_addr_str);
	if(len >= (sizeof(addr_buf) - 1)) {
		/* address too long */
		return ADDR_PARSE_INVALID_FORMAT;
	} else {
		addr_beg = addr_buf;
	}

	memset(addr_buf, '\0', sizeof(addr_buf));
	memcpy(addr_buf, full_addr_str, len);

	last_colon = strrchr(addr_buf, ':');

	if(addr_beg[0] == '[') {
		/* [<addr>] or [<addr>]:<port> */
		addr_tmp = strrchr(addr_beg, ']');

		if(addr_tmp == NULL) {
			/* broken format */
			return ADDR_PARSE_INVALID_FORMAT;
		}

		*addr_tmp = '\0';
		addr_str = addr_beg + 1;

		if(*(addr_tmp+1) == '\0') {
			port_str = default_port;
		} else if(*(addr_tmp+1) == ':') {
			port_str = addr_tmp + 2;
		} else {
			/* port expected */
			return ADDR_PARSE_INVALID_FORMAT;
		}
	} else if(last_colon && last_colon == strchr(addr_buf, ':')) {
		/* <non-ipv6-addr>:<port> */
		addr_tmp = last_colon;
		if(addr_tmp) {
			*addr_tmp = '\0';
			addr_str = addr_buf;
			port_str = addr_tmp+1;
		} else {
			addr_str = addr_buf;
			port_str = default_port;
		}
	} else {
		/* <addr> */
		addr_str = addr_buf;
		port_str = default_port;
	}

	return addr_parse(addr, addr_str, port_str, af);
}

char *str_addr(const IP *addr, char *addrbuf)
{
	char buf[INET6_ADDRSTRLEN+1];
	unsigned short port;

	switch(addr->ss_family) {
	case AF_INET6:
		port = ntohs(((IP6 *)addr)->sin6_port);
		inet_ntop(AF_INET6, &((IP6 *)addr)->sin6_addr, buf, sizeof(buf));
		sprintf(addrbuf, "[%s]:%hu", buf, port);
		break;
	case AF_INET:
		port = ntohs(((IP4 *)addr)->sin_port);
		inet_ntop(AF_INET, &((IP4 *)addr)->sin_addr, buf, sizeof(buf));
		sprintf(addrbuf, "%s:%hu", buf, port);
		break;
	default:
		sprintf(addrbuf, "<invalid address>");
	}

	return addrbuf;
}

int net_set_nonblocking(int fd)
{
	int rc;
	int nonblocking = 1;

	rc = fcntl(fd, F_GETFL, 0);
	if(rc < 0)
		return -1;

	rc = fcntl(fd, F_SETFL, nonblocking?(rc | O_NONBLOCK):(rc & ~O_NONBLOCK));
	if(rc < 0)
		return -1;

	return 0;
}

int net_bind(
	const char *name,
	const char *addr,
	const char *port,
	const char *ifce,
	int protocol, int af
)
{
	char addrbuf[FULL_ADDSTRLEN+1];
	int sock;
	int val;
	IP sockaddr;

	if(af != AF_INET && af != AF_INET6) {
		fprintf(stderr, "plainprpl: Unknown address family value.");
		return -1;
	}

	if(addr_parse(&sockaddr, addr, port, af) != 0) {
		fprintf(stderr, "plainprpl: Failed to parse ip address '%s' and port '%s'.", addr, port);
		return -1;
	}

	if(protocol == IPPROTO_TCP) {
		sock = socket(sockaddr.ss_family, SOCK_STREAM, IPPROTO_TCP);
	} else if(protocol == IPPROTO_UDP) {
		sock = socket(sockaddr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	} else {
		sock = -1;
	}

	if(sock < 0) {
		fprintf(stderr, "plainprpl: Failed to create socket: %s", strerror(errno));
		return -1;
	}

	val = 1;
	if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
		fprintf(stderr, "plainprpl: Failed to set socket option SO_REUSEADDR: %s", strerror(errno));
		return -1;
	}

	if(ifce && setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, ifce, strlen(ifce))) {
		fprintf(stderr, "plainprpl: Unable to bind to device '%s': %s", ifce, strerror(errno));
		return -1;
	}

	if(af == AF_INET6) {
		val = 1;
		if(setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val)) < 0) {
			fprintf(stderr, "plainprpl: Failed to set socket option IPV6_V6ONLY: %s", strerror(errno));
			return -1;
		}
	}

	if(bind(sock, (struct sockaddr *) &sockaddr, sizeof(IP)) < 0) {
		fprintf(stderr, "plainprpl: Failed to bind socket to address: '%s'", strerror(errno));
		close(sock);
		return -1;
	}

	if(net_set_nonblocking(sock) < 0) {
		fprintf(stderr, "plainprpl: Failed to make socket nonblocking: '%s'", strerror(errno));
		return -1;
	}

	if(protocol == IPPROTO_TCP && listen(sock, 5) < 0) {
		fprintf(stderr, "plainprpl: Failed to listen on socket: '%s'", strerror(errno));
		return -1;
	}

	return sock;
}

int otr_line_exists( const char *path, const char line[] ) {
	char linebuf[60];
	int found;
	FILE *fp;

	fp = fopen( path, "r" );
	if( fp == NULL ) {
		return 0;
	}

	/* Search for line */
	found = 0;
	while( fgets( linebuf, sizeof(linebuf), fp ) != NULL ) {
		if(strcmp(linebuf, line) == 0) {
			found = 1;
		}
	}

	fclose( fp );
	return found;
}

int otr_line_append(const char *path, const char line[] ) {
	FILE *fp;

	fp = fopen( path, "a+" );
	if( fp == NULL ) {
		return 0;
	}

	fprintf( fp, "\n%s", line );
	fclose( fp );

	return 1;
}

int path_exists(const char* path) {
	struct stat st;
	return (stat( path, &st) == 0);
}

/*
* Workaround to tell the OTR plugin our maximum message size.
* There is not other way for current libpurple 2.x.
*
* Tries to set $HOME/.libpurple/otr.max_message_size if the
* libpurple folder exists.
*/
int otr_set_max_message_size( const char protocol_id[], unsigned int max_message_size ) {
	char path[512];
	char line[40];
	const char *home_path;

	/* The OTR setting that is needed */
	sprintf( line, "%s\t%u\n", protocol_id, max_message_size);

	home_path = purple_home_dir(); //advised instead of getenv( "HOME" );
	if( snprintf(path, sizeof(path), "%s/.purple/", home_path) >= sizeof(path) ) {
		/* path too long - error */
		return 1;
	}

	if( !path_exists(path)) {
		/* purple configuration folder not found - nothing to do */
		return 0;
	}

	if( snprintf(path, sizeof(path), "%s/.purple/otr.max_message_size", home_path) >= sizeof(path) ) {
		/* path too long - error */
		return 1;
	}

	if( otr_line_exists(path, line) ) {
		/* Line exists - nothing to do */
		return 0;
	}

	if( otr_line_append(path, line) ) {
		/* Line added */
		return 0;
	} else {
		/* Could not append line - error */
		return 1;
	}
}
