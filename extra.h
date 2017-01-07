
#ifndef _EXTRA_H_
#define _EXTRA_H_

#define FULL_ADDSTRLEN (INET6_ADDRSTRLEN + 8)

#define ADDR_PARSE_SUCCESS 0
#define ADDR_PARSE_INVALID_FORMAT 1
#define ADDR_PARSE_CANNOT_RESOLVE 2
#define ADDR_PARSE_NO_ADDR_FOUND 3


typedef struct sockaddr_storage IP;
typedef struct sockaddr_in6 IP6;
typedef struct sockaddr_in IP4;
typedef unsigned int UINT;
typedef unsigned char UCHAR;


int otr_set_max_message_size(const char protocol_id[], unsigned int max_message_size);

int addr_equal(const IP *addr1, const IP *addr2);

int str_to_af(const char *str);
const char *af_to_str(int af);

int addr_parse(IP *addr, const char *addr_str, const char *port_str, int af);
int addr_parse_full(IP *addr, const char *full_addr_str, const char *default_port, int af);
char *str_addr(const IP *addr);

int net_bind(
	const char name[],
	const char addr[],
	const char port[],
	const char ifce[],
	int protocol, int af
);

#endif /* _EXTRA_H_ */
