#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "log.h"
#include "host.h"

char *
host_getaddr(char *hostname)
{
	struct addrinfo *res, hints;
	char *s = hostname, addr_str[INET6_ADDRSTRLEN + 6];
	void *addr;
	int r, port_included = 0;

	while (*s && *s != ':')
		++s;
	if (*s == ':')
		port_included = 1;
	*s = '\0';

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	r = getaddrinfo(hostname, NULL, &hints, &res);
	if (r != 0) {
		log_info("getaddrinfo: %s", gai_strerror(r));
		return (NULL);
	}
	switch (res->ai_family) {
	case AF_INET:
		addr = &((struct sockaddr_in *)res->ai_addr)->sin_addr;
		break;
	case AF_INET6:
		addr = &((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
		break;
	default:
		log_info("getaddr: unsupported family: %d", res->ai_family);
		freeaddrinfo(res);
		return (NULL);
	}
	inet_ntop(res->ai_family, addr, addr_str, sizeof(addr_str));
	freeaddrinfo(res);

	if (port_included) {
		strcat(addr_str, ":");
		strcat(addr_str, s + 1);
	}
	return (strdup(addr_str));
}
