<div align="center">

## A Simple but effective port scanner


</div>

### Description

This port scanner is pretty simple, it just fork()'s each connect() call, and reads the return value.
 
### More Info
 


<span>             |<span>
---                |---
**Submitted On**   |
**By**             |[zer0python](https://github.com/Planet-Source-Code/PSCIndex/blob/master/ByAuthor/zer0python.md)
**Level**          |Intermediate
**User Rating**    |3.7 (11 globes from 3 users)
**Compatibility**  |C, UNIX C\+\+
**Category**       |[Security](https://github.com/Planet-Source-Code/PSCIndex/blob/master/ByCategory/security__3-14.md)
**World**          |[C / C\+\+](https://github.com/Planet-Source-Code/PSCIndex/blob/master/ByWorld/c-c.md)
**Archive File**   |[](https://github.com/Planet-Source-Code/zer0python-a-simple-but-effective-port-scanner__3-9664/archive/master.zip)





### Source Code

```
/* simple connect port scanner.. -- very fast .. very detectable... */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/poll.h>
static int verbose = 0;
enum port_e {
	P_ERROR = 0,
	P_CLOSED = 1,
	P_OPEN = 2,
};
enum port_e chkport(struct sockaddr_in addr);
//int v_printf(const char *fmt, ...);	/* verbose printf */
#define v_printf(x)	if(verbose) printf x
int main(int argc, char *argv[])
{
	int index = 1, i;
	struct sockaddr_in addr;
	struct hostent *hp;
	if(argc < 2) {
		fprintf(stderr, "Usage:\n\t%s [-v] <host>\n", argv[0]);
		return 0;
	}
	if((argv[1][0] == '-') && argv[1][1] == 'v')
		verbose = index++;
	if(index != 1 && argc == 2) {
		fprintf(stderr, "missing host\n");
		return 0;
	}
	hp = gethostbyname(argv[index]);
	if(!hp) {
		fprintf(stderr, "could not lookup host\n");
		return 0;
	}
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = PF_INET;
	memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);
	printf("Scanning Host %s\n", argv[index]);
	clock_t st = clock();
	for(i = 1; i <= 65535; i++) {
		addr.sin_port = htons(i);
		if(!fork()) {
			enum port_e p = chkport(addr);
			switch(p) {
				case P_OPEN: printf("%-4d OPEN\n", i); break;
				case P_CLOSED: if(verbose) printf("%-4d CLOSED\n", i); break;
				case P_ERROR: if(verbose) printf("%-4d ERROR\n", i); break;
			}
			exit(0);
		}
	}
	printf("Done in %.2lf seconds.\n", (float) (clock() - st) / CLOCKS_PER_SEC);
	return 0;
}
enum port_e chkport(struct sockaddr_in addr)
{
	int sd = socket(PF_INET, SOCK_STREAM, 0);
	enum port_e prtst = P_OPEN;
	if(sd < 0)
		return P_ERROR;
/*
	if(fcntl(sd, F_SETFL, O_NONBLOCK) < 0) {
		close(sd);
		return P_ERROR;
	}
*/
	if(connect(sd, (struct sockaddr*) &addr, sizeof(addr)))
		return P_CLOSED;
	shutdown(sd, 2);
	close(sd);
	return prtst;
}
```

