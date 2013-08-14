/*
 * $Id: interface.c,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
 */

#include <stdio.h>
#include <version.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <syslog.h>
#include <New.h>
#include <linked_list.h>
#include "interface.h"


extern Interface_Master_Struct *INTERFACES;

int ifinit() {
    struct ifconf ifc;
    /*Interface_Struct ifs;*/
    struct ifreq ifreq, *ifr;
    int s, n;
    char buf[BUFSIZ];
    int lookforinterfaces;
    int	foundloopback;			/* valid flag for loopaddr */
    struct	sockaddr loopaddr;		/* our address on loopback */
    struct	interface *ifnet;

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
       syslog(LOG_ERR, "socket: %m");
       close(s);
       return (-1);
    }

    ifc.ifc_len = sizeof (buf);
    ifc.ifc_buf = buf;
    if (ioctl(s, SIOCGIFCONF, (char *)&ifc) < 0) {
       syslog(LOG_ERR, "ioctl (get interface configuration)");
       close(s);
       return (-1);
    }


    ifr = ifc.ifc_req;
    lookforinterfaces = 0;
    for (n = ifc.ifc_len / sizeof (struct ifreq); n > 0; n--, ifr++) {

       /*bzero((char *)&ifs, sizeof(ifs));
       ifs.int_addr = ifr->ifr_addr;*/
       ifreq = *ifr;
       if (ioctl(s, SIOCGIFFLAGS, (char *)&ifreq) < 0) {
	  syslog(LOG_ERR, "%s: ioctl (get interface flags)",
		 ifr->ifr_name);
	  continue;
       }

       printf ("\nInterface %s 0x%x", ifr->ifr_name, ifreq.ifr_flags);

       if (ifreq.ifr_flags & IFF_LOOPBACK) 
	  printf (" loopback");

       {
	  struct sockaddr_in *addr;

	  addr = (struct sockaddr_in *) &(ifr->ifr_addr);

	  printf (" %s", inet_ntoa (addr->sin_addr));


	  if (ioctl(s, SIOCGIFBRDADDR, (char *)&ifreq) < 0) {
	     syslog(LOG_ERR, "%s: ioctl (get broadaddr)",
		    ifr->ifr_name);
	     continue;
	  }

	  addr = (struct sockaddr_in *) &(ifreq.ifr_broadaddr);

	  printf (" %s*", inet_ntoa (addr->sin_addr));



       }
    }
    
}
