/*
 * $Id: sunos.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <mrt.h>
#include <interface.h>
#include <sys/ioctl.h>
#include <net/route.h>


interface_t *ifstatus (char *name);

int read_interfaces () {
  struct ifconf ifc;
  struct ifreq *ifptr, *end;
  int s;
  char *name;
  interface_t *interface;

  char buffer[MAX_INTERFACES * sizeof(struct ifreq)];

  if ((s = INTERFACE_MASTER->sockfd) < 0)
	return;
  ifc.ifc_len = sizeof (buffer);
  ifc.ifc_buf = buffer;

  if (ioctl(s, SIOCGIFCONF, (char *)&ifc) < 0) {
    trace (ERROR, INTERFACE_MASTER->trace, 
      "SIOCGIFCONF (%s)\n", strerror (errno));
    return (-1);
  }

  end = (struct ifreq *) (ifc.ifc_buf + ifc.ifc_len);
  ifptr = ifc.ifc_req;

  while (ifptr < end) {
    name = ifptr->ifr_name;
    ifptr++;
    interface = ifstatus (name);
    if (interface == NULL) continue;
    ifstatus_v4 (interface, name);
  }
  return (1);
}


/* get interface configuration */
interface_t *ifstatus (char *name) {
  struct ifreq ifr;
  int s;
  u_long flags, mtu;
  char *cp;
  interface_t *interface;

  if ((s = INTERFACE_MASTER->sockfd) < 0)
    return (NULL);

  safestrncpy (ifr.ifr_name, name, sizeof (ifr.ifr_name));

  if ((cp = strrchr (ifr.ifr_name, ':')))
    *cp = '\0'; /* Remove the :n extension from the name */

  if ((interface = find_interface_byname (ifr.ifr_name)))
    return (interface);

  if (ioctl(s, SIOCGIFFLAGS, (caddr_t)&ifr) < 0) {
    trace (ERROR, INTERFACE_MASTER->trace, 
	"SIOCGIFFLAGS for %s (%s)\n", name, strerror (errno));
    return (NULL);
  }
  assert ((sizeof (ifr.ifr_flags) == 2)); 
  flags = ifr.ifr_flags&0x0000ffff; /* short */

#define ifr_mtu ifr_metric
  if (ioctl(s, SIOCGIFMTU, (caddr_t)&ifr) < 0) {
    trace (ERROR, INTERFACE_MASTER->trace, 
	"SIOCSIFMTU for %s (%s)\n", name, strerror (errno));
    ifr.ifr_mtu = 576; /* don't care */
  }
  mtu = ifr.ifr_mtu;

  interface = new_interface (name, flags, mtu, 0);
  return (interface);
}


/* get interface configuration for IPv4 */
int ifstatus_v4 (interface_t *interface, char *name) {
  struct ifreq ifr;
  struct sockaddr_in addr, mask, dest;
  int s;
  u_long flags;
  char *cp;

  if ((s = INTERFACE_MASTER->sockfd) < 0)
    return (-1);

  memcpy (ifr.ifr_name, name, sizeof (ifr.ifr_name));
  flags = interface->flags;

  if (ioctl(s, SIOCGIFADDR, (caddr_t)&ifr) < 0) {
    trace (ERROR, INTERFACE_MASTER->trace, 
	"SIOCGIFADDR for %s (%s)\n", name, strerror (errno));
    return (-1);
  }
  memcpy (&addr, &ifr.ifr_addr, sizeof (addr));

  if (addr.sin_family != AF_INET || addr.sin_addr.s_addr == INADDR_ANY) {
#if 0
    trace (ERROR, INTERFACE_MASTER->trace, 
      "SIOCGIFADDR returns strange address (family=%d)\n", 
      addr.sin_family);
#endif
    return (1);
  }

  if (ioctl(s, SIOCGIFNETMASK, (caddr_t)&ifr) < 0) {
    trace (ERROR, INTERFACE_MASTER->trace, 
      "SIOCGIFNETMASK for %s (%s)\n", name, strerror (errno));
    /* sometimes, no netmask */
    memset (&ifr.ifr_addr, -1, sizeof (ifr.ifr_addr));
  }
  memcpy (&mask, &ifr.ifr_addr, sizeof (mask));

  if (BIT_TEST (flags, IFF_POINTOPOINT)) {
    if (ioctl(s, SIOCGIFDSTADDR, (caddr_t)&ifr) < 0) {
      trace (ERROR, INTERFACE_MASTER->trace, 
        "SIOCGIFDSTADDR for %s (%s)\n", name, strerror (errno));
      /* sometimes, no destination address */
      memset (&ifr.ifr_addr, 0, sizeof (ifr.ifr_addr));
    }
  }
  else if (BIT_TEST (flags, IFF_BROADCAST)) {
    if (ioctl(s, SIOCGIFBRDADDR, (caddr_t)&ifr) < 0) {
      trace (ERROR, INTERFACE_MASTER->trace, 
        "SIOCGIFBRDADDR for %s (%s)\n", name, strerror (errno));
      /* sometimes, no broadcast address ??? */
      memset (&ifr.ifr_addr, 0, sizeof (ifr.ifr_addr));
    }
  }
  memcpy (&dest, &ifr.ifr_addr, sizeof (dest));

  if ((cp = strchr (ifr.ifr_name, ':')))
    *cp = '\0'; /* Remove the :n extension from the name */

  add_addr_to_interface (interface, AF_INET, 
      (char *)&addr.sin_addr.s_addr,
       mask2len ((char *)&mask.sin_addr.s_addr, 4),
      (char *)&dest.sin_addr.s_addr);
  return (1);
}


int route_sockfd = -1;

int
kernel_init (void)
{
    if ((route_sockfd = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
        trace (ERROR, MRT->trace, "KERNEL socket for AF_INET (%s)\n",
               strerror (errno));
        return (-1);
    }
    return (0);
}


/*
 */
int sys_kernel_update_route (prefix_t *dest, 
			 prefix_t *next_hop, prefix_t *old_hop, 
			 int index, int oldindex)
{
  int s;
  struct rtentry rt;
  struct sockaddr_in *dst = (struct sockaddr_in *)&rt.rt_dst;
  struct sockaddr_in *gateway = (struct sockaddr_in *)&rt.rt_gateway;
  struct ifnet inf;
  int op;

  if (next_hop && old_hop) {
    sys_kernel_update_route (dest, NULL, old_hop, 0, oldindex);
    sys_kernel_update_route (dest, next_hop, NULL, index, 0);
    return (1);
  }
  else if (next_hop) {
    op = SIOCADDRT;
  }
  else if (old_hop) {
    next_hop = old_hop;
    index = oldindex;
    op = SIOCDELRT;
  }

  if (dest->family == AF_INET) {

    if ((s = route_sockfd) < 0)
      return (-1);

    memset (&rt, 0, sizeof (rt));

    dst->sin_family = AF_INET;
    memcpy (&dst->sin_addr, prefix_tochar (dest), sizeof (dst->sin_addr));

    gateway->sin_family = AF_INET;
    memcpy (&gateway->sin_addr, prefix_tochar (next_hop), 
        sizeof (gateway->sin_addr));

    if (dest->bitlen == 32)
      rt.rt_flags  |= RTF_HOST;

    rt.rt_flags  |= RTF_UP;
    if (gateway->sin_addr.s_addr != INADDR_ANY) {
      rt.rt_flags |= RTF_GATEWAY;
    }
#ifdef notdef
    if (cmd == KERNEL_ROUTE_ADD) {
      /* I'm not sure this does work -- masaki */
      interface = find_interface_byindex (index);
      inf.if_name = interface->name;
      rt.rt_ifp =  &inf;
    }
#endif

    if (ioctl (s, op, &rt) < 0) {
      trace (TR_ERROR, MRT->trace, "kernel ioctl (%s)\n", strerror (errno));
      return (-1);
    }
  
  }
  else {
    assert (0); /* not a family we know about */
  }

  return (1);
}


int sys_kernel_read_rt_table () 
{
   /* should read /dev/kmem */
   return (1);
}
