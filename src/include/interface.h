/*
 * $Id: interface.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef _INTERFACE_H
#define _INTERFACE_H

/* Some of this code taken from Berkely routed software */

#include <mrt.h>
#include <trace.h>
#include <sys/types.h>
#ifndef NT
#include <sys/socket.h>
#endif /* NT */
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif /* HAVE_SYS_SOCKIO_H */
#ifndef NT
#include <net/if.h>
#include <net/route.h>
#endif /* NT */

typedef struct _ll_addr_t {
    prefix_t *prefix;		/* interface addresess */
    prefix_t *broadcast;	/* destination or broadcast address
				   broadcast address is defined in case of v4
				   prefixlen will be ignored */
} ll_addr_t;

#define IFF_TUNNEL  0x80000000  /* tunnel interface (special treatment
                                   when adding a route into the kernel) */
#define IFF_VIF_TUNNEL  0x40000000  /* vif interface used in multicasting */

#define MAX_INTERFACES 256
typedef struct _interface_bitset_t {
        bitx_mask_t bits[(MAX_INTERFACES+BITX_NBITS-1)/BITX_NBITS];
} interface_bitset_t;


typedef struct _interface_t {
#ifdef notdef
    u_long bit;			/* each interface assigned a unique bit */
#endif
    u_long flags;		/* interface flags (from the ioctl) */
    int mtu;			/* interface mtu (from the ioctl) */
    char name[IFNAMSIZ + 1];
    int index;			/* index number */
    u_long protocol_mask;	/* which protocols are on */

#ifdef notdef
/* the followings are RIP and RIPng deppendent */
    int dlist_in[PROTO_MAX];	/* list num for input filtering */
    int dlist_out[PROTO_MAX];	/* list num for output filtering */
    int metric_in;		/* input metric */
    int metric_out;		/* output metric */
    int default_pref;
#ifdef HAVE_IPV6
    int default_pref6;
#endif /* HAVE_IPV6 */
#endif /* notdef */

    LINKED_LIST *ll_addr;	/* address list */
    ll_addr_t *primary;		/* primary address for ipv4 */
#ifdef HAVE_IPV6
    ll_addr_t *primary6;	/* primary address for ipv6 (global) */
    ll_addr_t *link_local;	/* ipv6 link local address */
#endif /* HAVE_IPV6 */

#ifdef HAVE_MROUTING
    int vif_index;		/* vif index number */
    prefix_t *tunnel_source;
    prefix_t *tunnel_destination;
#endif /* HAVE_MROUTING */
#if defined(HAVE_MROUTING) || defined (HAVE_MROUTING6)
    int threshold;
    int rate_limit;
#endif /* HAVE_MROUTING || HAVE_MROUTING6 */
} interface_t;


typedef struct _interface_master_t {
    int number;		/* number of interfaces */
    interface_t *default_interface;
#ifdef HAVE_IPV6
    interface_t *default_interface6;
#endif				/* HAVE_IPV6 */ 
    trace_t *trace;
    LINKED_LIST *ll_interfaces;	/* IPv4 & v6 interfaces */
    int max_mtu;		/* maximum MTU */
    interface_t *index2if[MAX_INTERFACES];
#ifdef HAVE_MROUTING
    interface_t *vindex2if[MAX_INTERFACES];
    int num_vif;
#endif /* HAVE_MROUTING */
    int sockfd;			/* general purpose socket (v4) */
#ifdef HAVE_IPV6
    int sockfd6;		/* general purpose socket (v6) */
#endif /* HAVE_IPV6 */
    pthread_mutex_t mutex_lock;
    LINKED_LIST *ll_call_fns;	/* called on change */
} interface_master_t;

extern interface_master_t *INTERFACE_MASTER;

typedef void (*interface_call_fn_t)(int cmd, interface_t *interface, 
				    ll_addr_t *if_addr); 

/* This may conflict with other MSG_XXX flags defined in the system */
#define MSG_DONTCARE   0x80000000  /* interface info is not required */
#define MSG_MAYIGMP    0x40000000  /* a packet may be igmp kernel msg */
#define MSG_MULTI_LOOP 0x20000000  /* a packet will be echoed back to local */

/* public functions */
interface_t *new_interface (char *name, u_long flags, int mtu, int index);
interface_t *add_addr_to_interface (interface_t * interface, int family,
				    void *addr, int len, void *broadcast);
interface_t *update_addr_of_interface (int cmd,
                          interface_t * interface, int family,
                          void *addr, int bitlen, void *broadcast);
int read_interfaces ();

interface_t *find_interface (prefix_t * prefix);
interface_t *find_interface_flags (prefix_t * prefix, u_long flags);
interface_t *find_interface_byname (char *name);
LINKED_LIST *find_interface_byname_all (char *name);
interface_t *find_interface_byindex (int index);
interface_t *find_interface_local (prefix_t * prefix);
interface_t *find_interface_direct (prefix_t * prefix);
LINKED_LIST *find_network (prefix_t * prefix);
interface_t *local_interface (int familly, void *cp);
int init_interfaces (trace_t * ltrace);
interface_t *find_tunnel_interface (prefix_t * prefix);

int show_interfaces (uii_connection_t *uii);
int mask2len (void *mask, int bytes);
u_char *len2mask (int bitlen, void *mask, int bytes);

void kernel_update_route (prefix_t *dest, 
			  generic_attr_t *new_attr, generic_attr_t *old_attr, int pref);
int sys_kernel_update_route (prefix_t *dest,
                         prefix_t *next_hop, prefix_t *old_hop, 
			 int index, int oldindex);
int kernel_init (void);
void kernel_read_rt_table (int seconds);
int sys_kernel_read_rt_table (void);
int add_kernel_route (int family, void *dest, void *nhop, int masklen, 
		      int index);
int update_kernel_route (int cmd, int family, void *dest, void *nhop, 
			 int masklen, int index, int proto);
char *print_iflags (char *tmpx, int len, u_long flags);
void add_interfaces_to_rib (int cmd, interface_t *interface, 
			    ll_addr_t *if_addr);

/* socket.c */

int socket_open (int family, int type, int proto);
int socket_reuse (int sockfd, int yes);
int socket_broadcast (int sockfd, int yes);
int socket_rcvbuf (int sockfd, int size);
int ip_hdrincl (int sockfd, int yes);
int ip_multicast_loop (int sockfd, int yes);
int ip_multicast_loop_get (int sockfd);
int ip_multicast_hops (int sockfd, int hops);
int ip_pktinfo (int sockfd, int yes);
int ip_recvttl (int sockfd, int yes);

#ifdef HAVE_IPV6
int ipv6_multicast_loop (int sockfd, int yes);
int ipv6_multicast_loop_get (int sockfd);
int ipv6_pktinfo (int sockfd, int yes);
int ipv6_recvhops (int sockfd, int yes);
int ipv6_unicast_hops (int sockfd, int hops);
int ipv6_multicast_loop (int sockfd, int yes);
int ipv6_multicast_hops (int sockfd, int hops);
int ipv6_multicast_if (int sockfd, interface_t *interface);
#ifdef ICMP6_FILTER
int icmp6_filter (int sockfd, struct icmp6_filter *filter);
#endif /* ICMP6_FILTER */

#endif /* HAVE_IPV6 */
int join_leave_group (int sockfd, interface_t *interface, prefix_t *prefix, 
		      int join);
int ip_multicast_if (int sockfd, interface_t *interface);
int ip_multicast_vif (int sockfd, interface_t *interface);
int recvmsgfrom (int sockfd, u_char *buffer, int buflen, u_long flags,
	         prefix_t **prefix_p, int *port_p, interface_t **interface_p,
		 prefix_t **destin_p, int *hop_p);
int send_packet (int sockfd, u_char *msg, int len, u_long flags,
                 prefix_t *prefix, int port, interface_t *interface, 
		 u_long flowinfo);
#ifdef HAVE_MROUTING
int mc_mrtinit (void);
int mc_mrtversion (void);
int mc_mrtdone (void);
int mc_add_vif (interface_t *interface);
int mc_del_vif (interface_t *interface);
int mc_add_mfc (prefix_t *group, prefix_t *origin, interface_t *parent, 
		interface_bitset_t *children);
int mc_del_mfc (prefix_t *group, prefix_t *origin);
int mc_req_mfc (prefix_t *group, prefix_t *origin);
int mc_assert (int yes);
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
int mc6_mrtinit (void);
int mc6_add_vif (interface_t *interface);
int mc6_del_vif (interface_t *interface);
int mc6_add_mfc (prefix_t *group, prefix_t *source, interface_t *parent, 
		 interface_bitset_t *children);
int mc6_del_mfc (prefix_t *group, prefix_t *source);
int mc6_req_mfc (prefix_t *group, prefix_t *source);
int mc6_mrtdone (void);
int mc6_kernel_update_cache (int type, prefix_t *group, prefix_t *source,
                             interface_t *parent, interface_bitset_t *children);
int mc6_kernel_read_rt_table (void);
#endif /* HAVE_MROUTING6 */
int inet_cksum (void *cp, int len);
#ifdef HAVE_IPV6
int inet6_cksum (void *cp, int len, int nh,
                 struct in6_addr *src, struct in6_addr *dst);
#endif /* HAVE_IPV6 */
int how_many_bits (interface_bitset_t *bitset);
void socket_set_nonblocking (int sockfd, int yes);
int socket_bind_port (int sockfd, int family, void *addr, int lport);

int get_socket_addr (int sockfd, int remote, prefix_t **prefix_p);
#endif /* INTERFACE_H */
