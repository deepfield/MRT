/*
 * $Id: mrt.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef _MRT_H
#define _MRT_H

#define MAX_BGP_PEERS           64
#define MAX_BGP_VIEWS           64

#include <version.h>
#include <config.h>

#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>
#ifdef __GNUC__
/* to avoid it defined in stdio.h */
#include <stdarg.h>
#else
#ifndef NT
#include <sys/varargs.h>
#endif /* NT */
#endif /* __GNUC__ */
#include <errno.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#ifndef NT
#include <sys/param.h>
#include <sys/socket.h>
#include <unistd.h>
#endif /* NT */
#include <ctype.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif /* HAVE_STRING_H */
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */

/* Obtained from GNU autoconf manual */
/* AIX requires this to be the first thing in the file.  */
#ifdef __GNUC__
# ifndef alloca
# define alloca __builtin_alloca
# endif
#else
# if HAVE_ALLOCA_H
#  include <alloca.h>
# else
#  ifdef _AIX
 #pragma alloca
#  else
#   ifndef alloca /* predefined by HP cc +Olibcalls */
char *alloca ();
#   endif
#  endif
# endif
#endif

#ifndef NT
#include <netinet/in.h>
#else
#include <winsock2.h>
#endif /* NT */
#ifdef HAVE_RESOLV_H
#include <arpa/nameser.h>
#include <resolv.h>
#endif /* HAVE_RESOLV_H */


#include <defs.h>
#include <assert.h>
#include <mrt_thread.h>

typedef void (*void_fn_t)();
typedef int (*int_fn_t)();
typedef void *(*thread_fn_t)(void *);

#include <New.h>
#include <linked_list.h>
#include <object.h>
#include <trace.h>
#include <schedule.h>
#include <proto.h>
#include <select.h>

#ifdef notdef
extern int IPV4;
#ifdef HAVE_IPV6
extern int IPV6;
#endif /* IPV6 */
#endif

#define AFI_IP  1
#define AFI_IP6 2
#define AFI_MAX 3
#define SAFI_UNICAST 1
#define SAFI_MULTICAST 2
#define SAFI_MAX 3
        
int afi2family (int afi);
int family2afi (int family);
char *afi2string (int afi);
char *safi2string (int safi);

#ifndef ON
#define ON 1
#endif /* ON */
#ifndef OFF
#define OFF 0
#endif /* OFF */

#define NIL (-1)

#ifndef INET_ADDRSTRLEN
#define INET_ADDRSTRLEN   16
#endif /* INET_ADDRSTRLEN */

#ifdef NT
#ifdef HAVE_IPV6
#include <ip6.h> 
#include <ws2ip6.h>
#endif /* HAVE_IPV6 */
#endif /* NT */

#ifndef HAVE_IPV6
#ifndef AF_INET6
#define AF_INET6 24 /* XXX - may conflict with other value */
#endif
#ifndef HAVE_STRUCT_IN6_ADDR
struct in6_addr {
  u_char s6_addr[16];
};
#endif /* HAVE_STRUCT_IN6_ADDR */
#endif /* HAVE_IPV6 */
#include <api6.h>

typedef struct _prefix_t {
    u_short family;		/* AF_INET | AF_INET6 */
    u_short bitlen;		/* same as mask? */
    int ref_count;		/* reference count */
    pthread_mutex_t mutex_lock; /* lock down structure */
    union {
		struct in_addr sin;
#ifdef HAVE_IPV6
		struct in6_addr sin6;
#endif /* IPV6 */
    } add;
} prefix_t;

typedef struct _address_t {
    u_short family;		/* AF_INET | AF_INET6 */
    u_short port;		/* port number in host byte order */
    int ref_count;		/* reference count */
    pthread_mutex_t mutex_lock; /* lock down structure */
    union {
	struct in_addr sin;
#ifdef HAVE_IPV6
	struct in6_addr sin6;
#endif /* IPV6 */
    } add;
} address_t;

typedef struct _prefix4_t {
    u_short family;		/* AF_INET | AF_INET6 */
    u_short bitlen;		/* same as mask? */
    int ref_count;		/* reference count */
    pthread_mutex_t mutex_lock; /* lock down structure */
    struct in_addr sin;
} prefix4_t;

#ifdef HAVE_IPV6
typedef struct _prefix6_t {
    u_short family;		/* AF_INET | AF_INET6 */
    u_short bitlen;		/* same as mask? */
    int ref_count;		/* reference count */
    pthread_mutex_t mutex_lock; /* lock down structure */
    struct in6_addr sin6;
} prefix6_t;
#endif /* IPV6 */


typedef struct _prefix_pair_t {
    prefix_t *prefix1;
    prefix_t *prefix2;
} prefix_pair_t;


#include <alist.h>

typedef struct _Route {
    prefix_t *prefix;
    void *attr;			/* attribure strcutre like bgp_attr_t */
} Route;


enum ROUTE_ATTR_TYPES {
    ROUTE_ATTR_BGP4,
    ROUTE_ATTR_RIP,
    ROUTE_ATTR_IDRP
};

#ifdef NT
#undef interface
#endif /* NT */

typedef struct _gateway_t {
    prefix_t *prefix;
    struct _interface_t *interface;
/* the following two are protocol (BGP) dependent ? */
    int AS;
    u_long routerid;
/* the following two are for shared nexthop structure */
    int ref_count;		/* reference count */
    pthread_mutex_t mutex_lock; /* lock down structure */
    u_long flags;
} gateway_t;

#define GATEWAY_LOCAL	 0x01
#define GATEWAY_DIRECT   0x02
#define GATEWAY_INDIRECT 0x04
#define GATEWAY_UNSPEC   0x08
#define GATEWAY_LLOCAL   0x10

/* they share the same hash table */
typedef gateway_t nexthop_t;


/* this should match with other attributes */
typedef struct _generic_attr_t {
    u_char type;		/* RIP, BGP, OSPF */
    int ref_count;
    pthread_mutex_t mutex_lock; /* lock down structure */
    /* here is 3 bytes space */
    nexthop_t *nexthop;
    gateway_t *gateway;		/* gateway we learned route from */
    u_long tag;
    nexthop_t *parent;	/* parent nexthop in case of IBGP or MULTIHOP */
} generic_attr_t;


typedef struct _tuple_t {
    int len;
    u_char *data;
} tuple_t;


extern int VERBOSE_ERROR_FLAG;	/* yuck, delete this */


#include <hash.h>

typedef struct _mrt_hash_table_t {
    HASH_TABLE *table;
    pthread_mutex_t mutex_lock;
} mrt_hash_table_t;


#ifdef notdef
typedef struct _nexthop_t {
    prefix_t *prefix;
    int ref_count;		/* reference count */
    pthread_mutex_t mutex_lock; /* lock down structure */
} nexthop_t;
#endif

#ifdef HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif /* HAVE_NET_IF_DL_H */

#if defined(HAVE_MROUTING) || defined(HAVE_MROUTING6)
#include <net/route.h>
#endif /* HAVE_MROUTING || HAVE_MROUTING6 */

typedef union _sockunion_t {
    struct sockaddr sa;
    struct sockaddr_in sin;
#ifdef AF_LINK
    struct sockaddr_dl sdl;
#endif /* AF_LINK */
#ifdef HAVE_IPV6
    struct sockaddr_in6 sin6;
#ifdef RTA_DOWNSTREAM
    struct sockaddr_inds inds;
#endif /* RTA_DOWNSTREAM */
#endif  /* HAVE_IPV6 */
} sockunion_t;

u_char *sockunion2char (sockunion_t *u);


typedef void (*proto_update_route_t) (prefix_t *prefix, 
		generic_attr_t *new_attr,
                generic_attr_t *old_attr, int pref, int viewno);
typedef void (*kernel_update_route_t) (prefix_t *prefix, 
		generic_attr_t *new_attr,
                generic_attr_t *old_attr, int pref);
typedef void (*rib_update_route_t) (prefix_t *prefix, generic_attr_t *new_attr,
                         generic_attr_t *old_attr, int pref, u_long flags,
			 int safi);
typedef void (*rib_flush_route_t) (int proto, int afi, int safi);
typedef nexthop_t *(*rib_find_best_route_t) (prefix_t *prefix, int safi);
typedef nexthop_t *(*rib_find_upstream_t) (prefix_t *prefix, int safi);
typedef void (*rib_update_nexthop_t) (int afi, int safi);
typedef time_t (*rib_time_t) (int afi, int safi);
typedef int (*rib_redistribute_request_t) (int from, int viewno, 
					   int to, int on, int afi, int safi);
typedef int (*rib_redistribute_network_t) (int from, int viewno, 
					 prefix_t *network, int on, int safi);

/* Main MRT structure
 * holds bookkeeping information on gateways, threads, signals, etc
 * ALL MRT programs depend on this structure
 */
typedef struct _mrt_t {
    pthread_mutex_t mutex_lock;		/* lock down structure */
    trace_t *trace;			/* default trace - go away future? */
    LINKED_LIST *ll_threads;		/* list of all thread_t */
    LINKED_LIST *ll_signal_call_fn;	/* list of mrt_signal_t */
    LINKED_LIST *ll_gateways;		/* list of gateway_t for Solaris */
    LINKED_LIST *ll_trace;		/* list of trace_t */
    char *config_file_name;
    long start_time;			/* uptime of system (debugging) */
#ifndef HAVE_LIBPTHREAD
    /* for use on non-thread systems -- current thread # */
    int threadn;
#endif /* HAVE_LIBPTHREAD */
    u_long protocols;			/* protocols enabled */
    /* u_long redist[PROTO_MAX + 1]; */	/* protocols redistribute */
    proto_update_route_t proto_update_route[PROTO_MAX + 1];
    kernel_update_route_t kernel_update_route;
    rib_update_route_t rib_update_route;
    rib_flush_route_t rib_flush_route;
    rib_find_best_route_t rib_find_best_route;
    rib_find_upstream_t rib_find_upstream;
    rib_time_t rib_time;
    rib_update_nexthop_t rib_update_nexthop;
    rib_redistribute_request_t rib_redistribute_request;
    rib_redistribute_network_t rib_redistribute_network;
    /* for rebooting - save cwd, and arguments */
    char	*cwd;
    char        **argv;
    int    	argc;
    int		daemon_mode;
    mrt_hash_table_t hash_table;
#ifdef HAVE_IPV6
    mrt_hash_table_t hash_table6;
#endif /* HAVE_IPV6 */
    volatile int force_exit_flag;
#ifndef HAVE_LIBPTHREAD
    int initialization;
#endif /* HAVE_LIBPTHREAD */
    int		kernel_install_flag4;
    int		kernel_install_flag6;
    u_long	default_id; /* router id for bgp */
    int		pid;
    char	*version;
    char	*date;
} mrt_t;

/* must not the same as any signal number */
#define MRT_FORCE_EXIT   999
#define MRT_FORCE_REBOOT 998
#define MRT_FORCE_ABORT  997

typedef struct _redistribute_t {
    int type;
    proto_update_route_t fn;
} redistribute_t;


typedef struct _ll_value_t {
    int value;
    LL_POINTERS ptrs;
} ll_value_t;


extern mrt_t *MRT;
extern int IPV4;
extern int IPV6;

/* Main thread gets all signals. Threads can request to have call_fn
 * executed upon receipt of a signal
 */
typedef struct _mrt_signal_t {
    int signal;
    void_fn_t call_fn;
/*    mrt_call_fn_t call_fn; */
} mrt_signal_t;

typedef struct _mrt_thread_t {
    char *name;
    pthread_t thread;
    pthread_attr_t attr;
    schedule_t *schedule; /* schedule sttached to the thread */
} mrt_thread_t;


#ifdef HAVE_LIBPTHREAD

#define THREAD_SPECIFIC_DATA(type, data, size) \
    do { \
        static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER; \
        static pthread_key_t key;\
        static int need_get_key = 1; \
        \
        if (need_get_key) { \
	    pthread_mutex_lock (&mutex); \
	    /* need double check since this thread may be locked */ \
	    if (need_get_key) { \
	        if (pthread_key_create (&key, free) < 0) { \
	            pthread_mutex_unlock (&mutex); \
		    data = (type *) NULL; \
		    perror ("pthread_key_create"); \
		    abort (); \
		    break; \
		} \
		need_get_key = 0; \
	    } \
	    pthread_mutex_unlock (&mutex); \
        } \
        if ((data = (type *) pthread_getspecific (key)) == NULL) { \
	    if ((data = (type *) calloc (size, sizeof (type))) == NULL) { \
		perror ("pthread_getspecific"); \
		abort (); \
	        break; \
	    } \
	    if (pthread_setspecific (key, data) < 0) { \
		perror ("pthread_setspecific"); \
		abort (); \
		break; \
	    } \
        } \
    } while (0)
#else
#define THREAD_SPECIFIC_DATA(type, data, size) \
    do { \
        static type buff[size]; \
        data = buff; \
    } while (0)
#endif /* HAVE_LIBPTHREAD */

#define THREAD_SPECIFIC_STORAGE_LEN 1024
#define THREAD_SPECIFIC_STORAGE_NUM 16
#define THREAD_SPECIFIC_STORAGE2(data, len, num) \
    do { \
        struct buffer { \
            u_char buffs[num][len]; \
            u_int i; \
        } *buffp; \
	\
	THREAD_SPECIFIC_DATA (struct buffer, buffp, 1); \
	if (buffp) { \
	    data = (void*)buffp->buffs[buffp->i++%num]; \
	} \
	else { \
	    data = (void*)NULL; \
	} \
    } while (0)

#define THREAD_SPECIFIC_STORAGE_LEN 1024
#define THREAD_SPECIFIC_STORAGE_NUM 16
#define THREAD_SPECIFIC_STORAGE(data) THREAD_SPECIFIC_STORAGE2 (\
	data, THREAD_SPECIFIC_STORAGE_LEN, THREAD_SPECIFIC_STORAGE_NUM)

#define ASSERT(x) { if (!(x)) \
	err_dump ("\nAssert failed line %d in %s", __LINE__, __FILE__); }

#define UTIL_GET_BYTE(val, cp)   ((val) = *(cp)++)

#define UTIL_GET_SHORT(val, cp) \
        { \
            register u_char *val_p; \
	    val_p = (u_char *) &(val); \
	    *val_p++ = *(cp)++; \
	    *val_p++ = *(cp)++; \
        }

#define UTIL_GET_NETSHORT(val, cp) \
	{ \
            register u_char *val_p; \
            val_p = (u_char *) &(val); \
            *val_p++ = *(cp)++; \
            *val_p++ = *(cp)++; \
	    (val) = ntohs(val); \
	}

#define UTIL_GET_LONG(val, cp) \
        { \
            register u_char *val_p; \
            val_p = (u_char *) &(val); \
            *val_p++ = *(cp)++; \
            *val_p++ = *(cp)++; \
            *val_p++ = *(cp)++; \
            *val_p++ = *(cp)++; \
        }

/* This version of UTIL_GET_NETLONG uses ntohl for cross-platform
 * compatibility, which is A Good Thing (tm) */
#define UTIL_GET_NETLONG(val, cp) \
        { \
            register u_char *val_p; \
            val_p = (u_char *) &(val); \
            *val_p++ = *(cp)++; \
            *val_p++ = *(cp)++; \
            *val_p++ = *(cp)++; \
            *val_p++ = *(cp)++; \
            (val) = ntohl(val); \
        }

#define UTIL_GET_BITCOUNT(bitcount, cp)  ((bitcount) = *(cp)++)

#define UTIL_PUT_BYTE(val, cp)   (*(cp)++ = (byte)(val))

#define UTIL_PUT_SHORT(val, cp) \
        { \
            u_short tmp = (val); \
	    register u_char *tmp_p = (u_char *) &tmp; \
	    *(cp)++ = *tmp_p++; \
	    *(cp)++ = *tmp_p++; \
        }

/* Network version of UTIL_PUT_SHORT, using htons for cross-platform
 * compatibility */
#define UTIL_PUT_NETSHORT(val, cp) \
	{ \
	    u_short tmp; \
            register u_char *val_p; \
	    tmp = htons(val); \
	    val_p = (u_char *) &tmp; \
            *(cp)++ = *val_p++; \
            *(cp)++ = *val_p++; \
	}


#define UTIL_PUT_LONG(val, cp) \
        { \
            u_long tmp = (val); \
	    register u_char *tmp_p = (u_char *) &tmp; \
            *(cp)++ = *tmp_p++; \
            *(cp)++ = *tmp_p++; \
            *(cp)++ = *tmp_p++; \
            *(cp)++ = *tmp_p++; \
        }

/* Network version of UTIL_PUT_LONG which uses htonl to maintain
 * cross-platform byte-orderings across the network */
#define UTIL_PUT_NETLONG(val, cp) \
        { \
            u_long tmp; \
            register u_char *val_p; \
            tmp = htonl(val); \
            val_p = (u_char *) &tmp; \
            *(cp)++ = *val_p++; \
            *(cp)++ = *val_p++; \
            *(cp)++ = *val_p++; \
            *(cp)++ = *val_p++; \
        }

#include <user.h>
#include <filter.h>

/* public functions */

prefix_t *New_Prefix (int family, void * dest, int bitlen);
prefix_t *New_Prefix2 (int family, void * dest, int bitlen, prefix_t *prefix);
prefix_t *Change_Prefix (int family, void * dest, int bitlen, prefix_t * prefix);
prefix_t *Ref_Prefix (prefix_t * prefix);
void Deref_Prefix (prefix_t * prefix);
void Delete_Prefix (prefix_t * prefix);
int prefix_check_prefix_in_list (LINKED_LIST * ll_prefix, prefix_t * prefix);
void print_prefix_list (LINKED_LIST * ll_prefixes);
void print_prefix_list_buffer (LINKED_LIST * ll_prefixes, buffer_t * buffer);
void print_prefix (prefix_t * p_prefix);
void print_pref_prefix_list_buffer (LINKED_LIST * ll_prefixes, 
				    u_short *pref, buffer_t * buffer);
prefix_t *copy_prefix (prefix_t * prefix);
void print_pref_prefix_list (LINKED_LIST * ll_prefixes, u_short *pref);

struct sockaddr *prefix_tosockaddr(prefix_t *);
prefix_t *sockaddr_toprefix (struct sockaddr *sa);
prefix_t *name_toprefix(char *, trace_t *);
prefix_t *string_toprefix(char *, trace_t *);
char *prefix_toname(prefix_t *prefix);

#define prefix_tolong(prefix) (assert ((prefix)->family == AF_INET),\
			       (prefix)->add.sin.s_addr)
#define prefix_tochar(prefix) ((char *)&(prefix)->add.sin)
#define prefix_touchar(prefix) ((u_char *)&(prefix)->add.sin)
#define prefix_toaddr(prefix) (&(prefix)->add.sin)
#define prefix_getfamily(prefix) ((prefix)->family)
#define prefix_getlen(prefix) (((prefix)->bitlen)/8)
#ifdef HAVE_IPV6
#define prefix_toaddr6(prefix) (assert ((prefix)->family == AF_INET6),\
				&(prefix)->add.sin6)
#endif /* IPV6 */

#ifdef notdef
u_char *prefix_tochar (prefix_t * prefix);
#endif
int prefix_compare (prefix_t * p1, prefix_t * p2);
int prefix_equal (prefix_t * p1, prefix_t * p2);
int prefix_compare2 (prefix_t * p1, prefix_t * p2);
int prefix_compare_wolen (prefix_t *p, prefix_t *q);
int address_equal (prefix_t *p, prefix_t *q);
int prefix_compare_wlen (prefix_t *p, prefix_t *q);
int a_include_b (prefix_t * a, prefix_t * b);
char *prefix_toa (prefix_t * prefix);
char *prefix_toa2 (prefix_t * prefix, char *tmp);
char *prefix_toax (prefix_t * prefix);
char *prefix_toa2x (prefix_t * prefix, char *tmp, int with_len);
prefix_t *ascii2prefix (int family, char *string);
int my_inet_pton (int af, const char *src, void *dst);
/*int my_inet_pton6(int family, const char *string, struct in6_addr *sin6);*/

char *get_netname (int dest, int bitlen);
int munge_route_string ();
int _atoi ();
char *my_strftime (long t, char *fmt);

gateway_t *add_bgp_gateway (prefix_t * prefix, int as, u_long id,
	    /* resolve cross reference ... */ struct _interface_t *interface);
gateway_t *add_gateway (prefix_t * prefix, int as,
	    /* resolve cross reference ... */ struct _interface_t *interface);
/* gateway_t *find_gateway (prefix_t * prefix, int AS); */
char *gateway_toa (char *tmp, gateway_t * gateway);
char *gateway_toa2 (gateway_t * gateway);
/* void destroy_gateway (gateway_t * gateway); */

nexthop_t * add_bgp_nexthop (prefix_t *prefix, int as, u_long id,
			 struct _interface_t *interface);
nexthop_t * add_nexthop (prefix_t *prefix,
			 struct _interface_t *interface);
void deref_nexthop (nexthop_t *nexthop);
nexthop_t *eval_nexthop (nexthop_t *nexthop);
nexthop_t * ref_nexthop (nexthop_t *nexthop);
gateway_t * find_gateway (prefix_t *prefix);
gateway_t * find_bgp_gateway (prefix_t *prefix, int as, u_long id);
int is_prefix_on (prefix_t *prefix, interface_t *interface); 
int is_prefix_local_on (prefix_t * prefix, interface_t *interface); 
int nexthop_available (nexthop_t *nexthop);

int init_mrt (trace_t *tr);
mrt_thread_t *mrt_thread_create (char *name, schedule_t * schedule,
				 thread_fn_t callfn, void *arg);
mrt_thread_t *mrt_thread_create2 (char *name, schedule_t * schedule,
				 thread_fn_t callfn, void *arg);
int is_ipv4_prefix (char *string);

#ifdef HAVE_IPV6
int is_ipv6_prefix (char *string);
int ipv6_multicast_addr (struct in6_addr *sin6);
int ipv6_link_local_addr (struct in6_addr *sin6);
int ipv6_ipv4_addr (struct in6_addr *sin6);
int ipv6_compat_addr (struct in6_addr *sin6);
int ipv6_any_addr (struct in6_addr *sin6);
#endif /* HAVE_IPV6 */
u_char *netmasking (int family, void *addr, u_int bitlen);
int comp_with_mask (void *addr, void *dest, u_int mask);
int byte_compare (void *addr, void *dest, int bits, void *wildcard);

#ifndef NT
#include <arpa/inet.h>
#endif /* NT */
#ifndef HAVE_INET_NTOP
const char *inet_ntop (int af, const void *src, char *dst, size_t size);
int inet_pton (int af, const char *src, void *dst);
#endif /* HAVE_INET_NTOP */
#ifndef HAVE_MEMMOVE
#ifdef NT
void *memmove (void *dest, const void *src, size_t n);
#else
char *memmove (char *dest, const char *src, size_t n);
#endif /* NT */
#endif /* HAVE_MEMMOVE */

int atox (char *str);
char *r_inet_ntoa (char *buf, int n, u_char *l, int len);
char *family2string (int family);
int is_any_addr (prefix_t *prefix);
int prefix_is_unspecified (prefix_t *prefix);
int prefix_is_loopback (prefix_t *prefix);
int prefix_is_multicast (prefix_t *prefix);
int prefix_is_v4compat (prefix_t *prefix);
int prefix_is_linklocal (prefix_t *prefix);
int prefix_is_v4mapped (prefix_t *prefix);
int prefix_is_sitelocal (prefix_t *prefix);
int prefix_is_global (prefix_t *prefix);

int nonblock_connect (trace_t *default_trace, prefix_t *prefix, int port, int sockfd);
void mrt_reboot (void);
int init_mrt_reboot (int argc, char *argv[]);
void mrt_main_loop (void);
void mrt_busy_loop (volatile int *force_exit_flag, int ok);
void mrt_switch_schedule (void);
int mrt_update_pid (void);
void mrt_thread_exit (void);
void mrt_thread_kill_all (void);
void init_mrt_thread_signals (void);
void mrt_exit (int status);
void mrt_process_signal (int sig);
void mrt_set_force_exit (int code);

buffer_t *New_Buffer (int len);
void Delete_Buffer (buffer_t *buffer);

int string2proto (char *proto_string);
char *proto2string (int proto);

#define LL_Add2(ll, a) LL_Add (((ll)? (ll): ((ll) = LL_Create (0))), (a))
#define LL_Add3(ll, a) { void *_b; \
	LL_Iterate (ll, _b) { if (_b == (a)) break;} if (!_b) LL_Add2 (ll,a);}
extern int BGPSIM_TRANSPARENT;

int gen_hash_fn (prefix_t * prefix, int size);
int gen_lookup_fn (prefix_t * a, prefix_t * b);

const char *origin2string (int origin);
const int origin2char (int origin);
char *bgptype2string (int type);
int string2bgptype (char **str);
char *proto2string (int proto);
char *time2date (int elapsed, char *date);
char *safestrncpy (char *dest, const char *src, size_t n);
char *etime2ascii (time_t elapsed, char *date);
u_long strtoul10 (char *nptr, char **endptr);
int ip_hash_fn (prefix_t * prefix, int size);
int ip_lookup_fn (prefix_t * a, prefix_t * b);
int ip_pair_hash_fn (prefix_pair_t * prefix, int size);
int ip_pair_lookup_fn (prefix_pair_t * a, prefix_pair_t * b);

#ifndef HAVE_STRTOK_R
#define strtok_r(a,b,c) strtok(a,b)
#endif /* HAVE_STRTOK_R */

#define open(a,b,c) mrt_open((a),(b),(c),__FILE__,__LINE__)
#define close(a) mrt_close((a),__FILE__,__LINE__)
#undef socket
#define socket(a,b,c) mrt_socket((a),(b),(c),__FILE__,__LINE__)
#define accept(a,b,c) mrt_accept((a),(b),(c),__FILE__,__LINE__)

int mrt_open (const char *path, int flags, mode_t mode, char *s, int l);
int mrt_close (int d, char *s, int l);
int mrt_socket (int domain, int type, int protocol, char *s, int l);
int mrt_accept (int d, struct sockaddr *addr, int *addrlen, char *s, int l);

int ifzero (void *ptr, int size);
int ifneg (void *a, void *c, int size);
int ifor (void *a, void *b, void *c, int size);
int ifand (void *a, void *b, void *c, int size);
int ifxor (void *a, void *b, void *c, int size);

#ifdef NT
/* I don't know exactly but it would reduce code changes */
#define socket_errno()	WSAGetLastError()

#define EWOULDBLOCK     WSAEWOULDBLOCK
#define EINPROGRESS     WSAEINPROGRESS
#define ECONNREFUSED    WSAECONNREFUSED
#define ETIMEDOUT       WSAETIMEDOUT
#define ENETUNREACH     WSAENETUNREACH
#define EHOSTUNREACH    WSAEHOSTUNREACH
#define EHOSTDOWN       WSAEHOSTDOWN
#define EISCONN         WSAEISCONN
//#define EINVAL          WSAEINVAL
#else
#define socket_errno()	errno
#endif /* NT */

#endif /* _MRT_H */
