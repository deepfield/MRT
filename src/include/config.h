/* include/config.h.  Generated automatically by configure.  */
/* include/config.h.in.  Generated automatically from configure.in by autoheader.  */
/* 
 * $Id: config.h,v 1.2 2000/08/15 01:03:28 labovit Exp $
 */


/* Define if using alloca.c.  */
/* #undef C_ALLOCA */

/* Define to empty if the keyword does not work.  */
/* #undef const */

/* Define to one of _getb67, GETB67, getb67 for Cray-2 and Cray-YMP systems.
   This function is required for alloca.c support on those systems.  */
/* #undef CRAY_STACKSEG_END */

/* Define if you have alloca, as a function or macro.  */
#define HAVE_ALLOCA 1

/* Define if you have <alloca.h> and it should be used (not on Ultrix).  */
#define HAVE_ALLOCA_H 1

/* Define if the `setpgrp' function takes no argument.  */
#define SETPGRP_VOID 1

/* If using the C implementation of alloca, define if you know the
   direction of stack growth for your system; otherwise it will be
   automatically deduced at run-time.
 STACK_DIRECTION > 0 => grows toward higher addresses
 STACK_DIRECTION < 0 => grows toward lower addresses
 STACK_DIRECTION = 0 => direction of growth unknown
 */
/* #undef STACK_DIRECTION */

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if you can safely include both <sys/time.h> and <time.h>.  */
#define TIME_WITH_SYS_TIME 1

/* Define if your <sys/time.h> declares struct tm.  */
/* #undef TM_IN_SYS_TIME */

/* Defined if you have IPV6 support */
/* #undef HAVE_IPV6 */

/* Defined if you have SOLARIS IPV6 */
/* #undef SOLARIS_IPV6 */

/* Defined if you have WIDE IPV6 */
/* #undef WIDE_IPV6 */

/* Defined if you have INRIA IPV6 */
/* #undef INRIA_IPV6 */

/* Defined if you have NRL IPV6 */
/* #undef NRL_IPV6 */

/* Defined if RFC2292 conform */
/* #undef RFC2292 */

/* Define if you have (IPv4) IGMP support */
#define HAVE_IGMP 1

/* Define if you have IPv4 multicast routing support */
#define HAVE_MROUTING 1

/* Define if you have IPv6 multicast routing support */
/* #undef HAVE_MROUTING6 */

/* Define if you have old ipv6_mreq (linux only) */
/* #undef HAVE_IPV6MR_IFINDEX */

/* Define if ipv6mr_interface is index */
/* #undef IPV6MR_INTERFACE_INDEX */

/* Define if you have pthread library (-lpthread) */
#define HAVE_LIBPTHREAD 1

/* Define if you have "struct ether_addr" */
#define HAVE_ETHER_ADDR 1

/* Define if we have a phyiscal interface to the network */
#define HAVE_PHYSICAL_INTERFACE 1

/* Define if solaris 2.8 */
/* #undef SOLARIS28 */

/* Define if solaris 2.7 */
/* #undef SOLARIS27 */

/* Define if solaris 2.6 */
#define SOLARIS26 1

/* Define if send/recvmsg will be used */
#define USE_SENDRECVMSG 1

/* Define if OpenBSD */
/* #undef OPENBSD */

/* Define if you are using gdbm */
#define USE_GDBM 1

/* Define if you using berkeley db */
/* #undef USE_DB1 */

/* Define if you have pthread_attr_setscope */
#define HAVE_PTHREAD_ATTR_SETSCOPE 1

/* Define if you have struct in6_addr */
/* #undef HAVE_STRUCT_IN6_ADDR */

/* Define if you have u_char, u_int, u_short, and u_long */
#define HAVE_U_TYPES 1

/* Define if you have sin6_scope_id */
/* #undef HAVE_SIN6_SCOPE_ID */

/* Define if you have RIC QOS routing */
/* #undef HAVE_RIC */

/* Define if you have the addr2ascii function.  */
/* #undef HAVE_ADDR2ASCII */

/* Define if you have the gethostbyaddr_r function.  */
#define HAVE_GETHOSTBYADDR_R 1

/* Define if you have the gethostbyname_r function.  */
#define HAVE_GETHOSTBYNAME_R 1

/* Define if you have the inet_ntop function.  */
#define HAVE_INET_NTOP 1

/* Define if you have the localtime_r function.  */
#define HAVE_LOCALTIME_R 1

/* Define if you have the memmove function.  */
#define HAVE_MEMMOVE 1

/* Define if you have the setsid function.  */
#define HAVE_SETSID 1

/* Define if you have the sigaction function.  */
#define HAVE_SIGACTION 1

/* Define if you have the sigprocmask function.  */
#define HAVE_SIGPROCMASK 1

/* Define if you have the sigrelse function.  */
#define HAVE_SIGRELSE 1

/* Define if you have the sigset function.  */
#define HAVE_SIGSET 1

/* Define if you have the strerror function.  */
#define HAVE_STRERROR 1

/* Define if you have the strptime function.  */
#define HAVE_STRPTIME 1

/* Define if you have the strtok_r function.  */
#define HAVE_STRTOK_R 1

/* Define if you have the sysctl function.  */
/* #undef HAVE_SYSCTL */

/* Define if you have the sysctlbyname function.  */
/* #undef HAVE_SYSCTLBYNAME */

/* Define if you have the thr_setconcurrency function.  */
#define HAVE_THR_SETCONCURRENCY 1

/* Define if you have the <gdbm.h> header file.  */
#define HAVE_GDBM_H 1

/* Define if you have the <inttypes.h> header file.  */
#define HAVE_INTTYPES_H 1

/* Define if you have the <malloc.h> header file.  */
#define HAVE_MALLOC_H 1

/* Define if you have the <net/bpf.h> header file.  */
/* #undef HAVE_NET_BPF_H */

/* Define if you have the <net/ethernet.h> header file.  */
/* #undef HAVE_NET_ETHERNET_H */

/* Define if you have the <net/if_dl.h> header file.  */
#define HAVE_NET_IF_DL_H 1

/* Define if you have the <netinet/icmp6.h> header file.  */
/* #undef HAVE_NETINET_ICMP6_H */

/* Define if you have the <netinet/if_ether.h> header file.  */
#define HAVE_NETINET_IF_ETHER_H 1

/* Define if you have the <netinet/ip6.h> header file.  */
/* #undef HAVE_NETINET_IP6_H */

/* Define if you have the <netinet/ip_mroute.h> header file.  */
#define HAVE_NETINET_IP_MROUTE_H 1

/* Define if you have the <pthread.h> header file.  */
#define HAVE_PTHREAD_H 1

/* Define if you have the <resolv.h> header file.  */
#define HAVE_RESOLV_H 1

/* Define if you have the <string.h> header file.  */
#define HAVE_STRING_H 1

/* Define if you have the <strings.h> header file.  */
#define HAVE_STRINGS_H 1

/* Define if you have the <sys/bitypes.h> header file.  */
/* #undef HAVE_SYS_BITYPES_H */

/* Define if you have the <sys/dlpi.h> header file.  */
#define HAVE_SYS_DLPI_H 1

/* Define if you have the <sys/ethernet.h> header file.  */
#define HAVE_SYS_ETHERNET_H 1

/* Define if you have the <sys/select.h> header file.  */
#define HAVE_SYS_SELECT_H 1

/* Define if you have the <sys/sockio.h> header file.  */
#define HAVE_SYS_SOCKIO_H 1

/* Define if you have the <sys/stropts.h> header file.  */
#define HAVE_SYS_STROPTS_H 1

/* Define if you have the <sys/sysctl.h> header file.  */
/* #undef HAVE_SYS_SYSCTL_H */

/* Define if you have the <sys/time.h> header file.  */
#define HAVE_SYS_TIME_H 1
