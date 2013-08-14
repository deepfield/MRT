/* 
 * $Id: acconfig.h,v 1.1.1.1 2000/08/14 18:46:09 labovit Exp $
 */

@TOP@

/* Defined if you have IPV6 support */
#undef HAVE_IPV6

/* Defined if you have SOLARIS IPV6 */
#undef SOLARIS_IPV6

/* Defined if you have WIDE IPV6 */
#undef WIDE_IPV6

/* Defined if you have INRIA IPV6 */
#undef INRIA_IPV6

/* Defined if you have NRL IPV6 */
#undef NRL_IPV6

/* Defined if RFC2292 conform */
#undef RFC2292

/* Define if you have (IPv4) IGMP support */
#undef HAVE_IGMP

/* Define if you have IPv4 multicast routing support */
#undef HAVE_MROUTING

/* Define if you have IPv6 multicast routing support */
#undef HAVE_MROUTING6

/* Define if you have old ipv6_mreq (linux only) */
#undef HAVE_IPV6MR_IFINDEX

/* Define if ipv6mr_interface is index */
#undef IPV6MR_INTERFACE_INDEX

/* Define if you have pthread library (-lpthread) */
#undef HAVE_LIBPTHREAD

/* Define if you have "struct ether_addr" */
#undef HAVE_ETHER_ADDR

/* Define if we have a phyiscal interface to the network */
#undef HAVE_PHYSICAL_INTERFACE

/* Define if we don't have these typedefs */
#undef uint8_t
#undef uint16_t
#undef uint32_t

/* Define if solaris 2.8 */
#undef SOLARIS28

/* Define if solaris 2.7 */
#undef SOLARIS27

/* Define if solaris 2.6 */
#undef SOLARIS26

/* Define if send/recvmsg will be used */
#undef USE_SENDRECVMSG

/* Define if OpenBSD */
#undef OPENBSD

/* Define if you are using gdbm */
#undef USE_GDBM

/* Define if you using berkeley db */
#undef USE_DB1

/* Define if you have pthread_attr_setscope */
#undef HAVE_PTHREAD_ATTR_SETSCOPE

/* Define if you have struct in6_addr */
#undef HAVE_STRUCT_IN6_ADDR

/* Define if you have u_char, u_int, u_short, and u_long */
#undef HAVE_U_TYPES

/* Define if you have sin6_scope_id */
#undef HAVE_SIN6_SCOPE_ID

/* Define if you have RIC QOS routing */
#undef HAVE_RIC
