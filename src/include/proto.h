/*
 * $Id: proto.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef _PROTO_H
#define _PROTO_H

#define PROTO_MIN		1
#define PROTO_CONNECTED		1	/* directly connected interface */
#define PROTO_STATIC		2	/* staticly connected route */
#define PROTO_KERNEL		3       /* obtained from the kernel */
#define PROTO_RIP		4
#define PROTO_RIPNG		6
#define PROTO_OSPF		7
#define PROTO_PIM		8
#define PROTO_PIMV6		9
#define PROTO_IGMP		10
#define PROTO_IGMPV6		11	/* part of icmp v6 */
#define PROTO_DVMRP		12

#define PROTO_BGP		16
#define PROTO_MAX		16

#endif /* _PROTO_H */

