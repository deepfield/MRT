/*
 * $Id: srsvp.h,v 1.1.1.1 2000/08/14 18:46:14 labovit Exp $
 */

#ifndef _SRSVP_H_
#define _SRSVP_H_

#include "mrt.h"
#include "sspec.h"
#include "hqlip.h"

#define SRSVP_FLOW_HASH_SIZE 1023

#define SRSVP_TCP_PORT 7095
#define SRSVP_MSG_HDR_SIZE 8
#define SRSVP_MSG_SIZE 16384

#define SRSVP_OPEN_RETRY     5
#define SRSVP_OPEN_RETRY_MAX 4 /* retry timer exponentially grows */
#define SRSVP_OPEN_TIMEOUT 15
#define SRSVP_KEEP_ALIVE   10

#define SRSVP_MSG_VERSION 2

#define SRSVP_MSG_PATH       1
#define SRSVP_MSG_RESV       2
/* #define SRSVP_MSG_PATH_ERR   3 */
/* #define SRSVP_MSG_RESV_ERR   4 */
#define SRSVP_MSG_PATH_TEAR  5
#define SRSVP_MSG_RESV_TEAR  6
#define SRSVP_MSG_RESV0     98 /* internal */
#define SRSVP_MSG_RESV1     99 /* internal */

#define SRSVP_OBJ_SESSION       1
#define SRSVP_OBJ_RSVP_HOP      3
#define SRSVP_OBJ_SENDERT      11
#define SRSVP_OBJ_ERR_SPEC      6
#define SRSVP_OBJ_SENDER_TSPEC 12
#define SRSVP_OBJ_FLOW_SPEC     9
#define SRSVP_OBJ_PQC_INFO     16
#define SRSVP_OBJ_FAQ_INFO     17
#define SRSVP_OBJ_POLICYD      14

#define SRSVP_OBJ_HDR_SIZE   4

#define SRSVP_SENDER_CHARGE   0x80
#define SRSVP_RECEIVER_CHARGE 0x40

#define SRSVP_GET_HEADER(version, flags, type, ttl, charge, len, cp) \
    do { \
	int Xbyte; \
        MRT_GET_BYTE((Xbyte), (cp)); \
	(version) = (Xbyte >> 4); \
	(flags) = (Xbyte & 0x0f); \
        MRT_GET_BYTE((type), (cp)); \
	cp += 2; \
        MRT_GET_BYTE((ttl), (cp)); \
        MRT_GET_BYTE((charge), (cp)); \
        MRT_GET_SHORT((len), (cp)); \
    } while (0)

#define SRSVP_PEEK_HDRLEN(len, cp) \
    do { \
        int Xlen; \
        Xlen = ((int)*(u_char *)((cp) + 6)) << 8; \
        Xlen |= (int)*(u_char *)((cp) + 7); \
        (len) = Xlen; \
    } while (0)
  
#define SRSVP_PEEK_HDRTYPE(type, cp)       ((type) = *(u_char *)((cp) + 1))


#define SRSVP_OBJ_HDR_SIZE 4
typedef struct _srsvp_object_t {
    int len;	  /* including the header */
    short class;  /* afi or others */
    short type;
    char *data;
} srsvp_object_t;


#define SRSVP_GET_OBJHDR(len, class, type, cp) \
    do { \
        MRT_GET_SHORT((len), (cp)); \
        MRT_GET_BYTE((class), (cp)); \
        MRT_GET_BYTE((type), (cp)); \
    } while (0)

#define SRSVP_PUT_OBJHDR(len, class, type, cp) \
    do { \
        MRT_PUT_SHORT((len), (cp)); \
        MRT_PUT_BYTE((class), (cp)); \
        MRT_PUT_BYTE((type), (cp)); \
    } while (0)


typedef struct _srsvp_interface_t {
    prefix_t *prefix;
    interface_t *interface;
    u_long flags;
    LINKED_LIST *ll_neighbors;
    int tcp_sockfd;
    struct _srsvp_neighbor_t *myself;
    int qalg;
    int qlimit;
} srsvp_interface_t;


#define SRSVP_NEIGHBOR_DELETED 0x01
#define SRSVP_OPEN_IN_PROGRESS 0x02
#define SRSVP_OPEN_RETRYING    0x04
#define SRSVP_NEIGHBOR_ROUTER  0x08
#define SRSVP_NEIGHBOR_CONNECTED 0x10

typedef struct _srsvp_neighbor_t {
    prefix_t *prefix;
    srsvp_interface_t *vif;
    time_t ctime;
    time_t utime;
    u_long flags;
    mtimer_t *open_timeout;     /* neighbor timeout */
    mtimer_t *open_retry;       /* open retry timer */
    mtimer_t *keep_alive;       /* check peridodically */
    int sockfd;
    trace_t *trace;
    schedule_t *schedule;
#ifndef HAVE_LIBPTHREAD
    pthread_mutex_t send_mutex_lock; /* it's for non-thread, through */
    LINKED_LIST *send_queue;	/* for non-blocking send */
#endif /* HAVE_LIBPTHREAD */
    u_char buffer[SRSVP_MSG_SIZE * 2];
    u_char *start_ptr, *read_ptr;
    u_char *packet;
    int num_packets_recv;
    int num_packets_sent;
    int num_session_up;
    int lih;
} srsvp_neighbor_t;


typedef struct _srsvp_t {
    int family;
    interface_bitset_t interface_mask;	/* mask of interfaces configed for */
    trace_t *trace;
    schedule_t *schedule;
    LINKED_LIST *ll_srsvp_interfaces;	/* enabled srsvp interfaces */
    srsvp_interface_t *srsvp_interfaces[MAX_INTERFACES];
    mrt_hash_table_t *flows;
} srsvp_t;


#define SRSVP_MSG_ERR_UNREACH   0x80000000
#define SRSVP_MSG_ERR_BANDWIDTH 0x40000000
#define SRSVP_MSG_ERR_DELAY     0x20000000
#define SRSVP_MSG_ERR_CHARGE    0x10000000
#define SRSVP_MSG_ERR_FLOWSPEC  0x08000000 /* not in draft */
#define SRSVP_MSG_ERR_POLICY    0x04000000 /* not in draft */
#define SRSVP_MSG_ERR_NYSUPPORT 0x02000000 /* not in draft */

#define SRSVP_LEAFF_RESV0 0x0001
#define SRSVP_LEAFF_RESV1 0x0002
#define SRSVP_LEAFF_READY 0x0004

typedef struct _srsvp_leaf_t {
    srsvp_neighbor_t *neighbor;
    u_long flags;
    req_qos_t *req_qos;
} srsvp_leaf_t;


#define SRSVP_FLOWF_SENDER  0x0100 /* low 8 bits reserved */
#define SRSVP_FLOWF_RECVER  0x0200
#define SRSVP_FLOWF_RESV0   0x0400
#define SRSVP_FLOWF_RESV1   0x0800
#define SRSVP_FLOWF_READY   0x1000
#define SRSVP_FLOWF_DELETED 0x2000

typedef struct _srsvp_flow_t {
    prefix_t *destin;
    int dport;
    int proto;
    prefix_t *sender;
    int sport;
    req_qos_t *req_qos;
    req_qos_t *sender_tspec;
    LINKED_LIST *ll_downstreams;
    srsvp_neighbor_t *upstream;
    u_long flags;
    u_long errcode;
} srsvp_flow_t;

#endif /* _SRSVP_H_ */
