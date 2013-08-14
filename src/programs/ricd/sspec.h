/*
 * $Id: sspec.h,v 1.1.1.1 2000/08/14 18:46:14 labovit Exp $
 */

#ifndef _SSPEC_H_
#define _SSPEC_H_

#if /* defined(sun) || */ defined(__NetBSD__)
#define uint8_t u_int8_t
#define uint16_t u_int16_t
#define uint32_t u_int32_t
#endif /* __NetBSD__ */

#define SSPEC_MTU_SIZE 1280

typedef struct _if_qos_t {
    uint32_t pps;	/* packet per second */
    uint32_t qos_pps;	/* qos pps */
    uint32_t ann_pps;	/* announce pps */
    uint32_t dly;	/* queue delay */
} if_qos_t;

typedef struct _link_qos_t {
    uint8_t flag:1;	/* flag */
    uint8_t pri:7;	/* priority */
    uint8_t loh;	/* link overhead */
    uint16_t rsvd;	/* pad */
    uint32_t pps;	/* packet per second */
    uint32_t dly;	/* transmission delay */
} link_qos_t;

typedef struct _area_qos_t {
    uint8_t pri;	/* priority */
    uint8_t rsvd1;	/* pad */
    uint16_t rsvd2;	/* pad */
    uint32_t ctu;	/* charging time unit */
    uint32_t bfee;	/* base fee for each ctu */
    uint32_t pfee;	/* fee per packet for each ctu */
} area_qos_t;


#define SRSVP_REQ_QOS_SIZE 28
typedef struct _req_qos_t {
    uint8_t pri;	/* priority */
    uint8_t rsvd;	/* pad */
    uint16_t mtu;	/* maximum transmission unit */
    uint32_t pps;	/* packet per second */
    uint32_t sec;	/* second */
    uint32_t cd;	/* coefficient for delay */
    uint32_t cf;	/* coefficient for fee */
    uint32_t rdly;	/* restricted delay */
    uint32_t rfee;	/* restricted fee */
} req_qos_t;

typedef struct _path_qos_t {
    uint32_t pps;	/* packet per second */
    uint32_t dly;	/* transmission delay */
} path_qos_t;

#define SSPEC_PRI_EMERGENCY     0
#define SSPEC_PRI_LEASED        1
#define SSPEC_PRI_HIGH          2
#define SSPEC_PRI_USER          3

#define SSPEC_AGPPS 4000

#endif /* _SSPEC_H_ */
