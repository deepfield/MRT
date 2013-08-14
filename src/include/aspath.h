/*
 * $Id: aspath.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef ASPATH_H
#define ASPATH_H

typedef struct _aggregator_t {
    u_short as;
    prefix_t *prefix;
} aggregator_t;

/* destination preference attribute (Internet Draft) */
typedef struct _dpa_t {
    u_short as;
    u_long value;
} dpa_t;

typedef struct _community_t {
    int len;			/* the number of community values */
    u_long *value;
} community_t;


typedef LINKED_LIST cluster_list_t;

typedef struct _aspath_segment_t {
    u_char type;		/* PA_PATH_SET | PA_PATH_SEQ */
    u_char len;
    u_short *as;		/* AS's */
} aspath_segment_t;

typedef LINKED_LIST aspath_t;


typedef struct _bgp_attr_t {
    int type;			/* protocol learned by */
    int ref_count;		/* number of routes referencing this block */
    nexthop_t *direct;		/* local address for next hop - from rib */
    gateway_t *gateway;		/* gateway learned from */
    pthread_mutex_t mutex_lock;	/* lock down structure */
    u_long tag;
    u_long options;		/* same as BGP peer options (peer->options) */

    struct _bgp_attr_t *original;
    u_long attribs;		/* mask of attributes present */

    /* manditory */
    u_char origin;		/* origin (IGP, EGP, UNKNOWN) of route */
    aspath_t *aspath;		/* BGP aspath */
    nexthop_t *nexthop;		/* next hop bgp attribute */

    /* optional -- these should really be a linked list */
    u_long multiexit;
    u_long local_pref;
    aggregator_t aggregator;
    community_t *community;
    prefix_t *originator;
    cluster_list_t *cluster_list;
    dpa_t dpa;

    LINKED_LIST *opt_trans_list;

    int nodelete;		/* don't delete nexthop, gateway, aspath,
				   dpa, and community */
    nexthop_t *nexthop4;	/* next hop for ipv4 */
#ifdef HAVE_IPV6
    nexthop_t *link_local;	/* next hop link_local for bgp4+ */
#endif				/* HAVE_IPV6 */

    LINKED_LIST *ll_withdraw;
    LINKED_LIST *ll_announce;
    int home_AS;		/* Craig uses this */
} bgp_attr_t;


#define BGP4_BIT_TEST(bits, value) BIT_TEST((bits), (1<<(value)))
#define BGP4_BIT_SET(bits, value) BIT_SET((bits), (1<<(value)))
#define BGP4_BIT_RESET(bits, value) BIT_RESET((bits), (1<<(value)))

/*
 * Bit definitions for the attribute flags byte
 */
#define	PA_FLAG_OPT	0x80	/* attribute is optional */
#define	PA_FLAG_TRANS	0x40	/* attribute is transitive */
#define	PA_FLAG_PARTIAL	0x20	/* incomplete optional, transitive attribute */
#define	PA_FLAG_EXTLEN	0x10	/* extended length flag */

#define	PA_FLAG_ALL  (PA_FLAG_OPT|PA_FLAG_TRANS|PA_FLAG_PARTIAL|PA_FLAG_EXTLEN)
#define PA_FLAG_OPTTRANS        (PA_FLAG_OPT|PA_FLAG_TRANS)


/*
 * BGP version 4 attribute type codes (the dorks moved metric!).
 */
#define	PA4_TYPE_INVALID	0
#define	PA4_TYPE_ORIGIN		1
#define	PA4_TYPE_ASPATH		2
#define	PA4_TYPE_NEXTHOP	3
#define	PA4_TYPE_METRIC		4
#define	PA4_TYPE_LOCALPREF	5
#define	PA4_TYPE_ATOMICAGG	6
#define	PA4_TYPE_AGGREGATOR	7
#define	PA4_TYPE_COMMUNITY	8
#define PA4_TYPE_ORIGINATOR_ID  9
#define PA4_TYPE_CLUSTER_LIST   10
#define PA4_TYPE_DPA            11
#define PA4_TYPE_ADVERTISER     12
#define PA4_TYPE_RCID_PATH      13
#define	PA4_TYPE_MPREACHNLRI	14
#define	PA4_TYPE_MPUNRNLRI	15
#define	PA4_TYPE_KNOWN_MAX	15

#define PA4_LEN_ORIGIN          1
#define PA4_LEN_ASPATH          2 /* */
#define PA4_LEN_NEXTHOP         4
#define PA4_LEN_METRIC          4
#define PA4_LEN_LOCALPREF       4
#define PA4_LEN_ATOMICAGG       0
#define PA4_LEN_AGGREGATOR      6
#define PA4_LEN_ORIGINATOR_ID	4
#define	PA4_LEN_CLUSTER_LIST	4 /* */
#define PA4_LEN_DPA		6
#define	PA4_LEN_COMMUNITY	4 /* */
#define	PA4_LEN_MPREACHNLRI	5 /* was 7 (old BGPMP) */
#define	PA4_LEN_MPUNRNLRI	3 /* was 5 (old BGPMP) */


/*
 * BGP4 subcodes for the AS_PATH attribute
 */
#define	PA_PATH_NOTSETORSEQ	0	/* not a valid path type */
#define	PA_PATH_SET		1
#define	PA_PATH_SEQ		2
#define	PA_PATH_MAXSEGLEN	255	/* maximum segment length */

#ifndef GET_PATH_ATTR
/*
 * Macro for retrieving attribute information from a byte stream
 */
#define	GET_PATH_ATTR(flags, code, len, cp) \
    do { \
        register u_int Xtmp; \
        Xtmp = (u_int)(*(byte *)(cp)++); \
        (flags) = Xtmp & ~((u_int)(PA_FLAG_EXTLEN)); \
        (code) = *(byte *)(cp)++; \
        if (Xtmp & PA_FLAG_EXTLEN) { \
	    Xtmp = (int)((*(byte *)(cp)++) << 8); \
	    Xtmp |= (int)(*(byte *)(cp)++); \
	    (len) = Xtmp; \
	} else { \
	     (len) = (*(byte *)(cp)++); \
	} \
    } while (0)

#endif /* GET_PATH_ATTR */

#ifndef PATH_PUT_ATTR
/*
 * Macro for inserting a path attribute header into a buffer.  The
 * extended length bit is set in the flag as appropriate.
 */
#define	PATH_PUT_ATTR(flag, code, len, cp) \
    do { \
        register u_int Xtmp; \
        Xtmp = (len); \
        if (Xtmp > 255) { \
	    *(cp)++ = (byte)((flag) | PA_FLAG_EXTLEN); \
	    *(cp)++ = (byte)(code); \
	    *(cp)++ = (byte) (Xtmp >> 8); \
	    *(cp)++ = (byte) Xtmp; \
	} else { \
	    *(cp)++ = (byte)((flag) & ~((u_int)(PA_FLAG_EXTLEN))); \
	    *(cp)++ = (byte)(code); \
	    *(cp)++ = (byte) Xtmp; \
	} \
    } while (0)
#endif /* PATH_PUT_ATTR */

#include <io.h>
#include <flist.h>
#include <bgp.h>

int bgp_get_home_AS (aspath_t * aspath);
aspath_t *munge_aspath (int len, u_char * cp);
aspath_t *aspth_from_string (char *path);
int aspath_attrlen (aspath_t * aspath);
int aspath_length (aspath_t * aspath);
u_char *unmunge_aspath (aspath_t * aspath, u_char * cp);
char *aspath_toa (aspath_t * aspath);
aspath_t * New_ASPATH ();
void Delete_ASPATH (aspath_t * aspath);
int compare_aspaths (aspath_t * aspath1, aspath_t * aspath2);
int bgp_check_aspath_loop (aspath_t * aspath, int as);
int bgp_check_aspath_in (aspath_segment_t * as_seg, int as);
aspath_t *aspath_reduce (aspath_t * aspath);
aspath_t *aspath_merge (aspath_t * aspath1, aspath_t * aspath2, aspath_t *tail);
aspath_t *aspath_copy (aspath_t * aspath);
aspath_t *aspath_append (aspath_t * result, aspath_t * aspath);
aspath_t *aspath_prepend (aspath_t * result, aspath_t * aspath);
aspath_t *aspath_prepend_as (aspath_t * result, int as);
aspath_t *aspath_remove (aspath_t *aspath, int a, int b);

/* in bgp_msg.c */
u_char *bgp_process_mrt_msg (int type, int subtype, u_char * cp, int length,
        int *family_p, gateway_t **gateway_from, gateway_t **gateway_to);
int bgp_process_update_msg (int type, int subtype,
			    u_char * value, int length,
			    gateway_t ** gateway_to,
			    bgp_attr_t ** pp_attr,
			    LINKED_LIST ** ll_with_prefixes,
			    LINKED_LIST ** ll_ann_prefixes);
int mrt_bgp_msg_type (mrt_msg_t *msg);
u_char *bgp_create_update_msg (int type, int subtype, int * size,
			       bgp_attr_t * p_bgp_route_attr,
			       LINKED_LIST * ll_ann_prefixes,
			       LINKED_LIST * ll_with_prefixes,
			       gateway_t *gateway_to);
u_char *bgp_create_update_msg2 (int type, int subtype, int * size,
			        u_char * cp, gateway_t * gateway_from, 
			        gateway_t * gateway_to);
void bgp_process_sync_msg (int type, int subtype, u_char *msg, 
			   int length,
                           int *viewno, char *filename);
void bgp_process_state_msg (int type, int subtype, u_char *msg, 
			    int length,
                            gateway_t ** gateway, u_short * old_state, 
			    u_short * new_state);
void bgp_print_attr (bgp_attr_t * attr);
void bgp_print_attr_buffer (bgp_attr_t * attr, buffer_t * buffer, int mode);
int bgp_scan_attr (char *line, bgp_attr_t *attr, trace_t *tr);
void bgp_uii_attr (uii_connection_t *uii, bgp_attr_t * attr);

/* in bgp_attr.c */
int bgp_process_update_packet (u_char * value, int length, bgp_peer_t *peer);
u_char *bgp_add_attributes (u_char * cp, int cp_len, bgp_attr_t * attr,
			    trace_t * tr);
u_char *bgp_add_attr_ipv6 (u_char * cp, int cp_len, bgp_attr_t * attr,
			    trace_t * tr);
bgp_attr_t *bgp_munge_attributes (int attrlen, u_char * cp, bgp_peer_t *peer);
bgp_attr_t *bgp_new_attr (int type);
bgp_attr_t *bgp_ref_attr (bgp_attr_t * attr);
bgp_attr_t *bgp_copy_attr (bgp_attr_t * attr);
char *bgp_attr_toa (bgp_attr_t * attr);
int bgp_compare_attr (bgp_attr_t * a1, bgp_attr_t * a2);
void bgp_deref_attr (bgp_attr_t * attr);
void bgp_trace_attr2 (bgp_attr_t * attr, trace_t * tr);
dpa_t *New_DPA (int as, u_long value);
int bgp_create_pdu (LINKED_LIST * ll_with_prefixes,
		    LINKED_LIST * ll_ann_prefixes,
		    bgp_attr_t * attr, int safi,
		/* these argument are used by bgp daemon */
		    bgp_peer_t * peer, void (*fn) (),
		/* these argument are used by tools like route_atob */
		    u_char * pdu_memory, int pdu_len, int bgp4plus_version);
void bgp_trace_attr (u_long flag, trace_t *tr, bgp_attr_t *attr, int type);

#include "community.h"
#endif /* ASPATH_H */
