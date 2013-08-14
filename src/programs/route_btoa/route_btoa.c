/* 
 * $Id: route_btoa.c,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
 */

#include <mrt.h>
#include <aspath.h>
#include <bgp.h>

/* globals */
#define OUTPUT_MODE_TEXT 0
#define OUTPUT_MODE_MACHINE1 1
#define OUTPUT_MODE_MACHINE2 2	/* masaki uses this */
#define OUTPUT_MODE_RAW 3
static int output_mode = OUTPUT_MODE_TEXT;
static char time_str[MAXLINE];

static io_t *IO;
static trace_t *default_trace;
static buffer_t *stdbuf;

void process_input ();

static void 
print_bgp_msg (mrt_msg_t * msg)
{
    gateway_t *gateway_to = NULL;
    gateway_t *gateway_from = NULL;
    bgp_attr_t *p_attr;
    LINKED_LIST *ll_with_prefixes, *ll_ann_prefixes;
    u_short *pref;
    u_short old_state, new_state;
    u_char zero[16];
    int family = AF_INET;
    u_char *cp = msg->value;
    u_char *cpend = msg->value + msg->length;
#ifdef HAVE_IPV6
    int bgp4plus = DEFAULT_BGP4PLUS_VERSION;
#endif /* HAVE_IPV6 */
    int bgp_type = 0;

    p_attr = NULL;
    ll_with_prefixes = NULL;
    ll_ann_prefixes = NULL;
    pref = NULL;
    memset (zero, 0, 16);

    if ((msg->type == MSG_PROTOCOL_BGP4MP && 
	    msg->subtype == BGP4MP_STATE_CHANGE) ||
        (msg->type != MSG_PROTOCOL_BGP4MP &&
	    msg->subtype == MSG_BGP_STATE_CHANGE)) {

	bgp_process_state_msg (msg->type, msg->subtype, 
			       msg->value, msg->length,
			       &gateway_to, &old_state, &new_state);
	if (output_mode == OUTPUT_MODE_TEXT || 
	    output_mode == OUTPUT_MODE_RAW) {
	    buffer_printf (stdbuf, "PEER: %g\n", gateway_to);
	    buffer_printf (stdbuf, "STATE: %s/%s\n", sbgp_states[old_state], 
				      sbgp_states[new_state]);
	}
	else if (output_mode == OUTPUT_MODE_MACHINE1 || 
		 output_mode == OUTPUT_MODE_MACHINE2) {
	  buffer_printf (stdbuf, "%s|STATE|%a|%d|%d|%d\n",
		  time_str, gateway_to->prefix, 
		  gateway_to->AS, old_state, new_state);
	}
	return;
    }
    else if ((msg->type == MSG_PROTOCOL_BGP4MP && 
	    msg->subtype == BGP4MP_SNAPSHOT) ||
        (msg->type != MSG_PROTOCOL_BGP4MP &&
	    msg->subtype == MSG_BGP_SYNC)) {
	if (output_mode == OUTPUT_MODE_TEXT || 
	    output_mode == OUTPUT_MODE_RAW) {

	    int viewno;
	    char filename[MAXLINE];
	    bgp_process_sync_msg (msg->type, msg->subtype, 
				  msg->value, msg->length,
				  &viewno, filename);
	    buffer_printf (stdbuf, "VIEW: %d\n", viewno);
	    buffer_printf (stdbuf, "FILE: %s\n", filename);
	}
	return;
    }


    if ((msg->type == MSG_PROTOCOL_BGP4MP && (
	    msg->subtype == BGP4MP_MESSAGE || 
   	    msg->subtype == BGP4MP_MESSAGE_OLD)) ||
        (msg->type == MSG_PROTOCOL_BGP
	    || msg->type == MSG_PROTOCOL_BGP4PLUS 
	    || msg->type == MSG_PROTOCOL_BGP4PLUS_01)) {
	/* OK */
    }
    else {
	fprintf (stderr, 
		 "*** ERROR *** Unknown message type: %d, subtype: %d\n", 
		 msg->type, msg->subtype);
	return;
    }

    cp = bgp_process_mrt_msg (msg->type, msg->subtype, msg->value, 
			      msg->length, 
			      &family, &gateway_from, &gateway_to);
    if (cp == NULL)
	return;

    if (msg->type == MSG_PROTOCOL_BGP4MP) {
	assert (msg->subtype == BGP4MP_MESSAGE || 
		msg->subtype == BGP4MP_MESSAGE_OLD);
	bgp_type = mrt_bgp_msg_type (msg);
	BGP_SKIP_HEADER (cp);
    }
    else if (msg->subtype == MSG_BGP_UPDATE)
	 bgp_type = BGP_UPDATE;
    else if (msg->subtype == MSG_BGP_OPEN)
	 bgp_type = BGP_OPEN;
    else if (msg->subtype == MSG_BGP_NOTIFY)
	 bgp_type = BGP_NOTIFY;
    else if (msg->subtype == MSG_BGP_KEEPALIVE)
	 bgp_type = BGP_KEEPALIVE;

    if (bgp_type == BGP_UPDATE) {
	
        /* process bgp update */
        bgp_process_update_msg (msg->type, msg->subtype, 
			        msg->value, msg->length,
			        &gateway_to, &p_attr,
			        &ll_with_prefixes, &ll_ann_prefixes);
#ifdef HAVE_IPV6
	if (msg->type == MSG_PROTOCOL_BGP4MP) {
   	    if (msg->subtype == BGP4MP_MESSAGE)
                bgp4plus = 1;
	}
	else if (msg->type == MSG_PROTOCOL_BGP4PLUS_01) {
            bgp4plus = 1;
        }
#endif /* HAVE_IPV6 */
    }

    if (output_mode == OUTPUT_MODE_TEXT ||
            output_mode == OUTPUT_MODE_RAW) {
	if (gateway_from)
            buffer_printf (stdbuf, "FROM: %g\n", gateway_from);
	if (gateway_to)
            buffer_printf (stdbuf, "TO: %g\n", gateway_to);
    }

#define FMT "  %02d\t"

    if (bgp_type == BGP_OPEN) {
	int version, as, holdtime, optlen;
	u_long id;
	char str[MAXLINE];
	int i;

	BGP_GET_BYTE (version, cp);
	BGP_GET_SHORT (as, cp);
	BGP_GET_SHORT (holdtime, cp);
	BGP_GET_NETLONG (id, cp);
	BGP_GET_BYTE (optlen, cp);
        if (output_mode == OUTPUT_MODE_RAW) {
	    buffer_printf (stdbuf, "DATA:\n");
	    buffer_printf (stdbuf, FMT "%d\t# Version\n", 1, version);
	    buffer_printf (stdbuf, FMT "%d\t# My Autonomous System\n", 2, as);
	    buffer_printf (stdbuf, FMT "%d\t# Hold Time\n", 2, holdtime);
	    buffer_printf (stdbuf, FMT "%s\t# BGP Identifier\n", 4, 
			inet_ntop (AF_INET, &id, str, sizeof str));
	    buffer_printf (stdbuf, FMT "%d\t# Opt Parm Len\n", 1, optlen);
	    for (i = 0; i < optlen; i++) {
		int uval;
		BGP_GET_BYTE (uval, cp);
		buffer_printf (stdbuf, FMT "0x%02x\n", 1, uval);
	    }
	}
        else if (output_mode == OUTPUT_MODE_TEXT) {
	    buffer_printf (stdbuf, "VERSION: %d\n", version);
	    buffer_printf (stdbuf, "AS: %d\n", as);
	    buffer_printf (stdbuf, "HOLD_TIME: %d\n", holdtime);
	    buffer_printf (stdbuf, "ID: %s\n", 
			   inet_ntop (AF_INET, &id, str, sizeof str));
	    buffer_printf (stdbuf, "OPT_PARM_LEN: %d\n", optlen);
	    if (optlen > 0) {
	        /* XXX*/
	    }
	}
    }
    else if (bgp_type == BGP_KEEPALIVE) {
	/* nothing */
    }
    else if (bgp_type == BGP_NOTIFY) {
	int code, subcode;
	int len, i;

	BGP_GET_BYTE (code, cp);
	BGP_GET_BYTE (subcode, cp);
	len = cpend - cp;
        if (output_mode == OUTPUT_MODE_RAW) {
	    buffer_printf (stdbuf, "DATA:\n");
	    buffer_printf (stdbuf, FMT "%d\t# Error code\n", 1, code);
	    buffer_printf (stdbuf, FMT "%d\t# Error subcode\n", 1, subcode);
	    for (i = 0; i < len; i++) {
		int uval;
		BGP_GET_BYTE (uval, cp);
		buffer_printf (stdbuf, FMT "0x%02x\n", 1, uval);
	    }
	}
        else if (output_mode == OUTPUT_MODE_TEXT) {
	    buffer_printf (stdbuf, "CODE: %d/%d\n", code, subcode);
	    if (len > 0) {
	        /* XXX*/
	    }
	}
    }

    if (output_mode == OUTPUT_MODE_RAW) {
 	u_char *stop;
	int len;
	u_char addr[16];
	char str[MAXLINE];

		buffer_printf (stdbuf, "DATA:\n");

		BGP_GET_SHORT (len, cp);
		buffer_printf (stdbuf, FMT "%d\t# Unfeasible Routes Length\n", 
			       2, len);
		stop = cp + len;
    		while (cp < stop) {
		    int bitlen;
        	    struct in_addr dest;
		    u_char *here = cp;

		    BGP_GET_BITCOUNT (bitlen, cp);
		    BGP_GET_PREFIX (bitlen, &dest, cp);
		    buffer_printf (stdbuf, FMT "%s/%d\t# Withdrawn Route\n", 
				   cp - here,
			           inet_ntop (AF_INET, &dest, str, sizeof str), 
			           bitlen);
    		}

		BGP_GET_SHORT (len, cp);
		buffer_printf (stdbuf, FMT 
			       "%d\t# Total Path Attribute Length\n", 2, len);
		stop = cp + len;
    		while (cp < stop) {
		    int flags;
		    int code;
		    int len, i;

		    BGP_GET_BYTE (flags, cp);
		    buffer_printf (stdbuf, FMT "0x%02x\t"
			    "# Attribute Flags (O|T|P|E|R|R|R|R)\n",
			    1, flags);
		    BGP_GET_BYTE (code, cp);
		    buffer_printf (stdbuf, FMT 
			    "%d\t# Attribute Type Code (%d = %s)\n", 
			    1, code, code, bgptype2string (code));
		    if (flags & PA_FLAG_EXTLEN) {
		        BGP_GET_SHORT (len, cp);
		        buffer_printf (stdbuf, "  +%02d %d\t# Length\n", 
				       2, len);
		    }
		    else {
		        BGP_GET_BYTE (len, cp);
		        buffer_printf (stdbuf, FMT "%d\t# Length\n", 1, len);
		    }

		if (len > 0) {
		    u_long uval;
		    int as;
		    u_char *stop = cp + len;
#ifdef HAVE_IPV6
		    int family, subfamily, nhalen, nsnpa;
#endif /* HAVE_IPV6 */

		    switch (code) {
		    case PA4_TYPE_ORIGIN:
			BGP_GET_BYTE (uval, cp);
		        buffer_printf (stdbuf, FMT "%d\t"
				"# Value (0 - IGP, 1 - BGP, 2 - INCOMPLETE)\n",
				1, uval);
			break;
		    case PA4_TYPE_ASPATH:
			while (cp < stop) {
			    int seg_type, seg_len, as;

			    BGP_GET_BYTE (seg_type, cp);
		            buffer_printf (stdbuf, FMT 
				    "%d\t# Path Segment Type "
				    "(1 - AS_SET, 2 - AS_SEQUENCE)\n", 
				    1, seg_type);
			    BGP_GET_BYTE (seg_len, cp);
		            buffer_printf (stdbuf, FMT 
				    "%d\t# Path Segment Length\n",
				    1, seg_len);
			    while (seg_len-- > 0) {
			        BGP_GET_SHORT (as, cp);
		                buffer_printf (stdbuf, FMT 
				    	"%d\t# Path Segment Value\n", 
					2, as);
			    }
			}
			break;
		    case PA4_TYPE_NEXTHOP:
		    case PA4_TYPE_ORIGINATOR_ID:
			BGP_GET_DATA (addr, 4, cp);
			buffer_printf (stdbuf, FMT "%s\t# Address\n", 
			    4, inet_ntop (AF_INET, addr, str, sizeof str));
			break;
		    case PA4_TYPE_METRIC:
		    case PA4_TYPE_LOCALPREF:
			BGP_GET_LONG (uval, cp);
			buffer_printf (stdbuf, FMT "%d\t# Value\n", 4, uval);
			break;
		    case PA4_TYPE_ATOMICAGG:
			/* No values */
			break;
		    case PA4_TYPE_AGGREGATOR:
			BGP_GET_SHORT (as, cp);
			buffer_printf (stdbuf, FMT "%d\t# AS Number\n", 2, as);
			BGP_GET_DATA (addr, 4, cp);
			buffer_printf (stdbuf, FMT "%s\t# IP Address\n", 4,
			    inet_ntop (AF_INET, addr, str, sizeof str));
			break;
		    case PA4_TYPE_CLUSTER_LIST:
		    case PA4_TYPE_COMMUNITY:
			while (cp < stop) {
			    BGP_GET_LONG (uval, cp);
			    buffer_printf (stdbuf, FMT "%d\t# Value\n", 
					   4, uval);
			}
			break;
		    case PA4_TYPE_DPA:
			BGP_GET_SHORT (as, cp);
			buffer_printf (stdbuf, FMT "%d\t# AS Number\n", 2, as);
			BGP_GET_LONG (uval, cp);
			buffer_printf (stdbuf, FMT "%d\t# Value\n", 4, uval);
			break;
#ifdef HAVE_IPV6
		    case PA4_TYPE_MPUNRNLRI:
			BGP_GET_SHORT (family, cp);
			buffer_printf (stdbuf, FMT "%d\t# Family\n", 2, family);
			BGP_GET_BYTE (subfamily, cp);
			buffer_printf (stdbuf, FMT "%d\t# Subfamily\n", 
				       1, subfamily);
			if (bgp4plus == 0) {
			    BGP_GET_SHORT (len, cp);
			    buffer_printf (stdbuf, FMT "%d\t# Length\n", 
					   2, len);
			}
			while (cp < stop) {
        		    int bitlen;
		    	    u_char *here = cp;

        		    BGP_GET_BITCOUNT (bitlen, cp);
        		    BGP_GET_PREFIX6 (bitlen, addr, cp);
		    	    buffer_printf (stdbuf, FMT "%s/%d\t# Route\n", 
				    cp - here,
			    	    inet_ntop (AF_INET6, addr, str, sizeof str),
				    bitlen);
			}
			break;
		    case PA4_TYPE_MPREACHNLRI:
			BGP_GET_SHORT (family, cp);
			buffer_printf (stdbuf, FMT "%d\t# Family\n", 2, family);
			BGP_GET_BYTE (subfamily, cp);
			buffer_printf (stdbuf, FMT "%d\t# Subfamily\n", 1, 
				       subfamily);
			BGP_GET_BYTE (nhalen, cp);
			buffer_printf (stdbuf, FMT 
				"%d\t# Next Hop Address Length\n", 
				1, nhalen);
			while (nhalen >= 16) {
			    BGP_GET_DATA (addr, 16, cp);
			    buffer_printf (stdbuf, FMT "%s\t# Next Hop (16)\n",
				16,
			        inet_ntop (AF_INET6, addr, str, sizeof str));
			    nhalen -= 16;
			}
			BGP_GET_BYTE (nsnpa, cp);
			buffer_printf (stdbuf, FMT 
				"%d\t# Number of SNPAs (skip SNPAs)\n", 
				1, nsnpa);
			/* skip SNPAs */
        		for (i = 0; i < (u_int) nsnpa; i++) {
            		    BGP_GET_BYTE (nhalen, cp);
            		    cp += (nhalen + 1) >> 1;
        		}

			if (bgp4plus == 0) {
			    BGP_GET_SHORT (len, cp);
			    buffer_printf (stdbuf, FMT 
				    "%d\t# Length (old BGP4MP)\n", 
				    2, len);
			}
			while (cp < stop) {
        		    int bitlen;
			    u_char *here = cp;

        		    BGP_GET_BITCOUNT (bitlen, cp);
        		    BGP_GET_PREFIX6 (bitlen, addr, cp);
		    	    buffer_printf (stdbuf, FMT 
				    "%s/%d\t# Route\n", cp - here,
			    	    inet_ntop (AF_INET6, addr, str, sizeof str),
				    bitlen);
			}
			break;
#endif /* HAVE_IPV6 */
        	    case PA4_TYPE_ADVERTISER:
        	    case PA4_TYPE_RCID_PATH:
		    default:
			for (i = 0;;) {
			    BGP_GET_BYTE (uval, cp);
			    buffer_printf (stdbuf, FMT "0x%02x\n", 1, uval);
			    if (++i >= len)
			        break;
		        }
			break;
		    }
		}
	        }

    		while (cp < cpend) {
		    int bitlen;
		    u_char *here = cp;

		    BGP_GET_BITCOUNT (bitlen, cp);
		    BGP_GET_PREFIX (bitlen, addr, cp);
		    buffer_printf (stdbuf, FMT "%s/%d\t# Announce Route\n", 
			    cp - here,
			    inet_ntop (AF_INET, addr, str, sizeof str),
			    bitlen);
    		}
	}
        else if (output_mode == OUTPUT_MODE_TEXT) {

    	        /* print attributes in both cases
                   because sometimes withdraw has some, 
		   which is strange, though */
    	        if (p_attr) {
      		    bgp_print_attr (p_attr);
    	        }

    	        if (ll_ann_prefixes) {
		    buffer_printf (stdbuf, "ANNOUNCE\n");
		    if (msg->subtype == MSG_BGP_PREF_UPDATE)
	    	        print_pref_prefix_list_buffer (ll_ann_prefixes, pref,
						       stdbuf);
		    else
	    	        print_prefix_list_buffer (ll_ann_prefixes, stdbuf);
    	        }
    	        if (ll_with_prefixes) {
		    buffer_printf (stdbuf, "WITHDRAW\n");
		    print_prefix_list_buffer (ll_with_prefixes, stdbuf);
    	        }
        }

    if (ll_ann_prefixes == NULL && ll_with_prefixes == NULL)
	return;

    if (output_mode == OUTPUT_MODE_MACHINE1 || 
	output_mode == OUTPUT_MODE_MACHINE2) {

	prefix_t *prefix;
	char *attr_string;

	if (ll_ann_prefixes) {
	    attr_string = bgp_attr_toa (p_attr);
	    LL_Iterate (ll_ann_prefixes, prefix) {
		if (output_mode == OUTPUT_MODE_MACHINE2) {
		    char *cp = attr_string;
		    if ((cp = strchr (cp, '|')) != NULL &&
			(cp = strchr (cp+1, '|')) != NULL)
			*cp = '\0';
		}
		if (p_attr->gateway)
		    buffer_printf (stdbuf, "%s|A|%a|%d|%p|%s\n",
			    time_str, p_attr->gateway->prefix,
			    p_attr->gateway->AS, prefix, attr_string);
		else
		    buffer_printf (stdbuf, "%s|A|||%p|%s\n",
			    time_str, prefix, attr_string);
	    }
	}
	if (ll_with_prefixes) {
	    LL_Iterate (ll_with_prefixes, prefix) {
		if (p_attr && p_attr->gateway)
		    buffer_printf (stdbuf, "%s|W|%a|%d|%p\n",
		        time_str, p_attr->gateway->prefix,
		        p_attr->gateway->AS, prefix);
		else
		    buffer_printf (stdbuf, "%s|W|||%p\n", time_str, prefix);
	    }
	}
	///return; No!
    }

    if (p_attr)
      bgp_deref_attr (p_attr);
    if (ll_with_prefixes)
	LL_Destroy (ll_with_prefixes);
    if (ll_ann_prefixes)
	LL_Destroy (ll_ann_prefixes);
}


static void
print_msg_hdr (mrt_msg_t *msg)
{
    char *stime, **cpp;

    if (output_mode == OUTPUT_MODE_TEXT || output_mode == OUTPUT_MODE_RAW) {
	static int first = 1;
	if (first) {
	    first = 0;
	}
	else {
	    buffer_printf (stdbuf, "\n");
	}
#ifdef NT
	stime = my_strftime (msg->tstamp, "%m/%d/%Y");
#else
	stime = my_strftime (msg->tstamp, "%D %T");
#endif /* NT */
	buffer_printf (stdbuf, "TIME: %s\n", stime);
	buffer_printf (stdbuf, "TYPE: %s", S_MRT_MSG_TYPES[msg->type]);
	if ((cpp = S_MRT_MSG_SUBTYPES[msg->type]) != NULL)
	    buffer_printf (stdbuf, "/%s", cpp[msg->subtype]);
        if (msg->type == MSG_PROTOCOL_BGP4MP && (
		(msg->subtype == BGP4MP_MESSAGE || 
		 msg->subtype == BGP4MP_MESSAGE_OLD))) {
	    int bgp_type;
	    bgp_type = mrt_bgp_msg_type (msg);
	    buffer_printf (stdbuf, "/%s", bgpmessage2string (bgp_type));
	}
	buffer_printf (stdbuf, "\n");
	Delete (stime);
    }
    else if (output_mode == OUTPUT_MODE_MACHINE1 || 
	     output_mode == OUTPUT_MODE_MACHINE2) {
	if (output_mode == OUTPUT_MODE_MACHINE2) {
	    char *cp;
            strcpy (time_str, S_MRT_MSG_TYPES[msg->type]);
	    /* BGP4+(1) -> BGP4+ */
	    if ((cp = strchr (time_str, '(')) != NULL)
		*cp = '\0';
	    strcat (time_str, "|");
	    cp = my_strftime (msg->tstamp, "%D %T");
	    strcat (time_str, cp);
	    Delete (cp);
	}
	else {
	    /* leave a message in time_str to use later */
            sprintf (time_str, "%s|%lu", S_MRT_MSG_TYPES[msg->type],
		         (u_long) msg->tstamp);
	}
    }
}


/*
 * 2  view # | 
 * 
 *  4 prefix | 1 mask | status (VRTS_SUPPRESS) | 4 time originated | 
 *  4 len | attributes  
 */

void print_routing_table_msg (mrt_msg_t *msg) {
  char *attr_string;
  u_char *cp = msg->value;
  u_char *end_cp = msg->value + msg->length;
  int mask, status;
  int view, attrlen, seq_num, peer_as;
  time_t originated;
  bgp_peer_t *peer;
  bgp_attr_t *attr;
  gateway_t *gateway;
  prefix_t *prefix;
  /* char *_sorigins[] = {"i", "e", "?", "a"}; */
  /* char date[MAXLINE]; */
  /* time_t t; */
  int afi = AFI_IP;
  int family = AF_INET;
  int plen = 4;
  char peer_ip[16], addr[16];

  BGP_GET_SHORT (view, cp);
  BGP_GET_SHORT (seq_num, cp);
if (output_mode != OUTPUT_MODE_MACHINE1 &&
        output_mode != OUTPUT_MODE_MACHINE2) {
  buffer_printf (stdbuf, "VIEW: %d\n", view);
  buffer_printf (stdbuf, "SEQUENCE: %d\n", seq_num);
}

  afi = msg->subtype;
  if (afi != AFI_IP && afi != AFI_IP6) {
     fprintf (stderr, "unknown afi: %d\n", afi);
     exit (1);
  }
  if (afi == AFI_IP6) {
    family = AF_INET6;
    plen = 16;
  }

  peer = create_fake_peer ();

  while (end_cp - cp >= 16 /* min */) {
    BGP_GET_DATA (addr, plen, cp);
    BGP_GET_BYTE (mask, cp);
    BGP_GET_BYTE (status, cp);
    BGP_GET_LONG (originated, cp);
    BGP_GET_DATA (peer_ip, plen, cp);	/* gateway */
    BGP_GET_SHORT (peer_as, cp);	/* gateway */
    prefix = New_Prefix (family, peer_ip, plen * 8);
    gateway = add_gateway (prefix, peer_as, NULL);
    Deref_Prefix (prefix);

    BGP_GET_SHORT (attrlen, cp);

/*
 * There was a bug up to 2.0.1 that put the length less by 4 bytes
 * So, when reading data, if reading pointer reaches the end, read 4 bytes.
 */
/* this is not perfect, but for now it would be OK 
   since an attribute usually takes more than 4 bytes */
if (end_cp + 4 == (cp + attrlen)) {
    read (IO->in.fd, end_cp, 4);
    msg->length += 4;
    end_cp += 4;
    IO->in_bytes += 4;
    trace (TR_WARN, IO->trace, "Bug detected 4 bytes read\n");
}
    prefix = New_Prefix (family, addr, mask);

    peer->attr = NULL;
    bgp_munge_attributes (attrlen, cp, peer);
    if (peer->attr == NULL)
	continue;
    cp += attrlen;
    attr = peer->attr;
    attr->gateway = gateway;

if (output_mode == OUTPUT_MODE_MACHINE1 ||
        output_mode == OUTPUT_MODE_MACHINE2) {

    attr_string = bgp_attr_toa (attr);
    if (output_mode == OUTPUT_MODE_MACHINE2) {
        char *cp = attr_string;
        if ((cp = strchr (cp, '|')) != NULL &&
            (cp = strchr (cp+1, '|')) != NULL)
            *cp = '\0';
    }
    buffer_printf (stdbuf, "%s|B|%a|%d|%p|%s\n", time_str, 
			gateway->prefix, gateway->AS,
                        prefix, attr_string);
}
else {
    char *stime;

    buffer_printf (stdbuf, "PREFIX: %p\n", prefix);
    buffer_printf (stdbuf, "FROM: %g\n", gateway);
    stime = my_strftime (originated, "%D %T");
    buffer_printf (stdbuf, "ORIGINATED: %s\n", stime);
    Delete (stime);
    bgp_print_attr_buffer (attr, stdbuf, 0);
    if (status != 0)
        buffer_printf (stdbuf, "STATUS: 0x%x\n", status);

#ifdef notdef
    t = msg->tstamp - originated;
    if (t / 3600 > 99)
      sprintf (date, "%02lddy%02ldhr", 
	       t / (3600 * 24), (t % (3600 * 24)) / 3600);
    else
      sprintf (date, "%02ld:%02ld:%02ld", 
	       t / 3600, (t / 60) % 60, t % 60);

    if (attr) 
      buffer_printf (stdbuf, "B   20  %-15s %-15p   hme0  %A  %s\n",
	      date, prefix, attr->aspath, _sorigin[attr->origin]);
#endif
}

    Deref_Prefix (prefix);
    if (attr) 
      bgp_deref_attr (attr);
  }

  if (end_cp != cp) {
      trace (TR_WARN, IO->trace, "Garbage %d bytes remained\n", end_cp - cp);
  }
  Delete (peer);
}


void 
main (int argc, char *argv[])
{
    int c;
    extern char *optarg;	/* getopt stuff */ 
    extern int optind;		/* getopt stuff */ 
    char *usage = "Usage: route_btoa [-m] [(-i|-r)] [input_binary_file(s)] \n"; 
    int errs; 
    int input_mode = 0;
    
    default_trace = New_Trace ();

    init_mrt (default_trace);

 
    IO = New_IO (default_trace);
    io_set (IO, IO_INFILE, "stdin", NULL);
 

    while ((c = getopt (argc, argv, "if:o:mMuvh")) != -1)
      switch (c) {
	/* machine parseable format */
      case 'u':
	output_mode = OUTPUT_MODE_RAW;
	break;
      case 'M':
	output_mode = OUTPUT_MODE_MACHINE2;
	break;
      case 'm':
	output_mode = OUTPUT_MODE_MACHINE1;
	break;
      case 'i':
      case 'f':
	input_mode = 1;
	break;
      case 'r':
	if (io_set (IO, IO_INMSGQ, (char *) (optarg), NULL) < 0) {
	  if (optarg) 
	    fprintf (stderr, "\nError setting infile %s\n", optarg);
	  else
	    fprintf (stderr, "\nError -- no infile given!\n");
	  errs++;
	}
	input_mode = 2;
	break;
      case 'v':
	set_trace (default_trace, TRACE_FLAGS, TR_ALL,
		   TRACE_LOGFILE, "stdout", NULL);
	break;
      case 'h':
	fprintf (stderr, usage);
	fprintf (stderr, "Machine output (-m flag):\n");
	fprintf (stderr, "Protocol|Time|Type|PeerIP|PeerAS|Prefix|<update dependant>\n");
	fprintf (stderr, "  (for BGP announcements) ASPATH|Origin|NextHop|LocPref|MED|");
	fprintf (stderr, "Community|AtomicAGG|Aggregator\n");
	exit (0);
      default:
	fprintf (stderr, usage);
	printf ("\nMRT version (%s) compiled on %s\n\n",
		MRT_VERSION, __DATE__);
	exit (0);
      }

    stdbuf = New_Buffer_Stream (stdout);
    
    if (input_mode == 1) {
      for ( ; optind < argc; optind++) {
	if (io_set (IO, IO_INFILE, (char *) argv[optind], NULL) < 0) {
	  if (optarg) 
	    fprintf (stderr, "Failed to open infile %s", (char *) optarg);
	  else
	    fprintf (stderr, "Failed to open -- no file provided\n");
	  exit (1);
	}
	process_input ();
      }
    }
    else if (input_mode == 2) {
	process_input ();
    }
    else if (optind < argc) {
      for ( ; optind < argc; optind++) {
	if (io_set (IO, IO_INFILE, (char *) argv[optind], NULL) < 0) {
	  fprintf (stderr, "Failed to open infile %s", (char *) argv[optind]);
	  exit (1);
	}
	process_input ();
      }
    }
    else {
	if (io_set (IO, IO_INFILE, "stdin", NULL) >= 0)
	    process_input ();
    }
    exit (0);
}

void process_input () {
  mrt_msg_t *msg;
  
  while (MRT->force_exit_flag == 0) {

    if ((msg = (mrt_msg_t *) io_read (IO)) == NULL) {
	trace (TR_TRACE, IO->trace, "EOF %d bytes read\n", IO->in_bytes);
      /*       printf("\nInvalid MSG "); */
      if (IO->error)
	exit (1);
      return;
    }

    trace (TR_TRACE, IO->trace, "MRT_MESSAGE: %s (%d bytes)\n",
	   S_MRT_MSG_TYPES[msg->type], msg->length);

    switch (msg->type) {
    case MSG_NULL:
      print_msg_hdr (msg);
      break;

    case MSG_START:
    case MSG_I_AM_DEAD:
    case MSG_PEER_DOWN:
    case MSG_PROTOCOL_IDRP:
    case MSG_PROTOCOL_RIPNG:
    case MSG_PROTOCOL_RIP:
      print_msg_hdr (msg);
      buffer_printf (stdbuf, "*** Not yet implemented ***\n");
      break;

    case MSG_DIE:
      print_msg_hdr (msg);
      exit(0);
      
    case MSG_PROTOCOL_BGP:
#ifdef HAVE_IPV6
    case MSG_PROTOCOL_BGP4PLUS:
    case MSG_PROTOCOL_BGP4PLUS_01:
#endif /* HAVE_IPV6 */
    case MSG_PROTOCOL_BGP4MP:
      print_msg_hdr (msg);
      print_bgp_msg (msg);
      break;
    case MSG_TABLE_DUMP:
      print_msg_hdr (msg);
      print_routing_table_msg (msg);
      break;
    default:
      buffer_printf (stdbuf, "*** Unknown message type %d\n", msg->type);
      break;
    }
    Delete (msg);
  }
  /* return; XXX */
}
