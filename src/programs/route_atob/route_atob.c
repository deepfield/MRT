/* 
 * $Id: route_atob.c,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
 */

#include <mrt.h>
#include <bgp.h>
#include <ctype.h>

static void
adjust_y2k (struct tm *tm)
{
    /* if the year is 0 thru 68, it is treated as 21st centry */
    if (tm->tm_year <= 68)
	tm->tm_year += 100;
}

#ifndef HAVE_STRPTIME

/*
 * Please be careful because this function doesn't consult the format.
 * This only parses "MM/DD/YY HH:MM:SS" like 05/06/96 23:55:10.
 */

static char *
strptime (char *buf, const char *format, struct tm *tm)
{

    static char *tm_zone = NULL;
    static long tm_gmtoff = 0;
    static int tm_isdst = 0;

    if (strlen (buf) < 17)
	return (NULL);

    if (tm_zone == NULL && tm_gmtoff == 0) {
	struct tm *tmp;
	time_t now;
	time (&now);
	tmp = localtime (&now);
	tm_isdst = tmp->tm_isdst;
	tm_gmtoff = tmp->tm_gmtoff;
	tm_zone = strdup (tmp->tm_zone);
    }
    buf[2] = buf[5] = buf[8] = buf[11] = buf[14] = '\0';
    tm->tm_mon = atoi (buf + 0) - 1;
    tm->tm_mday = atoi (buf + 3);
    tm->tm_year = atoi (buf + 6);
    tm->tm_hour = atoi (buf + 9);
    tm->tm_min = atoi (buf + 12);
    tm->tm_sec = atoi (buf + 15);
    tm->tm_gmtoff = tm_gmtoff;
    tm->tm_zone = tm_zone;

    return (buf + 17);
}

#endif /* HAVE_STRPTIME */


static char *
checkstradvance (char *cp, char *s)
{
    int len = strlen (s);
    if (strncasecmp (cp, s, len) == 0) {
	if (cp[len] == '\0') {
	    return (cp + len);
	}
	if (cp[len] == ':' || isspace (cp[len])) {
	    do {
		len++;
	    } while (isspace (cp[len]));
	    return (cp + len);
	}
	return (NULL);
    }
    return (NULL);
}


static int
nulline (char *cp)
{
    while (isspace (*cp))
	cp++;
    if (*cp == '\0')
	return (1);
    return (0);
}


static void     
trace_mrt_header (trace_t *tr, time_t tstamp, int type, int subtype)
{   
    char *stime, **cpp;
    
    stime = my_strftime (tstamp, "%D %T");
    trace (TR_TRACE, tr, "TIME: %s\n", stime);
    if ((cpp = S_MRT_MSG_SUBTYPES[type]) != NULL)
        trace (TR_TRACE, tr, "TYPE: %s/%s\n",
               S_MRT_MSG_TYPES[type], cpp[subtype]);
    else  
        trace (TR_TRACE, tr, "TYPE: %s\n", S_MRT_MSG_TYPES[type]);
    Delete (stime);
}   


static void
flushout (io_t *io, time_t tstamp, int type, int subtype, bgp_attr_t *attr, 
	  LINKED_LIST *ll_ann, LINKED_LIST *ll_with, gateway_t *gateway_to)
{
    u_char *cp;
    int size;

    trace_mrt_header (MRT->trace, tstamp, type, subtype);
    cp = bgp_create_update_msg (type, subtype, &size, attr, ll_ann, ll_with, 
				gateway_to);
    io_write (io, tstamp, type, subtype, size, (char *) cp);
    Delete (cp);
    trace (TR_TRACE, MRT->trace, "write %d bytes\n", size);
    trace (TR_TRACE, MRT->trace, "\n");
}


static void
flushout2 (io_t *io, time_t tstamp, int type, int subtype,
	   u_char *bgp_packet, int len, 
	   gateway_t *gateway_from, gateway_t *gateway_to)
{
    u_char *cp = bgp_packet;
    int size = len;

    trace_mrt_header (MRT->trace, tstamp, type, subtype);
    cp = bgp_create_update_msg2 (type, subtype, &size, cp,
			 	 gateway_from, gateway_to);
    io_write (io, tstamp, type, subtype, size, (char *) cp);
    Delete (cp);
    trace (TR_TRACE, MRT->trace, "write %d bytes\n", size);
    trace (TR_TRACE, MRT->trace, "\n");
}


static void 
read_ascii (FILE *fd, io_t *IO)
{
    LINKED_LIST *ll_ann, *ll_with;
    bgp_attr_t *attr;
    int announce_flag = 0;
    int line_num = 0;
    int have_data = 0;
    int have_data2 = 0;
    time_t tstamp = 0;
    int type = 0;
    int subtype = 0;
    int bgptype = 0;
    int newtype = 0;
    gateway_t *gateway_from = NULL;
    gateway_t *gateway_to = NULL;
    int first = 1;
    u_char bgp_packet[BGPMAXPACKETSIZE], *bp = bgp_packet;
    u_char buffer[MAX_MSG_SIZE], *buffer_p = buffer;
    u_char *end = buffer + sizeof (buffer);
    int eof = 0;
    buffer_t *stdbuf;

    int state1 = 0, state2 = 0;

    int version = 0, as = 0, holdtime = 0, optlen = 0;
    u_long id = 0;

    int code = 0, subcode = 0;

    int viewno = 0;
    char *filename = NULL;

    prefix_t *route_prefix = NULL;
    time_t originated = 0;
    u_long status = 0;
    int seq_num = 0;

    attr = bgp_new_attr (PROTO_BGP);
    ll_ann = LL_Create (LL_DestroyFunction, Deref_Prefix, 0);
    ll_with = LL_Create (LL_DestroyFunction, Deref_Prefix, 0);

    stdbuf = New_Buffer_Stream (fd);
    for (;;) {
        char *line = NULL, *ret = NULL;
	int len = 0;
        int ok = 0;
	char *cp;

        if (buffer_gets (stdbuf) <= 0) {
	    eof++;
	}
	else {
	    len = buffer_data_len (stdbuf);
	    line = buffer_data (stdbuf);

	    if (line[len - 1] == '\n') {
	        line[len - 1] = '\0';
	        len--;
	    }
	    trace (TR_TRACE, MRT->trace, "++%s\n", line);
            line_num++;

	    if ((cp = strpbrk (line, "#!")) != NULL) {
	        *cp = '\0';
	        len = cp - line;
	    }

	    if (first && nulline (line))
	        continue;
	    first = 0;
	}
    
	if (eof || nulline (line)) {
	    if (have_data && have_data2) {
		trace (TR_ERROR, MRT->trace, "Mixture of two formats\n");
		goto error;
	    }
	    if (bgptype == BGP_UPDATE && have_data) {
		flushout (IO, tstamp, type, subtype, attr, ll_ann, ll_with, 
			  gateway_to);
	    }
	    else if (have_data2) {
		flushout2 (IO, tstamp, type, subtype, 
			   bgp_packet, bp - bgp_packet, 
			   gateway_from, gateway_to);
	    }
    	    else if (bgptype == BGP_KEEPALIVE) {
		if (type == MSG_PROTOCOL_BGP4MP) {
		    memset (bgp_packet, 0xff, BGP_HEADER_MARKER_LEN);
	  	    BGP_PUT_HDRTYPE (bgptype, bgp_packet);
		    bp = bgp_packet + BGP_HEADER_LEN;
	  	    BGP_PUT_HDRLEN (bp - bgp_packet, bgp_packet);
		}
		else {
		    bp = bgp_packet;
		}
		flushout2 (IO, tstamp, type, subtype, 
		   	   bgp_packet, bp - bgp_packet, 
			   gateway_from, gateway_to);
    	    }
    	    else if (bgptype == BGP_OPEN) {
		if (type == MSG_PROTOCOL_BGP4MP) {
		    memset (bgp_packet, 0xff, BGP_HEADER_MARKER_LEN);
	  	    BGP_PUT_HDRTYPE (bgptype, bgp_packet);
		    bp = bgp_packet + BGP_HEADER_LEN;
		}
		else {
		    bp = bgp_packet;
		}
		BGP_PUT_BYTE (version, bp);
		BGP_PUT_SHORT (as, bp);
		BGP_PUT_SHORT (holdtime, bp);
		BGP_PUT_NETLONG (id, bp);
		BGP_PUT_BYTE (0, bp); /* XXX */
		if (type == MSG_PROTOCOL_BGP4MP) {
	  	    BGP_PUT_HDRLEN (bp - bgp_packet, bgp_packet);
		}
		flushout2 (IO, tstamp, type, subtype, 
		 	   bgp_packet, bp - bgp_packet, 
			   gateway_from, gateway_to);
    	    }
    	    else if (bgptype == BGP_NOTIFY) {
		if (type == MSG_PROTOCOL_BGP4MP) {
		    memset (bgp_packet, 0xff, BGP_HEADER_MARKER_LEN);
	  	    BGP_PUT_HDRTYPE (bgptype, bgp_packet);
		    bp = bgp_packet + BGP_HEADER_LEN;
		}
		else {
		    bp = bgp_packet;
		}
		BGP_PUT_BYTE (code, bp);
		BGP_PUT_BYTE (subcode, bp);
		if (type == MSG_PROTOCOL_BGP4MP) {
	  	    BGP_PUT_HDRLEN (bp - bgp_packet, bgp_packet);
		}
		flushout2 (IO, tstamp, type, subtype, 
		 	   bgp_packet, bp - bgp_packet, 
			   gateway_from, gateway_to);
    	    }
	    else if (newtype == BGP4MP_STATE_CHANGE) {
		bp = bgp_packet;
		BGP_PUT_SHORT (state1, bp);
		BGP_PUT_SHORT (state2, bp);
		flushout2 (IO, tstamp, type, subtype, 
		 	   bgp_packet, bp - bgp_packet, 
			   gateway_from, NULL);
	    }
	    else if (newtype == BGP4MP_SNAPSHOT) {
		bp = bgp_packet;
		BGP_PUT_SHORT (viewno, bp);
		if (filename)
		    BGP_PUT_DATA (filename, strlen (filename), bp);
		BGP_PUT_BYTE (0, bp);
    		trace_mrt_header (MRT->trace, tstamp, type, subtype);
    		io_write (IO, tstamp, type, subtype, 
			  bp - bgp_packet, bgp_packet);
	    }
	    else if (newtype == BGP4MP_ENTRY) {
		if (route_prefix != NULL) {
		    buffer_p = bgp_table_dump_entry (buffer_p, end, type, 
						     subtype, viewno, 
				   route_prefix, status, originated, attr);
		}
		if (buffer_p - buffer > 0) {
    		    trace_mrt_header (MRT->trace, tstamp, type, subtype);
    		    io_write (IO, tstamp, type, subtype, 
			      buffer_p - buffer, buffer);
		}
	    }

	    if (eof)
		break;
	if (MRT->force_exit_flag)
	    exit (1);
	    bgp_deref_attr (attr);
	    attr = bgp_new_attr (PROTO_BGP);
	    LL_Clear (ll_ann);
	    LL_Clear (ll_with);

    	    announce_flag = 0;
    	    have_data = 0;
    	    have_data2 = 0;
    	    tstamp = 0;
    	    type = 0;
    	    subtype = 0;
    	    bgptype = 0;
    	    newtype = 0;
    	    gateway_to = NULL;
    	    gateway_from = NULL;
    	    route_prefix = NULL;
	    seq_num = 0;
    	    first = 1;
    	    if (filename)
		free (filename);
	    filename = NULL;
	    continue;
	}

    if (have_data) {
	/* a prefix -- line begins with a space */
	if (isspace (line[0])) {
	    prefix_t *prefix;
	    char *cp = line +1;

	    while (isspace (*cp))
		cp++;
	    if ((prefix = ascii2prefix (0, cp)) != NULL) {
		if (announce_flag == 1) {
		    LL_Add (ll_ann, prefix);
		}
		else {
		    LL_Add (ll_with, prefix);
		}
	        continue;
	    }
	}
    }

	if (have_data2) {
	    prefix_t *prefix;
	    int num;
	    u_long value;

	    if (isspace (line[0]) &&
		    strpbrk (line, ".:") && strchr (line, '/') &&
		    parse_line (line, "%d %m", &num, &prefix) == 2) {
		u_char *here = bp;
		/* v4 or v6 address with prefixlen */
#ifdef HAVE_IPV6
		if (prefix->family == AF_INET6)
		    BGP_PUT_PREFIX6 (prefix->bitlen, prefix_tochar (prefix), 
				     bp);
		else
#endif /* HAVE_IPV6 */
		    BGP_PUT_PREFIX (prefix->bitlen, prefix_tochar (prefix), 
				    bp);
		Deref_Prefix (prefix);
		if (num != bp - here) {
		    trace (TR_ERROR, MRT->trace, 
			   "length was %d but must be %d\n", num, bp - here);
		    goto error;
		}
		continue;
	    }
	    else if (isspace (line[0]) &&
	    	         strpbrk (line, ".:") && 
		    	 parse_line (line, "%d %M", &num, &prefix) == 2) {
		/* v4 or v6 address w/o prefixlen */
		if (prefix->family == AF_INET6 && num > 16) {
		    trace (TR_ERROR, MRT->trace, 
			   "length was %d but must be less than or equal %d\n",
			    num, 16);
		    Deref_Prefix (prefix);
		    goto error;
		}
		if (prefix->family == AF_INET && num > 4) {
		    trace (TR_ERROR, MRT->trace, 
			   "length was %d but must be less than or equal %d\n",
			    num, 4);
		    Deref_Prefix (prefix);
		    goto error;
		}
		BGP_PUT_DATA (prefix_tochar (prefix), num, bp);
		Deref_Prefix (prefix);
		continue;
	    }
	    else if (isspace (line[0]) &&
	    		parse_line (line, "%d %i", &num, &value) == 2) {
		if (num == 1)
		    BGP_PUT_BYTE (value, bp);
		else if (num == 2)
		    BGP_PUT_SHORT (value, bp);
		else if (num == 4)
		    BGP_PUT_LONG (value, bp);
		else {
		    trace (TR_ERROR, MRT->trace, 
			   "unknown length %d\n", num);
		    goto error;
		}
		continue;
	    }
	}

	if ((ret = checkstradvance (line, "TIME"))) {
	    struct tm tm;
	    if (strptime (ret, "%D %T", &tm)) {
		time_t now;
		time (&now);
		tm.tm_isdst = localtime (&now)->tm_isdst;
		adjust_y2k (&tm);
		tstamp = mktime (&tm);
	    }
	}

	else if ((ret = checkstradvance (line, "TO"))) {
	    int as;
    	    char data[MAXLINE];
	    prefix_t *prefix;
	    if (sscanf (ret, "%s AS%d", data, &as) >= 2 ||
	        sscanf (ret, "AS%d %s", &as, data) >= 2 /* obsolete */) {
		prefix = ascii2prefix (0, data);
		gateway_to = add_gateway (prefix, as, NULL);
		Deref_Prefix (prefix);
	    }
	}

	else if ((ret = checkstradvance (line, "FROM"))) {
	    int as;
    	    char data[MAXLINE];
	    if (sscanf (ret, "%s AS%d", data, &as) >= 2 ||
	        sscanf (ret, "AS%d %s", &as, data) >= 2 /* obsolete */) {
		prefix_t *prefix = ascii2prefix (0, data);
		gateway_from = add_gateway (prefix, as, NULL);
		attr->gateway = gateway_from;
		Deref_Prefix (prefix);
	    }
	}

	/* type BGP/UPDATE */
	else if ((ret = checkstradvance (line, "TYPE"))) {
	    char *subtypestr;
	    char **cpp;
	    int i;

	    if ((subtypestr = strchr (ret, '/')) != NULL)
		*subtypestr++ = '\0';

	    cpp = S_MRT_MSG_TYPES;
	    for (i = 0; cpp[i]; i++) {
	        if (strcasecmp (cpp[i], ret) == 0)
			break;
	    }
	    type = (enum MRT_MSG_TYPES) i;

	    if (subtypestr) {
		char *subsubtypestr;

	        if ((subsubtypestr = strchr (subtypestr, '/')) != NULL)
		    *subsubtypestr++ = '\0';
		if ((cpp = S_MRT_MSG_SUBTYPES[type]) != NULL) {
		    for (i = 0; cpp[i]; i++) {
		        if (strcasecmp (cpp[i], subtypestr) == 0)
			    break;
		    }
		    subtype = i;
		}
		newtype = subtype;

		if (type == MSG_PROTOCOL_BGP ||
			type == MSG_PROTOCOL_BGP4PLUS ||
			type == MSG_PROTOCOL_BGP4PLUS_01) {
		    if (subtype == MSG_BGP_UPDATE) {
		        bgptype = BGP_UPDATE;
			newtype = BGP4MP_MESSAGE;
		    }
		    else if (subtype == MSG_BGP_KEEPALIVE) {
		        bgptype = BGP_KEEPALIVE;
			newtype = BGP4MP_MESSAGE;
		    }
		    else if (subtype == MSG_BGP_NOTIFY) {
		        bgptype = BGP_NOTIFY;
			newtype = BGP4MP_MESSAGE;
		    }
		    else if (subtype == MSG_BGP_OPEN) {
		        bgptype = BGP_OPEN;
			newtype = BGP4MP_MESSAGE;
		    }
		    else if (subtype == MSG_BGP_SYNC) {
			newtype = BGP4MP_SNAPSHOT;
		    }
		    else if (subtype == MSG_BGP_STATE_CHANGE) {
			newtype = BGP4MP_STATE_CHANGE;
		    }
		    else if (subtype == MSG_TABLE_DUMP) {
			newtype = BGP4MP_ENTRY;
		    }
		}
		else if (type == MSG_PROTOCOL_BGP4MP && (
			subtype == BGP4MP_MESSAGE || 
			subtype == BGP4MP_MESSAGE_OLD)) {
		    for (i = 0; sbgp_pdus[i]; i++) {
		        if (strcasecmp (sbgp_pdus[i], subsubtypestr) == 0) {
		    	    bgptype = i;
			    break;
			}
		    }
		}
	    }

	    if (type == MSG_PROTOCOL_BGP
		    || type == MSG_PROTOCOL_BGP4PLUS
		    || type == MSG_PROTOCOL_BGP4PLUS_01
		    || type == MSG_TABLE_DUMP
		    || type == MSG_PROTOCOL_BGP4MP
		    ) {
		/* OK */
	    }
	    else {
		trace (TR_ERROR, MRT->trace, 
		       "Unknown message type %s at line %d\n", ret, line_num);
		goto error;
	    }
	}

	else if ((ret = checkstradvance (line, "DATA"))) {
	    bp = bgp_packet;
	    have_data2++;
	}
	else if (newtype == BGP4MP_STATE_CHANGE &&
	         (ret = checkstradvance (line, "PEER"))) {
	    int as;
    	    char data[MAXLINE];
	    if (sscanf (ret, "%s AS%d", data, &as) >= 2 ||
	        sscanf (ret, "AS%d %s", &as, data) >= 2 /* obsolete */) {
		prefix_t *prefix = ascii2prefix (0, data);
		gateway_from = add_gateway (prefix, as, NULL);
		Deref_Prefix (prefix);
	    }
	}
	else if (newtype == BGP4MP_STATE_CHANGE &&
	         (ret = checkstradvance (line, "STATE"))) {
	    char *cp = strchr (ret, '/');
	    int i;

	    if (cp == NULL)
		goto error;
	    *cp++ = '\0';
	    for (i = 0; sbgp_states[i]; i++) {
		if (strcasecmp (sbgp_states[i], ret) == 0) {
		    state1 = i;
		}
	    }
	    for (i = 0; sbgp_states[i]; i++) {
		if (strcasecmp (sbgp_states[i], cp) == 0) {
		    state2 = i;
		}
	    }
	}
	else if ((newtype == BGP4MP_SNAPSHOT || newtype == BGP4MP_ENTRY) &&
	         (ret = checkstradvance (line, "VIEW"))) {
	    viewno = atoi (ret);
	}
	else if (newtype == BGP4MP_SNAPSHOT &&
	         (ret = checkstradvance (line, "FILE"))) {
	    if (filename)
		free (filename);
	    filename = strdup (ret);
	}
	else if (newtype == BGP4MP_ENTRY &&
	         (ret = checkstradvance (line, "PREFIX"))) {
	    if (route_prefix == NULL) {
	    	buffer_p = buffer;
		if (type == MSG_TABLE_DUMP) {
	    	    BGP_PUT_SHORT (viewno, buffer_p);
            	    BGP_PUT_SHORT (seq_num, buffer_p);
		}
	    }
	    else {
		buffer_p = bgp_table_dump_entry (buffer_p, end, type, subtype,
                      viewno, route_prefix, status, originated, attr);
	    }
	    route_prefix = ascii2prefix (0, ret);
	    bgp_deref_attr (attr);
	    attr = bgp_new_attr (PROTO_BGP);
	}
	else if (newtype == BGP4MP_ENTRY &&
	         (ret = checkstradvance (line, "SEQUENCE"))) {
	    seq_num = atoi (ret);
	}
	else if (newtype == BGP4MP_ENTRY &&
	        (ret = checkstradvance (line, "ORIGINATED"))) {
	    struct tm tm;
	    if (strptime (ret, "%D %T", &tm)) {
		time_t now;
		time (&now);
		tm.tm_isdst = localtime (&now)->tm_isdst;
		adjust_y2k (&tm);
		originated = mktime (&tm);
	    }
	}
	else if (newtype == BGP4MP_ENTRY &&
	         (ret = checkstradvance (line, "STATUS"))) {
	    sscanf (ret, "%li", &status);
	}
	else if (bgptype == BGP_OPEN &&
		(ret = checkstradvance (line, "VERSION"))) {
	    version = atoi (ret);
	}
	else if (bgptype == BGP_OPEN &&
		(ret = checkstradvance (line, "AS"))) {
	    as = atoi (ret);
	}
	else if (bgptype == BGP_OPEN &&
		(ret = checkstradvance (line, "HOLD_TIME"))) {
	    holdtime = atoi (ret);
	}
	else if (bgptype == BGP_OPEN &&
		(ret = checkstradvance (line, "ID"))) {
	    inet_pton (AF_INET, ret, &id);
	}
	else if (bgptype == BGP_OPEN &&
		(ret = checkstradvance (line, "OPT_PARM_LEN"))) {
	    optlen = atoi (ret);
	}
	else if (bgptype == BGP_NOTIFY &&
		(ret = checkstradvance (line, "CODE"))) {
	    char *cp;
	    code = atoi (ret);
	    if ((cp = strchr (ret, '/')) != NULL)
		subcode = atoi (cp + 1);
	}
	else if (bgptype == BGP_UPDATE &&
		(ret = checkstradvance (line, "ANNOUNCE"))) {
	    announce_flag = 1;
	    have_data++;
	}
	else if (bgptype == BGP_UPDATE &&
		(ret = checkstradvance (line, "WITHDRAW"))) {
	    announce_flag = 0;
	    have_data++;
	}
	else if ((bgptype == BGP_UPDATE || newtype == BGP4MP_ENTRY) &&
		(ok = bgp_scan_attr (line, attr, MRT->trace)) > 0) {
	    /* OK */
	}
	else if ((bgptype == BGP_UPDATE || newtype == BGP4MP_ENTRY) && ok < 0) {
	    trace (TR_ERROR, MRT->trace, 
	           "Invalid BGP attribute at line %d\n", line_num);
	    goto error;
	}
	else {
	    trace (TR_ERROR, MRT->trace, "Unrecognized line at %d\n", line_num);
	    goto error;
	}
    }

error:
    if (filename)
	free (filename);
    bgp_deref_attr (attr);
    LL_Destroy (ll_ann);
    LL_Destroy (ll_with);
    Delete_Buffer (stdbuf);
}


void
main (int argc, char *argv[])
{
    int c;
    extern char *optarg;	/* getopt stuff */
    extern int optind;		/* getopt stuff */
    char *usage =
    "Usage: route_atob [-i ascii_data_file] [-(o|w) binary_out_file]\n";
    char *filename = "stdin";
    char *ofile = "stdout";
    char *wfile = NULL;
    int errors = 0;
    io_t *IO;
    trace_t *default_trace;
    FILE *fd;

    default_trace = New_Trace ();
    IO = New_IO (default_trace);

    while ((c = getopt (argc, argv, "i:f:o:w:v")) != -1)
	switch (c) {
	case 'o':
	    ofile = (char *) (optarg);
	    break;
	case 'w':
	    wfile = (char *) (optarg);
	    break;
	case 'i':
	case 'f':
	    filename = (char *) optarg;
	    break;
	case 'v':
	    set_trace (default_trace, TRACE_FLAGS, TR_ALL,
		       TRACE_LOGFILE, "stdout", NULL);
	    break;
	default:
	    errors++;
	}

    init_mrt (default_trace);

    if (ofile) {
	if (io_set (IO, IO_OUTFILE, ofile, NULL) < 0) {
	    printf ("Error setting outfile: %s (%s)\n", ofile, strerror (errno));
	    errors++;
	}
    }
    if (wfile) {
	if (io_set (IO, IO_OUTMSGQ, wfile, NULL) < 0) {
	    printf ("Error setting output: %s (%s)\n", wfile, strerror (errno));
	    errors++;
	}
    }
    if (errors) {
	fprintf (stderr, usage);
	printf ("\nMRT version (%s) compiled on %s\n\n",
		MRT_VERSION, __DATE__);
	exit (0);
    }

    if (!strcasecmp (filename, "stdin"))
	fd = stdin;
    else
	fd = fopen (filename, "r");

    if (fd == NULL) {
	perror (filename);
	exit (1);
    }
    read_ascii (fd, IO);
    exit (0);
}

