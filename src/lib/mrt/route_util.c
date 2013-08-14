/*
 * $Id: route_util.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <mrt.h>

#ifdef notdef
Route *New_Route (u_char *dest, int bitlen, void *attr)
{
   Route *tmp = New (Route);
   
   tmp->prefix = New_Prefix (AF_INET, dest, bitlen);
   tmp->attr = attr;
   return (tmp);
}
#endif


typedef struct _string2proto_table_t {
    char *name;
    int proto;
} string2proto_table_t;

string2proto_table_t string2proto_table[] = {
    {"kernel", PROTO_KERNEL},
    {"static", PROTO_STATIC},
    {"connected", PROTO_CONNECTED},
    {"direct", PROTO_CONNECTED}, /* for compatibility */
    {"rip", PROTO_RIP},
    {"ospf", PROTO_OSPF},
    {"bgp", PROTO_BGP},
    {"ripng", PROTO_RIPNG},
    {"pim", PROTO_PIM},
    {"pimv6", PROTO_PIMV6},
    {"igmp", PROTO_IGMP},
    {"igmpv6", PROTO_IGMPV6},
    {"dvmrp", PROTO_DVMRP},
    {NULL, 0},
};


int
string2proto (char *proto_string)
{
    string2proto_table_t *table;

    for (table = string2proto_table; table->name; table++) {
	if (strcasecmp (table->name, proto_string) == 0)
	    return (table->proto);
    }
    return (-1);
}


char *
proto2string (int proto)
{
    string2proto_table_t *table;

    for (table = string2proto_table; table->proto; table++) {
	if (table->proto == proto)
	    return (table->name);
    }
    return ("unknown");
}


char *s_origins[] = {"IGP", "EGP", "INCOMPLETE", "AGGREGATE"};
char c_origins[] = {'i', 'e', '?', 'a'};
const char *origin2string (int origin) { return (s_origins[origin]); }
const int origin2char (int origin) { return (c_origins[origin]); }


static char *
s_bgp_attr_type[] = {
    "INVALID",
    "ORIGIN",
    "ASPATH", /* AS_PATH in RFC */
    "NEXT_HOP",
    "MULTI_EXIT_DISC",
    "LOCAL_PREF",
    "ATOMIC_AGGREGATE",
    "AGGREGATOR",
    "COMMUNITY",
    "ORIGINATOR_ID",
    "CLUSTER_LIST",
    "DPA",
    "ADVERTISER",
    "RCID_PATH",
    "MPREACHNLRI",
    "MPUNRNLRI",
};


char *
bgptype2string (int type)
{
    if (type >= 0 && type <= PA4_TYPE_KNOWN_MAX)
	return (s_bgp_attr_type[type]);
    return (s_bgp_attr_type[0]);
}


int
string2bgptype (char **str)
{
    int i;

    for (i = 0; i <= PA4_TYPE_KNOWN_MAX; i++) {
	int len = strlen (s_bgp_attr_type[i]);
	if (strncasecmp (s_bgp_attr_type[i], *str, len) == 0) {
	    *str += len;
	    return (i);
	}
    }
    return (-1);
}
