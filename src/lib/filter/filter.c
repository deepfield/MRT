/*
 * $Id: filter.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <mrt.h>
#include <bgp.h>
#include <filter.h>


#define MAX_ROUTE_MAP 100
static LINKED_LIST *ll_route_map[MAX_ROUTE_MAP];


static void
del_route_map_memory (route_map_t *route_map)
{
    assert (route_map);
    if (route_map->attr)
	 bgp_deref_attr (route_map->attr);
    Delete (route_map);
}


route_map_t *
add_route_map (int num, int precedence, u_long flag)
{
    route_map_t *route_map, *prev = NULL;

    if (num <= 0 && num >= MAX_ROUTE_MAP) {
	return (NULL);
    }
    if (precedence < 0)
	precedence = 0;
    if (ll_route_map[num]) {
        LL_Iterate (ll_route_map[num], route_map) {
	    if (route_map->precedence == precedence) {
		route_map->flag = flag;
	        return (route_map);
	    }
	    if (route_map->precedence > precedence)
	        break;
	    prev = route_map;
        }
    }
    else {
	ll_route_map[num] = 
	    LL_Create (LL_DestroyFunction, 
		       del_route_map_memory, 0);
    }
    route_map = New (route_map_t);
    route_map->attr = bgp_new_attr (PROTO_BGP);
    route_map->flag = flag;
    /* XXX condition */
    route_map->alist = -1;
    route_map->flist = -1;
    route_map->clist = -1;
    route_map->precedence = precedence;
    LL_InsertAfter (ll_route_map[num], route_map, prev);
    return (route_map);
}


int
get_route_map_num (int num)
{
    if (num <= 0 && num >= MAX_ROUTE_MAP) {
	return (-1);
    }
    if (ll_route_map[num] == NULL)
	return (0);
    return (LL_GetCount (ll_route_map[num]));
}


int
del_route_map (int num, int precedence)
{
    if (num <= 0 && num >= MAX_ROUTE_MAP) {
	return (-1);
    }
    if (ll_route_map[num] == NULL)
	return (0);
    if (precedence < 0)
        LL_Clear (ll_route_map[num]);
    else {
        route_map_t *route_map;
        LL_Iterate (ll_route_map[num], route_map) {
	    if (route_map->precedence == precedence) {
	        LL_Remove (ll_route_map[num], route_map);
	        break;
	    }
        }
    }
    return (LL_GetCount (ll_route_map[num]));
}


int
apply_route_map_alist (int num, prefix_t *prefix)
{
    route_map_t *route_map;

    if (num >= MAX_ROUTE_MAP)
	return (0);

    if (ll_route_map[num] == NULL)
	return (0);

    LL_Iterate (ll_route_map[num], route_map) {
	int listn;
	assert (route_map->attr);

	/* check alist */
	if ((listn = route_map->alist) > 0) {
	    if (prefix != NULL && apply_access_list (listn, prefix))
		return (1);
	}
    }
    return (0);
}


/* if destructive, overwrites the changes */
bgp_attr_t *
apply_route_map (int num, bgp_attr_t * attr, prefix_t *prefix, int destructive)
{
    route_map_t *route_map;

    if (num >= MAX_ROUTE_MAP)
	return (NULL);

    if (ll_route_map[num] == NULL || LL_GetCount (ll_route_map[num]) <= 0)
	return (attr);

    /* if it has its original, 
       use it and delete one that has been already modified */
    if (!destructive && attr->original) {
	bgp_attr_t *original;
	original = attr->original;
	bgp_deref_attr (attr);
	attr = original;
	assert (attr->original == NULL);
    }

    if (!destructive) {
	bgp_attr_t *new_attr;
	new_attr = bgp_copy_attr (attr);
        assert (new_attr->original == NULL);
        new_attr->original = attr;
        attr = new_attr;
    }

    LL_Iterate (ll_route_map[num], route_map) {
	int listn;
	assert (route_map->attr);

	/* check condition */

	/* check alist */
	if ((listn = route_map->alist) > 0) {
	    if (prefix == NULL || !apply_access_list (listn, prefix))
	        continue;
	}

	/* check flist */
	if ((listn = route_map->flist) > 0) {
	    if (!BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ASPATH) ||
		    !apply_as_access_list (listn, attr->aspath))
		continue;
	}

	/* check clist */
	if ((listn = route_map->clist) > 0) {
	    if (!BGP4_BIT_TEST (attr->attribs, PA4_TYPE_COMMUNITY) ||
		    !apply_community_list (listn, attr->community))
		continue;
	}

	if (BGP4_BIT_TEST (route_map->attr->attribs, PA4_TYPE_ORIGIN)) {
	    attr->origin = route_map->attr->origin;
	    BGP4_BIT_SET (attr->attribs, PA4_TYPE_ORIGIN);
	}
	if (BGP4_BIT_TEST (route_map->attr->attribs, PA4_TYPE_ASPATH)) {
	    if (BIT_TEST (route_map->flag, ROUTE_MAP_ASPATH_PREPEND))
		attr->aspath = aspath_prepend (attr->aspath,
					       route_map->attr->aspath);
	    else {
		if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ASPATH))
		    Delete_ASPATH (attr->aspath);
		attr->aspath = aspath_copy (route_map->attr->aspath);
	    }
	    BGP4_BIT_SET (attr->attribs, PA4_TYPE_ASPATH);
	}
	if (BGP4_BIT_TEST (route_map->attr->attribs, PA4_TYPE_NEXTHOP)) {
#ifdef HAVE_IPV6
	    if (route_map->attr->link_local) {
		if (attr->link_local)
		    deref_nexthop (attr->link_local);
		attr->link_local = ref_nexthop (route_map->attr->link_local);
	    }
	    if (route_map->attr->nexthop4) {
		if (attr->nexthop4)
		    deref_nexthop (attr->nexthop4);
		attr->nexthop4 = ref_nexthop (route_map->attr->nexthop4);
	    }
#endif /* HAVE_IPV6 */
	    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_NEXTHOP))
		deref_nexthop (attr->nexthop);
	    attr->nexthop = ref_nexthop (route_map->attr->nexthop);
	    BGP4_BIT_SET (attr->attribs, PA4_TYPE_NEXTHOP);
	}
	if (BGP4_BIT_TEST (route_map->attr->attribs, PA4_TYPE_METRIC)) {
	    attr->multiexit = route_map->attr->multiexit;
	    BGP4_BIT_SET (attr->attribs, PA4_TYPE_METRIC);
	}
	if (BGP4_BIT_TEST (route_map->attr->attribs, PA4_TYPE_LOCALPREF)) {
	    attr->local_pref = route_map->attr->local_pref;
	    BGP4_BIT_SET (attr->attribs, PA4_TYPE_LOCALPREF);
	}
	if (BGP4_BIT_TEST (route_map->attr->attribs, PA4_TYPE_ATOMICAGG)) {
	    BGP4_BIT_SET (attr->attribs, PA4_TYPE_ATOMICAGG);
	}
	if (BGP4_BIT_TEST (route_map->attr->attribs, PA4_TYPE_AGGREGATOR)) {
	    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_AGGREGATOR))
		Deref_Prefix (attr->aggregator.prefix);
	    attr->aggregator.as = route_map->attr->aggregator.as;
	    attr->aggregator.prefix =
		Ref_Prefix (route_map->attr->aggregator.prefix);
	    BGP4_BIT_SET (attr->attribs, PA4_TYPE_AGGREGATOR);
	}
	if (BGP4_BIT_TEST (route_map->attr->attribs, PA4_TYPE_COMMUNITY)) {
	    if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_COMMUNITY))
		Delete_community (attr->community);
	    attr->community = community_copy (route_map->attr->community);
	    BGP4_BIT_SET (attr->attribs, PA4_TYPE_COMMUNITY);
	}
	if (BGP4_BIT_TEST (route_map->attr->attribs, PA4_TYPE_DPA)) {
	    attr->dpa = route_map->attr->dpa;
	    BGP4_BIT_SET (attr->attribs, PA4_TYPE_DPA);
	}
#ifdef notdef
/* XXX pref is in route_t */
	if (route_map->attr->pref >= 0)
	    attr->pref = route_map->attr->pref;
#endif
    }
    return (attr);
}


void
route_map_out (int num, void_fn_t fn)
{
    route_map_t *route_map;

    assert (num < MAX_ROUTE_MAP);

    if (ll_route_map[num] == NULL || LL_GetCount (ll_route_map[num]) <= 0)
	return;

    LL_Iterate (ll_route_map[num], route_map) {
        bgp_attr_t *attr = route_map->attr;

        if (route_map->precedence <= 0) {
            fn ("route-map %d\n", num);
        }
        else {
            fn ("route-map %d %d\n", num, route_map->precedence);
        }

        if (route_map->alist >= 0)
	    fn ("  match ip address %d\n", route_map->alist);
        if (route_map->flist >= 0)
	    fn ("  match as-path %d\n", route_map->flist);
        if (route_map->clist >= 0)
	    fn ("  match community %d\n", route_map->clist);

        if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ORIGIN))
	    fn ("  set origin %s\n", origin2string (attr->origin));
        if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ASPATH)) {
	    fn ("  set as-path ");
	    if (BIT_TEST (route_map->flag, ROUTE_MAP_ASPATH_PREPEND))
	        fn ("prepend ");
	    fn ("%s\n", aspath_toa (attr->aspath));
	}

        if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_NEXTHOP)) {
#ifdef HAVE_IPV6
	    if (attr->link_local)
	        fn ("  set next-hop %s\n", 
			prefix_toa (attr->link_local->prefix));
	    if (attr->nexthop4)
	        fn ("  set next-hop %s\n", 
			prefix_toa (attr->nexthop4->prefix));
#endif /* HAVE_IPV6 */
	    fn ("  set next-hop %s\n", prefix_toa (attr->nexthop->prefix));
        }
        if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_METRIC))
	    fn ("  set metric %ld\n", attr->multiexit);
        if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_LOCALPREF))
	    fn ("  set local-preference %ld\n", attr->local_pref);
        if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_ATOMICAGG))
	    fn ("  set atomic-aggregate\n");
        if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_AGGREGATOR))
	    fn ("  set aggregator as %d %s\n", 
		attr->aggregator.as, prefix_toa (attr->aggregator.prefix));
        if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_COMMUNITY)) {
	    int i;
    
	    for (i = 0; i < attr->community->len; i++) {
	        char strbuf[64];
    
	        if (i == 0) {
		    fn ("  set community %s\n",
			    community_toa2 (attr->community->value[i],
						    strbuf));
	        }
	        else {
		    fn ("  set community %s additive\n",
				    community_toa2 (attr->community->value[i],
						    strbuf));
	        }
	    }
        }
        if (BGP4_BIT_TEST (attr->attribs, PA4_TYPE_DPA)) {
	    fn ("  set dpa as %d %ld\n",
			attr->dpa.as, attr->dpa.value);
        }
#ifdef notdef
/* XXX pref is in route_t */
        if (attr->pref >= 0)
	    fn ("  set weight %d\n", attr->pref);
#endif
    }
}
