/*
 * $Id: hqlip.c,v 1.1.1.1 2000/08/14 18:46:14 labovit Exp $
 */

#include "ricd.h"


static void hqlip_neighbor_down (hqlip_t *hqlip, hqlip_neighbor_t *neighbor);
static void hqlip_neighbor_start (hqlip_t *hqlip, hqlip_neighbor_t *neighbor);
static int hqlip_process_pdu (hqlip_t *hqlip, hqlip_neighbor_t *neighbor);
static spath_link_qos_t *spath_link_qos_create (hqlip_t *hqlip,
                       area_t *area1, area_t *area2,
                       int metric, link_qos_t *link_qos, u_long flags);
static void hqlip_trace_link_qos (u_long flags, trace_t *tr, char *head,
		      my_area_t *my_area, spath_link_qos_t *spath_link_qos);
static void hqlip_send_link_qos (hqlip_t *hqlip, my_area_t *my_area,
                     hqlip_neighbor_t *neighbor,
                     spath_link_qos_t *specified);
static void hqlip_calc_ilink (hqlip_t *hqlip, my_area_t *my_area, 
			      area_t *area2);
static int hqlip_spath_compare (u_char *a, u_char *b);
static void hqlip_update_database (hqlip_t *hqlip, my_area_t *my_area);
static void destroy_spath_link_qos (spath_link_qos_t *spath_link_qos);


static char *hqlip_pdus[] = {
    "",
    "KEEP_ALIVE",
    "LINK_QOS",
    "AREA_CENTER",
    "AREA_ADDR",
    "AREA_QOS",
    "SYNC",
};


link_qos_t *
copy_link_qos (link_qos_t *src, link_qos_t *dst)
{   
    assert (src);
    if (src == NULL)
        return (NULL);
    if (dst == NULL) {
        dst = New (link_qos_t);
    }
    *dst = *src;
    return (dst);
}   


static int
my_area_is_center (my_area_t *my_area)
{
    if (my_area == NULL || my_area->parent == NULL)
	return (0);
    return (my_area->parent && my_area->parent->winner &&
                my_area->parent->winner->area == my_area->area);
}

	
static link_qos_t *
hqlip_find_best_qos (LINKED_LIST *ll_link_qoses, req_qos_t *req_qos)
{
    int best_cost = 9999999 /* shut up the compiler */, cost;
    link_qos_t *best_qos = NULL, *link_qos;

    LL_Iterate (ll_link_qoses, link_qos) {
	if (req_qos) {
/* XXX
	    if (link_qos->pri != req_qos->pri) {
	        continue;
	    }
*/
	    if (link_qos->pps < req_qos->pps)
	        continue;
	    cost = req_qos->cd * link_qos->dly + req_qos->cf /* + area qos */;
	}
	else {
	    /* for the time being */
	    cost = link_qos->dly;
	}
	if (best_qos == NULL || best_cost > cost) {
	    best_cost = cost;
	    best_qos = link_qos;
	}
    }
if (best_qos)
trace (TR_PACKET, MRT->trace, "link-qos found pri %u pps %u cost %u\n",
	best_qos->pri, best_qos->pps, best_cost);
    return (best_qos);
}


static int
area_is_child (my_area_t *my_area, area_t *area)
{
    my_area_t *child;
    spath_link_qos_t *spath_link_qos;
    spath_area_addr_t *spath_area_addr;
    spath_area_qos_t *spath_area_qos;
    spath_area_center_t *spath_area_center;

    LL_Iterate (my_area->ll_children, child) {
	if (child->area == area)
	    return (TRUE);
    }

    /* dynamically determine this since area structure may change */
    /* I don't know how I can get relationship in foreign areas */

    LL_Iterate (my_area->ll_spath_link_qoses, spath_link_qos) {
	if (spath_link_qos->area1 == area)
	    return (TRUE);
/* can't beleive him ? */
/*
	if (!BIT_SET (lqos->flags, LINK_QOS_EXTERNAL)) {
	    if (lqos->area2 == area2)
		break;
	}
*/
    }
    LL_Iterate (my_area->ll_spath_area_addrs, spath_area_addr) {
	if (spath_area_addr->area == area)
	    return (TRUE);
    }
    LL_Iterate (my_area->ll_spath_area_qoses, spath_area_qos) {
	if (spath_area_qos->area == area)
	    return (TRUE);
    }
    LL_Iterate (my_area->ll_spath_area_centers, spath_area_center) {
	if (spath_area_center->area == area)
	    return (TRUE);
    }
    return (FALSE);
}


static int
area_is_descendant (my_area_t *my_area, area_t *area)
{
    my_area_t *child;

    if (my_area->area == area)
	return (FALSE);
    if (area_is_child (my_area, area))
	return (TRUE);
    LL_Iterate (my_area->ll_children, child) {
	if (area_is_descendant (child, area))
	    return (TRUE);
    }
    return (FALSE);
}


static int
area_is_local (area_t *area)
{
    if (area == NULL)
	return (TRUE);
    return (area->my_area != NULL);
}


#define area_is_r_local(area) area_is_local(area)
#ifdef notdef
/* I know it's inefficient */
/* the area and its centers are recursively local */
static int
area_is_r_local (area_t *area)
{
    if (area == NULL)
	return (TRUE);

    if (!area_is_local (area)) {
	/* foreign area */
/* trace (TR_PACKET, MRT->trace, "area %d:%a not local\n",  
	area->level, area->id); */
	return (FALSE);
    }
    if (area->level == 0) {
/* trace (TR_PACKET, MRT->trace, "area %d:%a is local\n", 
	area->level, area->id); */
	/* because of my_area */
	return (TRUE);
    }
    if (area->my_area->winner)
        return (area_is_r_local (area->my_area->winner->area));
/* trace (TR_PACKET, MRT->trace, "area %d:%a no center\n", 
	area->level, area->id); */
    return (FALSE);
}
#endif


/* check destination first to avoid loop */
static link_qos_t *
spath_calc_link_qos2 (hqlip_t *hqlip, my_area_t *my_area,
		      area_t *area1, area_t *area2, req_qos_t *req_qos,
		      link_qos_t *link_qos, int *metric, int count,
		      u_long *reason)
{
    spath_link_qos_t *spath_link_qos;

    if (count-- <= 0) {
        trace (TR_ERROR, hqlip->trace, "find_link_qos loop detected\n");
	if (reason && *reason == 0)
	    *reason = SRSVP_MSG_ERR_UNREACH;
	return (NULL);
    }

    /* area1 == NULL means local to somewhere */

    if (area_is_r_local (area1))
	area1 = NULL;
    assert (area2 != NULL);

    if (area1 == NULL)
        trace (TR_TRACE, hqlip->trace, "find_link_qos local -> %d:%a in %s\n", 
	   area2->level, area2->id, my_area->name);
    else
        trace (TR_TRACE, hqlip->trace, "find_link_qos %d:%a -> %d:%a in %s\n", 
	   area1->level, area1->id, area2->level, area2->id, my_area->name);

    while (area1 == NULL && area2 && area2->level >= 1 &&
		area2->my_area && area2->my_area->winner) {
	trace (TR_TRACE, hqlip->trace, 
		"area2 %d:%a is being replaced with the center %d:%a in %s\n", 
	   	area2->level, area2->id, 
		area2->my_area->winner->area->level, 
		area2->my_area->winner->area->id, area2->my_area->name);
	my_area = area2->my_area;
	area2 = area2->my_area->winner->area;
    }
    if (area_is_r_local (area2))
	area2 = NULL;

    if (area1 == NULL && area2 == NULL) {
        trace (TR_TRACE, hqlip->trace, "both are local in %s\n", 
		my_area->name);
        link_qos->flag = 0;
        link_qos->pri = SSPEC_PRI_USER;
        link_qos->loh = 0;
        link_qos->pps = (req_qos)? req_qos->pps: 999999 /* XXX */;
        link_qos->dly = 0;
	*metric = 0;
	if (reason)
	    *reason = 0;
        return (link_qos);
    }

    trace (TR_TRACE, hqlip->trace, "  list candidates:\n");
    LL_Iterate (my_area->ll_spath_link_qoses, spath_link_qos) {
	trace (TR_PACKET, hqlip->trace, "  %d:%a (%s)-> %d:%a (%s)%s\n", 
	    spath_link_qos->area1->level, spath_link_qos->area1->id,
	    area_is_r_local (spath_link_qos->area1)?"local":"",
	    spath_link_qos->area2->level, spath_link_qos->area2->id,
	    area_is_r_local (spath_link_qos->area2)?"local":"",
	BIT_TEST (spath_link_qos->flags, LINK_QOS_DELETED)?" deleted":"");
    }

    LL_Iterate (my_area->ll_spath_link_qoses, spath_link_qos) {

        if (BIT_TEST (spath_link_qos->flags, LINK_QOS_DELETED)) {
trace (TR_PACKET, hqlip->trace, "  skip %d:%a -> %d:%a (deleted)\n", 
	spath_link_qos->area1->level, spath_link_qos->area1->id,
	spath_link_qos->area2->level, spath_link_qos->area2->id);
	    continue;
	}

        if (area2 != spath_link_qos->area2) {
trace (TR_PACKET, hqlip->trace, "  skip %d:%a -> %d:%a (area2 x)\n", 
	spath_link_qos->area1->level, spath_link_qos->area1->id,
	spath_link_qos->area2->level, spath_link_qos->area2->id);
	    continue;
	}

        if ((area1 == NULL && area_is_r_local (spath_link_qos->area1)) ||
	    (area1 != NULL && area1 == spath_link_qos->area1)) {
	    /* area1 == null means elink(0,k) lookup */
	    /* exact match anyway */

	    link_qos_t *lqosp;
	    lqosp = hqlip_find_best_qos (spath_link_qos->ll_link_qoses, 
					 req_qos);
	    if (lqosp == NULL) {
trace (TR_PACKET, hqlip->trace, "  skip %d:%a -> %d:%a (qos x)\n", 
	spath_link_qos->area1->level, spath_link_qos->area1->id,
	spath_link_qos->area2->level, spath_link_qos->area2->id);
		if (reason)
	    	    *reason |= SRSVP_MSG_ERR_BANDWIDTH; /* XXX */
		continue;
	    }
trace (TR_PACKET, hqlip->trace, "  found at %d:%a -> %d:%a\n", 
	spath_link_qos->area1->level, spath_link_qos->area1->id,
	spath_link_qos->area2->level, spath_link_qos->area2->id);
		copy_link_qos (lqosp, link_qos);
		*metric = spath_link_qos->metric;
		if (reason)
	    	    *reason = 0;
		return (link_qos);
         }
    }

    if (area2 == NULL || area2->level == 0) {
	/* we don't handle a request such as remote to local */
        if (reason && *reason == 0)
	    *reason = SRSVP_MSG_ERR_UNREACH;
	return (NULL);
    }

    trace (TR_TRACE, hqlip->trace, "  no direct match:\n");
    LL_Iterate (my_area->ll_spath_link_qoses, spath_link_qos) {

        if (BIT_TEST (spath_link_qos->flags, LINK_QOS_DELETED))
	    continue;

        if (area2 != spath_link_qos->area2)
	    continue;

	/* skip it was tried */
        if ((area1 == NULL && area_is_r_local (spath_link_qos->area1)) ||
	    (area1 != NULL && area1 == spath_link_qos->area1))
		continue;

	{
	    link_qos_t lqos;
	    int mm = 0;
	    u_long errcode;
	    memset (&lqos, 0, sizeof (lqos));
if (area1)
trace (TR_PACKET, hqlip->trace, "  indirect %d:%a -> %d:%a\n", 
	area1->level, area1->id,
	spath_link_qos->area1->level, spath_link_qos->area1->id);
else
trace (TR_PACKET, hqlip->trace, "  indirect local -> %d:%a\n", 
	spath_link_qos->area1->level, spath_link_qos->area1->id);
	    if (spath_calc_link_qos2 (hqlip, my_area, 
		    area1, spath_link_qos->area1, req_qos, &lqos, &mm,
		    count, &errcode)) {
if (area1)
trace (TR_PACKET, hqlip->trace, "  found at %d:%a -> %d:%a\n", 
	area1->level, area1->id,
	spath_link_qos->area1->level, spath_link_qos->area1->id);
else
trace (TR_PACKET, hqlip->trace, "  found at local -> %d:%a\n", 
	spath_link_qos->area1->level, spath_link_qos->area1->id);
		link_qos->flag = 0;
		link_qos->pri = lqos.pri;
		link_qos->pps = 999999 /* XXX */;
		link_qos->loh = 0;
		if (link_qos->pps > lqos.pps)
		    link_qos->pps = lqos.pps;
		link_qos->dly += lqos.dly;
		*metric += mm;
		if (reason)
	    	    *reason = 0;
		return (link_qos);
	    }
	    if (reason && !BIT_TEST (errcode, SRSVP_MSG_ERR_UNREACH))
		*reason |= errcode;
	}
    }
    if (reason && *reason == 0)
	*reason = SRSVP_MSG_ERR_UNREACH;
    return (NULL);
}


static link_qos_t *
spath_calc_link_qos (hqlip_t *hqlip, my_area_t *my_area,
		     area_t *area1, area_t *area2, req_qos_t *req_qos,
		     link_qos_t *link_qos, int *metric, u_long *reason)
{
#define HQLIP_LOOKUP_COUNT 16
    if (reason)
	*reason = 0;
    if (metric)
	*metric = 0;
    if (link_qos)
	memset (link_qos, 0, sizeof (link_qos_t));
    return (spath_calc_link_qos2 (hqlip, my_area, area1, area2, req_qos,
				  link_qos, metric, HQLIP_LOOKUP_COUNT,
				  reason));
}


/* XXXXX */
/* transtion from a to b */
static int
hqlip_spath_link_qos_worse (spath_link_qos_t *a, spath_link_qos_t *b)
{
    link_qos_t *aqos, *bqos;

    if (BIT_TEST (a->flags, LINK_QOS_DELETED) &&
	    BIT_TEST (b->flags, LINK_QOS_DELETED))
	return (FALSE);
    if (!BIT_TEST (a->flags, LINK_QOS_DELETED) &&
	    BIT_TEST (b->flags, LINK_QOS_DELETED))
	return (TRUE);
    if (BIT_TEST (a->flags, LINK_QOS_DELETED) &&
	    !BIT_TEST (b->flags, LINK_QOS_DELETED))
	return (FALSE);

    LL_Iterate (a->ll_link_qoses, aqos) {
	LL_Iterate (b->ll_link_qoses, bqos) {
	    if (/* aqos->pri == bqos->pri && */
		    aqos->pps > bqos->pps)
		break;
	}
	/* XXX qos comparison */
	if (bqos)
	    return (TRUE);
    }
    return (FALSE);
}


/* XXXXX */
static int
hqlip_link_qos_comp (spath_link_qos_t *a, spath_link_qos_t *b)
{
    link_qos_t *aqos, *bqos;

    if (BIT_TEST (a->flags, LINK_QOS_DELETED) &&
	    BIT_TEST (b->flags, LINK_QOS_DELETED))
	return (0);
    if (!BIT_TEST (a->flags, LINK_QOS_DELETED) &&
	    BIT_TEST (b->flags, LINK_QOS_DELETED))
	return (-1);
    if (BIT_TEST (a->flags, LINK_QOS_DELETED) &&
	    !BIT_TEST (b->flags, LINK_QOS_DELETED))
	return (1);
    LL_Iterate (a->ll_link_qoses, aqos) {
	LL_Iterate (b->ll_link_qoses, bqos) {
            if (memcmp (aqos, bqos, sizeof (*aqos)) != 0)
                break;
        }
        /* XXX qos comparison */  
        if (bqos)
            return (1);
    }
    /* match */
    return (0);
}


static void
list_link_qos (hqlip_t *hqlip, my_area_t *my_area)
{
    spath_link_qos_t *spath_link_qos;

    LL_Iterate (my_area->ll_spath_link_qoses, spath_link_qos) {
        hqlip_trace_link_qos (TR_TRACE, my_area->trace, 
	      "  list", my_area, spath_link_qos);
    }
}


static int
hqlip_spath_link_qos_equal (spath_link_qos_t *a, spath_link_qos_t *b)
{
    return (a->area1 == b->area1 &&
	    a->area2 == b->area2 &&
	    a->neighbor == b->neighbor &&
	    a->flags == b->flags &&
	    hqlip_link_qos_comp (a, b) == 0);
}


/* a is being updated by b */
static int
hqlip_spath_link_qos_ready (spath_link_qos_t *a, spath_link_qos_t *b)
{
    int diff = 0;
    time_t now;

    /* local time used instead of b's tstamp */
    time (&now);
    if (b->neighbor)
	 diff = HQLIP_LINK_QOS_INTERVAL / 2;

    if (a->ll_bad_updates == NULL) {
	/* the previous was not bad */
	if (a->utime + HQLIP_LINK_QOS_INTERVAL - diff > now) {
	    trace (TR_TRACE, MRT->trace, 
		   "entry is not ready for update (%d sec later)\n",
		   a->utime + HQLIP_LINK_QOS_INTERVAL - diff - now);
	    return (FALSE);
	}
    }
    else {
	/* the previous was bad */
	if (a->ktime == 0) {
	    time_t *utimep;
	    int k = LL_GetCount (a->ll_bad_updates);
	    LL_Iterate (a->ll_bad_updates, utimep) {
	        trace (TR_TRACE, MRT->trace, 
		   "bad update %d time(s) before requires %d sec\n", k,
		   *utimep + k * HQLIP_LINK_QOS_INTERVAL - diff - now);
		if (a->ktime < *utimep + k * HQLIP_LINK_QOS_INTERVAL)
		    a->ktime = *utimep + k * HQLIP_LINK_QOS_INTERVAL;
		k--;
	    }
	}
	/* cached time is available */
	assert (a->ktime);
	if (a->ktime - diff > now) {
	    trace (TR_TRACE, MRT->trace, 
		   "entry is not ready for update (%d sec later)\n",
		   a->ktime - diff - now);
	    return (FALSE);
	}
    }
    return (TRUE);
}


static int
hqlip_inject_spath_link_qos (hqlip_t *hqlip, my_area_t *my_area, 
			     spath_link_qos_t *spath_link_qos)
{
    spath_link_qos_t *lqos;
    u_long flags_saved = 0;

    assert (spath_link_qos->ll_bad_updates == NULL);
    LL_Iterate (my_area->ll_spath_link_qoses, lqos) {

	if (lqos->area1 == spath_link_qos->area1 &&
	    lqos->area2 == spath_link_qos->area2) {

	    if (BIT_TEST (lqos->flags, LINK_QOS_DELETED) &&
	        BIT_TEST (spath_link_qos->flags, LINK_QOS_DELETED)) {
    	        hqlip_trace_link_qos (TR_TRACE, my_area->trace, 
        	BIT_TEST (lqos->flags, LINK_QOS_EXTERNAL)? 
			"already deleted (elink-qos)": 
			"already deleted (ilink-qos)", 
			my_area, spath_link_qos);
	        destroy_spath_link_qos (spath_link_qos);
		return (FALSE);
	    }

	    if (lqos->neighbor == NULL &&
		    hqlip_spath_link_qos_equal (lqos, spath_link_qos)) {
		/* exactly same (both were locally generated) */
		/* this happens when re-calculating */
    	        hqlip_trace_link_qos (TR_TRACE, my_area->trace, 
        	BIT_TEST (lqos->flags, LINK_QOS_EXTERNAL)? 
			"same (elink-qos)": "same (ilink-qos)", 
			my_area, spath_link_qos);
	        destroy_spath_link_qos (spath_link_qos);
	    	return (FALSE);
	    }

	    if (hqlip_spath_link_qos_worse (lqos, spath_link_qos)) {
		time_t *utimep = New (time_t);
		assert (spath_link_qos->ll_bad_updates == NULL);
	        spath_link_qos->ll_bad_updates = lqos->ll_bad_updates;
	        lqos->ll_bad_updates = NULL;
		*utimep = spath_link_qos->utime;
		LL_Add2 (spath_link_qos->ll_bad_updates, utimep);
		spath_link_qos->ktime = 0;
    	        hqlip_trace_link_qos (TR_TRACE, my_area->trace, 
			"registered as wrose", my_area, spath_link_qos);
	    }
	    /* avoid delete and delete condition */
	    else if (!BIT_TEST (spath_link_qos->flags, LINK_QOS_DELETED)) {
		if (!hqlip_spath_link_qos_ready (lqos, spath_link_qos)) {
		    if (spath_link_qos->neighbor) {
		        BIT_SET (spath_link_qos->flags, LINK_QOS_DELETED);
		        /* will be deleted */
    	       	        hqlip_trace_link_qos (TR_ERROR, my_area->trace, 
        		    BIT_TEST (lqos->flags, LINK_QOS_EXTERNAL)? 
			    "frequent (elink-qos)": "frequent (ilink-qos)", 
			    my_area, spath_link_qos);
		    }
		    else {
    	       	        hqlip_trace_link_qos (TR_WARN, my_area->trace, 
        		    BIT_TEST (lqos->flags, LINK_QOS_EXTERNAL)? 
			    "delayed (elink-qos)": "delayed (ilink-qos)", 
			    my_area, spath_link_qos);
		        if (lqos->delayed_link_qos)
			    destroy_spath_link_qos (lqos->delayed_link_qos);
		        lqos->delayed_link_qos = spath_link_qos;
		        return (FALSE);
		    }
	        }
	    }
	    LL_Remove (my_area->ll_spath_link_qoses, lqos);
	    flags_saved = lqos->flags;
    	    hqlip_trace_link_qos (TR_TRACE, my_area->trace, 
        	BIT_TEST (lqos->flags, LINK_QOS_EXTERNAL)? 
			"removed (elink-qos)": "removed (ilink-qos)", 
			my_area, lqos);
	    destroy_spath_link_qos (lqos);
	    break;
	}
    }

    assert (my_area->area->level > spath_link_qos->area1->level);
    assert (BIT_TEST (spath_link_qos->flags, LINK_QOS_EXTERNAL) ||
	    my_area->area->level > spath_link_qos->area2->level);

    /* always inject even in case of delete to keep history */
    /* there is a loop back link */
    /* assert (spath_link_qos->area1 != spath_link_qos->area2); */
    LL_Add (my_area->ll_spath_link_qoses, spath_link_qos);
    hqlip_trace_link_qos (TR_TRACE, my_area->trace, 
        BIT_TEST (spath_link_qos->flags, LINK_QOS_EXTERNAL)?
			  "inject (elink-qos)": "inject (ilink-qos)",
			  my_area, spath_link_qos);

    if (spath_link_qos->neighbor == NULL)
        hqlip_send_link_qos (hqlip, my_area, NULL, spath_link_qos);
    hqlip_update_database (hqlip, my_area);

#ifdef notdef
    if (my_area_is_center (my_area)) {
	if (BIT_TEST (spath_link_qos->flags, LINK_QOS_EXTERNAL)) {
	    trace (TR_TRACE, my_area->trace, 
		   "follwoing the external link to %d:%a\n",
		   spath_link_qos->area2->level,
		   spath_link_qos->area2->id);
	    /* try ilink calc with its elink area2 */
	    hqlip_calc_ilink (hqlip, my_area, spath_link_qos->area2);
	}
	else {
	    /* try ilink calc with all elink area2 */
	    LL_Iterate (my_area->ll_spath_link_qoses, lqos) {
		 if (BIT_TEST (lqos->flags, LINK_QOS_EXTERNAL)) {
	    	    hqlip_calc_ilink (hqlip, my_area, lqos->area2);
	    	    trace (TR_TRACE, my_area->trace, 
			   "following the internal link to %d:%a\n",
		   	   lqos->area2->level,
		   	   lqos->area2->id);
		}
	    }
	}
    }
#endif

    return (TRUE);
}


/* a new ilink will be injected into may_area->parent */
/* calculate my_area's center to elink's dest area2 */
/* my_area has to be a center since only a center does this */
static void
hqlip_calc_ilink (hqlip_t *hqlip, my_area_t *my_area, area_t *area2)
{
    req_qos_t req_qos;
    link_qos_t link_qos;
    spath_link_qos_t *spath_link_qos;
    int metric = 0;
    area_t *area1;
    u_long flags = 0;

    area1 = my_area->winner->area;
    trace (TR_TRACE, my_area->trace, 
	    "%s at %d:%a ilink-qos calc %d:%a -> %d:%a\n", 
	   my_area->name, my_area->area->level, my_area->area->id,
	   my_area->area->level, my_area->area->id,
	   area2->level, area2->id);

    if (BIT_TEST (my_area->flags, HQLIP_MY_AREA_SYNCING)) {
        trace (TR_TRACE, my_area->trace, "my area is under syncing\n");
	return;
    }
    if (BIT_TEST (my_area->parent->flags, HQLIP_MY_AREA_SYNCING)) {
        trace (TR_TRACE, my_area->trace, "my parent is under syncing\n");
	return;
    }
    if (my_area->winner == NULL) {
        trace (TR_TRACE, my_area->trace, "no center available now\n");
	return;
    }
/*
    if (!my_area_is_center (my_area)) {
        trace (TR_TRACE, my_area->trace, "I am not a center\n");
	return;
    }
*/

#if 0
    req_qos.pri = SSPEC_PRI_USER;
    req_qos.mtu = SSPEC_MTU_SIZE;
    req_qos.pps = SSPEC_AGPPS;
    req_qos.sec = 0;
    req_qos.cd = 1;
    req_qos.cf = 0;
    req_qos.rdly = 0;
    req_qos.rfee = 0;
#endif

    /* find if area2 has the same parent (my_area) */
    if (!area_is_child (my_area->parent, area2)) {
        BIT_SET (flags, LINK_QOS_EXTERNAL);
	/* we do only in this case for external */
	assert (area_is_r_local (area1));
    }

    /* center to elink dest */
    if (spath_calc_link_qos (hqlip, my_area, 
		BIT_TEST (flags, LINK_QOS_EXTERNAL)? area1: NULL,
			area2, NULL, &link_qos, &metric, NULL) == NULL) {
	trace (TR_WARN, my_area->trace, 
		"calic_ilink: link-qos not found %d:%a -> %d:%a\n", 
		area1->level, area1->id, area2->level, area2->id);

	BIT_SET (flags, LINK_QOS_DELETED);
    }

    spath_link_qos = spath_link_qos_create (hqlip, my_area->area, area2, 
					    metric, 
		BIT_TEST (flags, LINK_QOS_DELETED)? NULL: 
		copy_link_qos (&link_qos, NULL), flags);
    hqlip_inject_spath_link_qos (hqlip, my_area->parent, spath_link_qos);
}


static void
spath_calc_elink (hqlip_t *hqlip, my_area_t *my_area, 
		  hqlip_interface_t *vif, area_t *area)
{
    req_qos_t req_qos;
    link_qos_t link_qos;
    spath_link_qos_t *spath_link_qos;
    my_area_t *my_area0;
    int metric = 0;
    u_long flags = LINK_QOS_EXTERNAL;

    my_area0 = vif->my_area0;
    trace (TR_TRACE, my_area->trace, 
	    "calc_elink in %s at %d:%a elink-qos %d:%a -> %d:%a on %s\n", 
	   my_area->name, my_area->area->level, my_area->area->id,
	   my_area0->area->level, my_area0->area->id, 
	   area->level, area->id,
	   vif->interface->name);

#if 0
    req_qos.pri = SSPEC_PRI_USER;
    req_qos.mtu = SSPEC_MTU_SIZE;
    req_qos.pps = SSPEC_AGPPS;
    req_qos.sec = 0;
    req_qos.cd = 1;
    req_qos.cf = 0;
    req_qos.rdly = 0;
    req_qos.rfee = 0;
#endif
    if (area->my_area->winner == NULL) {
	trace (TR_WARN, my_area->trace, 
		"calc_elink: no center available for %d:%a\n", 
		area->level, area->id);
	return;
    }
    if (spath_calc_link_qos (hqlip, area->my_area, NULL, 
				area->my_area->winner->area, 
			 	NULL, &link_qos, &metric, NULL) == NULL) {
	trace (TR_TRACE, my_area->trace, 
		"calc_elink: elink-qos not found for %d:%a\n", 
		area->level, area->id);
	BIT_SET (flags, LINK_QOS_DELETED);
    }
    spath_link_qos = spath_link_qos_create (hqlip, my_area0->area, area, 
					    metric, 
			BIT_TEST (flags, LINK_QOS_DELETED)? NULL:
			copy_link_qos (&link_qos, NULL), flags);
    hqlip_inject_spath_link_qos (hqlip, my_area0->parent, spath_link_qos);
}


static void
hqlip_get_interface_mask (my_area_t *my_area, 
			  interface_bitset_t *interface_mask_p)
{
    my_area_t *child;

    if (my_area->area->level <= 0) {
	BITX_SET (interface_mask_p, my_area->vif->interface->index);
	return;
    }
    LL_Iterate (my_area->ll_children, child) {
	hqlip_get_interface_mask (child, interface_mask_p);
    }
}


/* for my_area's sub-areas */
static void
hqlip_update_elink (hqlip_t *hqlip, my_area_t *my_area, hqlip_interface_t *vif)
{
    my_area_t *child;

    if (my_area->area->level >= 2) {
	interface_bitset_t parent_ifmask;
	my_area_t *my_root = NULL;

	memset (&parent_ifmask, 0, sizeof (parent_ifmask));
	hqlip_get_interface_mask (my_area, &parent_ifmask);

        LL_Iterate (my_area->ll_children, child) {
	    interface_bitset_t children_ifmask;

	    memset (&children_ifmask, 0, sizeof (children_ifmask));
	    hqlip_get_interface_mask (child, &children_ifmask);
	    ifxor (&parent_ifmask, &children_ifmask, &parent_ifmask,
		   sizeof (interface_bitset_t));

	    if (BITX_TEST (&children_ifmask, vif->interface->index)) {
		assert (my_root == NULL);
                my_root = child;
	    }
	    else {
	        spath_calc_elink (hqlip, my_area, vif, child->area);
	    }
	}
	if (!ifzero (&parent_ifmask, sizeof (parent_ifmask))) {
	    int i;

	    assert (my_root);
	    for (i = 0; i < MAX_INTERFACES; i++) {
		if (!BITX_TEST (&parent_ifmask, i))
		    continue;
		spath_calc_elink (hqlip, my_area, 
				  hqlip->hqlip_interfaces[i], my_root->area);
	    }
	}
    }
}


static spath_link_qos_t *
spath_link_qos_create (hqlip_t *hqlip, 
                       area_t *area1, area_t *area2,
                       int metric, link_qos_t *link_qos, u_long flags)
{
    time_t now;

    spath_link_qos_t *spath_link_qos;
    spath_link_qos = New (spath_link_qos_t);
    spath_link_qos->area1 = area1;
    spath_link_qos->area2 = area2;
    spath_link_qos->metric = metric;
    spath_link_qos->ll_link_qoses = LL_Create (0);
    if (link_qos)
	LL_Add (spath_link_qos->ll_link_qoses, link_qos);
    time (&now);
    spath_link_qos->tstamp = now;
    spath_link_qos->flags = (flags | LINK_QOS_CHANGED);
    spath_link_qos->ctime = now;
    spath_link_qos->utime = now;
    return (spath_link_qos);
}


/* XXX non thread-safe */
static void 
hqlip_delayed_link_qos (hqlip_t *hqlip, my_area_t *my_area)
{
    my_area_t *child;
    spath_link_qos_t *spath_link_qos;
    LINKED_LIST *ll_delays = NULL;

    LL_Iterate (my_area->ll_children, child)
	hqlip_delayed_link_qos (hqlip, child);

    /* first gather delayed entries since the list may change */
    LL_Iterate (my_area->ll_spath_link_qoses, spath_link_qos) {
	if (spath_link_qos->delayed_link_qos) {
	   if (hqlip_spath_link_qos_ready (spath_link_qos, 
		    spath_link_qos->delayed_link_qos)) {
		LL_Add2 (ll_delays, spath_link_qos->delayed_link_qos);
		spath_link_qos->delayed_link_qos = NULL;
	    }
	}
    }

    if (ll_delays == NULL)
	return;

    LL_Iterate (ll_delays, spath_link_qos) {
    	trace (TR_TRACE, my_area->trace, "delayed entry being processed\n");
	hqlip_inject_spath_link_qos (hqlip, my_area, spath_link_qos);
    }
    LL_Destroy (ll_delays);
}


static void
hqlip_send_hello (hqlip_t *hqlip, hqlip_interface_t *vif)
{
    char buffer[HQLIP_UDP_SIZE], *cp = buffer;

    if (!hqlip->running)
	return;

    /* XXX should have a separate timer */
    hqlip_delayed_link_qos (hqlip, hqlip->root);

    if (vif->udp_sockfd >= 0) {
	if (vif->prefix) {
	    /* fill my address to avoid a zero length udp packet */
    	    int plen = 4;
	    assert (vif->prefix->family == hqlip->family);
#ifdef HAVE_IPV6
	    if (hqlip->family == AF_INET6)
	        plen = 16;
#endif /* HAVE_IPV6 */
    	    MRT_PUT_DATA (prefix_tochar (vif->prefix), plen, cp);
	}
	/* MSG_MULTI_LOOP should be redundant */
        send_packet (vif->udp_sockfd, buffer, cp - buffer, /*MSG_MULTI_LOOP*/0,
                     hqlip->all_hosts, HQLIP_UDP_PORT, vif->interface, 0);
    }
}


static int
hqlip_write (hqlip_neighbor_t *neighbor, u_char *data, int len)
{
    int ret;

    if (neighbor->sockfd < 0)
	return (-1);
    ret = write (neighbor->sockfd, data, len);
    if (ret < 0) {
	trace (TR_ERROR, neighbor->trace,
	       "write failed %m on fd %d\n", neighbor->sockfd);
    }
    else {
	trace (TR_PACKET, neighbor->trace, "write %d bytes\n", ret);
	neighbor->num_packets_sent++;
	Timer_Reset_Time (neighbor->keep_alive);
    }
    return (ret);
}


#ifndef HAVE_LIBPTHREAD
static void
destroy_packet (packet_t *packet)
{
    Delete (packet->data);
    Delete (packet);
}


static int
hqlip_flush_queue (hqlip_t *hqlip, hqlip_neighbor_t * neighbor)
{   
    packet_t *packet;
    int ret;
    
    for (;;) {
        pthread_mutex_lock (&neighbor->send_mutex_lock);
        packet = LL_GetHead (neighbor->send_queue);
        if (packet == NULL) {
	    /* end of queue */
            pthread_mutex_unlock (&neighbor->send_mutex_lock);
	    return (1);
        }
        LL_RemoveFn (neighbor->send_queue, packet, NULL);
        pthread_mutex_unlock (&neighbor->send_mutex_lock);

        ret = hqlip_write (neighbor, packet->data, packet->len);
    
        if (ret == 0) {
	    /* try again */
            pthread_mutex_lock (&neighbor->send_mutex_lock);
	    LL_Prepend (neighbor->send_queue, packet);
	    select_enable_fd_mask (neighbor->sockfd, SELECT_WRITE);
            pthread_mutex_unlock (&neighbor->send_mutex_lock);
	    return (0);
        }
    	destroy_packet (packet);
	if (ret < 0)
	    return (ret);
    }
    return (0);
}   
#endif /* HAVE_LIBPTHREAD */


static int 
hqlip_send_message (hqlip_t *hqlip, hqlip_neighbor_t *neighbor, 
		    int flags, int type, int level, int len, time_t tstamp,
		    u_char *data)
{
    assert (type >= HQLIP_MSG_KEEP_ALIVE && type <= HQLIP_MSG_SYNC);
    assert (len >= 0 && len + HQLIP_MSG_HDR_SIZE < HQLIP_MSG_SIZE);

    if (neighbor->sockfd < 0)
	return (-1);
    /* is timestamp required for keep alive? */
    if (tstamp == 0)
	time (&tstamp);
{
#ifdef HAVE_LIBPTHREAD
    u_char msgbuf[HQLIP_MSG_SIZE];
    u_char *cp = msgbuf;
#else
    u_char *cp = NewArray (u_char, len + HQLIP_MSG_HDR_SIZE);
    packet_t *packet = New (packet_t);
    packet->data = cp;
    packet->len = len + HQLIP_MSG_HDR_SIZE;
#endif /* HAVE_LIBPTHREAD */

    MRT_PUT_BYTE (flags, cp);
    MRT_PUT_BYTE (type, cp);
    MRT_PUT_BYTE (level, cp);
    MRT_PUT_BYTE (0, cp); /* reserved */
    MRT_PUT_SHORT (0, cp); /* reserved */
    MRT_PUT_SHORT (len + HQLIP_MSG_HDR_SIZE, cp); /* includes common header */
    MRT_PUT_LONG (tstamp, cp);
    if (len > 0)
	memcpy (cp, data, len);

#ifdef HAVE_LIBPTHREAD
    /* send it directly since I am a thread */
    return (hqlip_write (neighbor, msgbuf, len + HQLIP_MSG_HDR_SIZE));
#else
    pthread_mutex_lock (&neighbor->send_mutex_lock);
    LL_Append (neighbor->send_queue, packet);
    if (LL_GetCount (neighbor->send_queue) == 1) {
	select_enable_fd_mask (neighbor->sockfd, SELECT_WRITE);
    }
    pthread_mutex_unlock (&neighbor->send_mutex_lock);
    trace (TR_PACKET, neighbor->trace, "send %s at %d (%d bytes) queued\n",
           hqlip_pdus[type], level, len + HQLIP_MSG_HDR_SIZE);
    return (0);
#endif /* HAVE_LIBPTHREAD */
}
}


static void
hqlip_forward_message (hqlip_t *hqlip, my_area_t *my_area, 
		       hqlip_neighbor_t *from, 
		       int flags, int type, int level, int len, time_t tstamp,
		       u_char *data)
{
    hqlip_neighbor_t *neighbor;

    LL_Iterate (my_area->ll_neighbors, neighbor) {
	if (neighbor == from)
	    continue;
	hqlip_send_message (hqlip, neighbor,
                    	    flags, type, level, len, tstamp, data);
    }
}

    
static void
hqlip_send_keep_alive (hqlip_t *hqlip, hqlip_neighbor_t *neighbor)
{
    hqlip_send_message (hqlip, neighbor, 0, HQLIP_MSG_KEEP_ALIVE, 0, 0, 0,
			NULL);
}


static int
hqlip_send_sync (hqlip_t *hqlip, int level, hqlip_neighbor_t *neighbor)
{
    return (hqlip_send_message (hqlip, neighbor, 0, HQLIP_MSG_SYNC, level, 
				0, 0, NULL));
}


static u_char *
hqlip_put_area (area_t *area, u_char *cp)
{
    int len = 4; /* for address part */
    int afi = family2afi (area->id->family);
    u_char *addr = prefix_tochar (area->id);

    if (afi == AFI_IP6) {
	len = 8;
	if (area->level <= 0) {
	    /* host id part for level 0 */
	    addr += 8;
	}
    }

    MRT_PUT_BYTE (afi, cp);
    MRT_PUT_BYTE (area->level, cp);
    MRT_PUT_SHORT (len + 4, cp);
    MRT_PUT_DATA (addr, len, cp);
    return (cp);
}


static u_char *
hqlip_get_area (area_t **area_p, u_char *cp, hqlip_neighbor_t *neighbor)
{
    int afi, level, len;
    u_char addr[16], *start = addr;
    prefix_t *prefix;
    int bitlen = 32;

    MRT_GET_BYTE (afi, cp);
    MRT_GET_BYTE (level, cp);
    MRT_GET_SHORT (len, cp);
    if (afi != AFI_IP && afi != AFI_IP6) {
	trace (TR_INFO, neighbor->trace, "unknown afi %d\n", afi);
	return (NULL);
    }
    if (level <= 0 && level > HQLIP_AREA_LEVEL_INTERNET) {
	trace (TR_INFO, neighbor->trace, "wrong level %d\n", level);
	return (NULL);
    }
    if (len != 8 && len != 12) {
	trace (TR_INFO, neighbor->trace, "wrong len %d\n", len);
	return (NULL);
    }
    if (!((afi == AFI_IP && len == 8) || (afi == AFI_IP6 && len == 12))) {
	trace (TR_INFO, neighbor->trace, "afi %d and len %d mismatch\n");
	return (NULL);
    }
    if (afi == AFI_IP6) {
	if (level <= 0) {
	    memset (addr, 0, 8);
	    start += 8;
	}
	else {
	    memset (addr + 8, 0, 8);
	}
	bitlen = 128;
    }
    MRT_GET_DATA (start, len - 4, cp);
    prefix = New_Prefix (afi2family (afi), addr, bitlen);
    assert (area_p);
    *area_p = add_area (level, prefix);
    Deref_Prefix (prefix);
    return (cp);
}


static u_char *
hqlip_put_addr (prefix_t *prefix, u_char *cp)
{
    int len = 4; /* for address part */
    int afi = family2afi (prefix->family);
    int bitlen = prefix->bitlen;
    u_char *addr = prefix_tochar (prefix);

    if (afi == AFI_IP6) {
	len = 8;
	if (bitlen > 64)
	    bitlen = 64;
    }
    MRT_PUT_BYTE (afi, cp);
    MRT_PUT_BYTE (bitlen, cp);
    MRT_PUT_SHORT (len + 4, cp);
    MRT_PUT_DATA (addr, len, cp);
    return (cp);
}


static u_char *
hqlip_get_addr (prefix_t **prefix_p, u_char *cp, hqlip_neighbor_t *neighbor)
{
    int afi, bitlen, len;
    u_char addr[16];

    MRT_GET_BYTE (afi, cp);
    MRT_GET_BYTE (bitlen, cp);
    MRT_GET_SHORT (len, cp);
    if (afi != AFI_IP && afi != AFI_IP6) {
	trace (TR_INFO, neighbor->trace, "unknown afi %d\n", afi);
	return (NULL);
    }
    if (!(afi == AFI_IP && bitlen <= 32) || (afi == AFI_IP6 && bitlen <= 64)) {
	trace (TR_INFO, neighbor->trace, "wrong bitlen %d\n", bitlen);
	return (NULL);
    }
    if (len != 8 && len != 12) {
	trace (TR_INFO, neighbor->trace, "wrong len %d\n", len);
	return (NULL);
    }
    if (!((afi == AFI_IP && len == 8) || (afi == AFI_IP6 && len == 12))) {
	trace (TR_INFO, neighbor->trace, "afi %d and len %d mismatch\n");
	return (NULL);
    }
    if (afi == AFI_IP6)
	memset (addr + 8, 0, 8);
    MRT_GET_DATA (addr, len - 4, cp);
    assert (prefix_p);
    *prefix_p = New_Prefix (afi2family (afi), addr, bitlen);
    return (cp);
}


static char *
hqlip_prepare_link_qos (hqlip_t *hqlip, spath_link_qos_t *spath_link_qos, 
		        char *cp)
{
    link_qos_t *link_qos;

    cp = hqlip_put_area (spath_link_qos->area1, cp);
    cp = hqlip_put_area (spath_link_qos->area2, cp);
    if (!BIT_TEST (spath_link_qos->flags, LINK_QOS_DELETED)) {
        MRT_PUT_LONG (spath_link_qos->metric, cp);
	LL_Iterate (spath_link_qos->ll_link_qoses, link_qos) {
            MRT_PUT_BYTE ((link_qos->flag << 7) | link_qos->pri, cp);
            MRT_PUT_BYTE (link_qos->loh, cp);
            MRT_PUT_SHORT (link_qos->rsvd, cp);
            MRT_PUT_LONG (link_qos->pps, cp);
            MRT_PUT_LONG (link_qos->dly, cp);
	}
    }
    return (cp);
}


static void
hqlip_trace_link_qos (u_long flags, trace_t *tr, char *head,
		      my_area_t *my_area, spath_link_qos_t *spath_link_qos)
{
    link_qos_t *link_qos;

    trace (flags, tr, 
		"%s at %d:%s link-qos %d:%a -> %d:%a%s%s\n",
		head, my_area->area->level, my_area->name,
	spath_link_qos->area1->level, spath_link_qos->area1->id,
	spath_link_qos->area2->level, spath_link_qos->area2->id,
	BIT_TEST (spath_link_qos->flags, LINK_QOS_EXTERNAL)?
		" external": "",
	BIT_TEST (spath_link_qos->flags, LINK_QOS_DELETED)?
		" deleted": "");

    if (!BIT_TEST (spath_link_qos->flags, LINK_QOS_DELETED)) {
        LL_Iterate (spath_link_qos->ll_link_qoses, link_qos) {
            if (link_qos->flag)
                trace (flags, tr,
                        "  pri %u pps %u dly %u loh %u\n",
                        link_qos->pri, link_qos->pps, link_qos->dly,
                        link_qos->loh);
            else
                trace (flags, tr, 
                        "  pri %u pps %u dly %u\n",
                        link_qos->pri, link_qos->pps, link_qos->dly);
	}
    }
}


static void
hqlip_send_link_qos (hqlip_t *hqlip, my_area_t *my_area, 
		     hqlip_neighbor_t *neighbor, 
		     spath_link_qos_t *specified)
{
    spath_link_qos_t *spath_link_qos;
    hqlip_neighbor_t *receiver;

    LL_Iterate (my_area->ll_spath_link_qoses, spath_link_qos) {
	char msgbuf[HQLIP_MSG_SIZE], *cp = msgbuf;
        int flags = 0;

	if (specified && spath_link_qos != specified)
	    continue;
	if (neighbor && BIT_TEST (spath_link_qos->flags, LINK_QOS_DELETED))
	    continue;

        cp = hqlip_prepare_link_qos (hqlip, spath_link_qos, cp);

	/* if neighbor is supplied, it means the first syncing */
	if (neighbor)
	    flags |= HQLIP_MSGF_NOTSYNCED;
	if (BIT_TEST (spath_link_qos->flags, LINK_QOS_EXTERNAL))
	    flags |= HQLIP_MSGF_EXTERNAL;

        LL_Iterate (my_area->ll_neighbors, receiver) {
	    if (spath_link_qos->neighbor == receiver)
	        continue;
	    if (neighbor && neighbor != receiver)
	        continue;
            hqlip_send_message (hqlip, receiver, flags,
		        HQLIP_MSG_LINK_QOS, my_area->area->level, 
		        cp - msgbuf, spath_link_qos->tstamp, msgbuf);
	    hqlip_trace_link_qos (TR_PACKET, receiver->trace, "sent", 
				  my_area, spath_link_qos);
	}
    }
}


static void
destroy_spath_link_qos (spath_link_qos_t *spath_link_qos)
{
    if (spath_link_qos->ll_link_qoses)
	LL_DestroyFn (spath_link_qos->ll_link_qoses, Destroy);
    if (spath_link_qos->delayed_link_qos)
	destroy_spath_link_qos (spath_link_qos->delayed_link_qos);
    if (spath_link_qos->ll_bad_updates)
	LL_DestroyFn (spath_link_qos->ll_bad_updates, Destroy);
    Destroy (spath_link_qos);
}


static void
hqlip_recv_link_qos (hqlip_t *hqlip, hqlip_neighbor_t *neighbor, 
		     my_area_t *my_area, int flags, 
		     int len, time_t tstamp, u_char *cp)
{
    spath_link_qos_t *spath_link_qos, *slq;
    u_char *begin = cp;
    u_char *end = cp + len;
    time_t now;
    int dont_forward = 0;

    time (&now);
    spath_link_qos = New (spath_link_qos_t);
    cp = hqlip_get_area (&spath_link_qos->area1, cp, neighbor);
    cp = hqlip_get_area (&spath_link_qos->area2, cp, neighbor);
    if (cp >= end) {
	BIT_SET (spath_link_qos->flags, LINK_QOS_DELETED);
    }
    else {
        spath_link_qos->ll_link_qoses = LL_Create (0);
        MRT_GET_LONG (spath_link_qos->metric, cp);
	while (end - cp >= sizeof (link_qos_t)) {
	    int temp;
    	    link_qos_t *link_qos;

    	    link_qos = New (link_qos_t);
            MRT_GET_BYTE (temp, cp);
	    link_qos->flag = (temp >> 7);
	    link_qos->pri = (temp & 0x7f);
            MRT_GET_BYTE (link_qos->loh, cp);
            MRT_GET_SHORT (link_qos->rsvd, cp);
            MRT_GET_LONG (link_qos->pps, cp);
            MRT_GET_LONG (link_qos->dly, cp);
	    LL_Add2 (spath_link_qos->ll_link_qoses, link_qos);
	}
	if (cp != end) {
	    trace (TR_INFO, neighbor->trace, "wrong data boundary (%d)\n",
		  end - cp);
	    len = len - (end - cp); /* adjusted for forwarding XXX */
	}
    }

    spath_link_qos->tstamp = tstamp;
    spath_link_qos->ctime = now;
    spath_link_qos->utime = now;
    spath_link_qos->neighbor = neighbor;
    BIT_SET (spath_link_qos->flags, LINK_QOS_CHANGED);
    if (BIT_TEST (flags, HQLIP_MSGF_EXTERNAL))
	BIT_SET (spath_link_qos->flags, LINK_QOS_EXTERNAL);

    LL_Iterate (my_area->ll_spath_link_qoses, slq) {
	if (slq->area1 == spath_link_qos->area1 &&
	    slq->area2 == spath_link_qos->area2 &&
	    slq->neighbor != spath_link_qos->neighbor) {
	    trace (TR_TRACE, neighbor->trace, "the following is being "
			"updated by another router %s -> %s\n",
		   slq->neighbor? prefix_toa (slq->neighbor->prefix): "local",
		   spath_link_qos->neighbor? 
		       prefix_toa (spath_link_qos->neighbor->prefix): "local");
	    dont_forward++;
	}
	if (slq->area1 == spath_link_qos->area1 &&
	    slq->area2 == spath_link_qos->area2 &&
	    slq->neighbor == spath_link_qos->neighbor)
	    break;
    }

    if (spath_link_qos->area1->level >= my_area->area->level) {
        trace (TR_WARN, neighbor->trace, 
	       "link-qos area1 level %d wrong for %s at %d\n", 
		spath_link_qos->area1->level, my_area->name, 
		my_area->area->level);
	Delete (spath_link_qos);
  	return;
    }

    if (spath_link_qos->area1 == spath_link_qos->area2) {
        trace (TR_WARN, neighbor->trace, 
	       "link-qos both area1 and area2 is same with %d:%a\n", 
		spath_link_qos->area1->level, spath_link_qos->area1->id);
	Delete (spath_link_qos);
  	return;
    }

    if (BIT_TEST (spath_link_qos->flags, LINK_QOS_DELETED)) {
        hqlip_trace_link_qos (TR_PACKET, neighbor->trace, 
			      "recv (del)", my_area, spath_link_qos);
        if (hqlip_inject_spath_link_qos (hqlip, my_area, spath_link_qos)) {
	    if (!dont_forward)
	        hqlip_forward_message (hqlip, my_area, neighbor, flags, 
				HQLIP_MSG_LINK_QOS, my_area->area->level, 
				len, tstamp, begin);
	}
    }
    else if (slq == NULL) {
        hqlip_trace_link_qos (TR_PACKET, neighbor->trace, 
			      "recv (new)", my_area, spath_link_qos);
        if (hqlip_inject_spath_link_qos (hqlip, my_area, spath_link_qos)) {
	    if (!dont_forward)
	        hqlip_forward_message (hqlip, my_area, neighbor, flags, 
			       HQLIP_MSG_LINK_QOS, my_area->area->level, 
			       len, tstamp, begin);
	}
    }
    else if (tstamp > slq->tstamp) {
	/* newer */
        hqlip_trace_link_qos (TR_PACKET, neighbor->trace, 
			      "recv (update)", my_area, spath_link_qos);
        if (hqlip_inject_spath_link_qos (hqlip, my_area, spath_link_qos))
	    hqlip_forward_message (hqlip, my_area, neighbor, flags, 
				    HQLIP_MSG_LINK_QOS, my_area->area->level, 
				    len, tstamp, begin);
    }
    else {
        hqlip_trace_link_qos (TR_PACKET, neighbor->trace, 
				  "recv (ignore)", my_area, spath_link_qos);
	destroy_spath_link_qos (spath_link_qos);
    }
}


static void
hqlip_trace_area_center (u_long flags, trace_t *tr, char *head,
	      my_area_t *my_area, spath_area_center_t *spath_area_center)
{
    /* char strbuf[64]; */

    if (BIT_TEST (spath_area_center->flags, AREA_CENTER_DELETED))
        /*trace (flags, tr, "%s at %d:%s area-center %d:%a from %s deleted\n",*/
        trace (flags, tr, "%s at %d:%s area-center %d:%a deleted\n",
	   head, my_area->area->level, my_area->name,
	   spath_area_center->area->level, spath_area_center->area->id /*,
	   inet_ntop (AF_INET, &spath_area_center->router_id, 
			strbuf, sizeof (strbuf))*/);
    else
        /*trace (flags, tr, "%s at %d:%s area-center %d:%a from %s pri %d\n",*/
        trace (flags, tr, "%s at %d:%s area-center %d:%a pri %d\n",
	   head, my_area->area->level, my_area->name,
	   spath_area_center->area->level, spath_area_center->area->id,
	   /* inet_ntop (AF_INET, &spath_area_center->router_id, 
			strbuf, sizeof (strbuf)),*/
	   spath_area_center->pri);
}


static void
hqlip_send_area_center (hqlip_t *hqlip, my_area_t *my_area, 
		hqlip_neighbor_t *neighbor, spath_area_center_t *specified)
{
    spath_area_center_t *spath_area_center;
    hqlip_neighbor_t *receiver;

    LL_Iterate (my_area->ll_spath_area_centers, spath_area_center) {
	char msgbuf[HQLIP_MSG_SIZE], *cp = msgbuf;
        int flags = 0;

	if (specified && spath_area_center != specified)
	    continue;
	if (neighbor && 
		BIT_TEST (spath_area_center->flags, AREA_CENTER_DELETED))
	    continue;

	 /* originating & it's center is local */
	if (area_is_local (spath_area_center->area) && (
	      spath_area_center->area->my_area->winner == NULL ||
	      !area_is_local (spath_area_center->area->my_area->winner->area)))
	    continue;

        cp = hqlip_put_area (spath_area_center->area, cp);
        /* MRT_PUT_NETLONG (spath_area_center->router_id, cp); */
        if (!BIT_TEST (spath_area_center->flags, AREA_CENTER_DELETED)) {
            MRT_PUT_BYTE (spath_area_center->pri, cp);
            MRT_PUT_BYTE (0, cp);
            MRT_PUT_SHORT (0, cp);
	}
	/* if neighbor is supplied, it means the first syncing */
	if (neighbor)
	    flags |= HQLIP_MSGF_NOTSYNCED;

        LL_Iterate (my_area->ll_neighbors, receiver) {
	    if (spath_area_center->neighbor == receiver)
	        continue;
	    if (neighbor && neighbor != receiver)
	        continue;
            hqlip_send_message (hqlip, receiver, flags,
		        HQLIP_MSG_AREA_CENTER, my_area->area->level, 
		        cp - msgbuf, spath_area_center->tstamp, msgbuf);
	    hqlip_trace_area_center (TR_PACKET, receiver->trace, 
				  "sent", my_area, spath_area_center);
	}
    }
}


static int 
spath_area_center_compare (spath_area_center_t *a, spath_area_center_t *b)
{
    if (a->pri == b->pri) {
        if (a->area != b->area) {
    	    assert (0); /* should not happen */
	    return (0);
        }
	if (area_is_local (a->area) &&
		a->area->my_area->winner &&
	        area_is_local (a->area->my_area->winner->area))
	    return (-1);
        return (0);
        /* return (a->router_id - b->router_id); */
	    /* smaller router id wins */
    }
    return (a->pri - b->pri);
    /* smaller priority wins */
}


static void
hqlip_ask_descendant_calc (hqlip_t *hqlip, my_area_t *child,
			   area_t *area2)
{
    my_area_t *descendant;

    if (child->winner && area_is_r_local (child->winner->area))
	hqlip_calc_ilink (hqlip, child, area2);
    if (child->area->level <= 1)
	return;
    LL_Iterate (child->ll_children, descendant)
	hqlip_ask_descendant_calc (hqlip, descendant, area2);
}


static void
hqlip_update_database (hqlip_t *hqlip, my_area_t *my_area)
{
    my_area_t *ancestor, *child;
    my_area_t *me, *sister;
    spath_link_qos_t *spath_link_qos;

    assert (my_area->area->level > 0);
    if (my_area->parent == NULL /* internet area */) {
	my_area->exwinner = my_area->winner;
	return;
    }
    if (my_area->winner == NULL) {
	/* lost a center */
	/* XXX all entries have to delete */
	my_area->exwinner = my_area->winner;
	return;
    }

    trace (TR_TRACE, my_area->trace, "update database: (0,k)\n");

    /* general role -- I could this in the same way as the center does */

    /* 0) update (0, k) elink where k is myself */

    {
	interface_bitset_t parent_ifmask;
	interface_bitset_t my_ifmask;

	/* finding vifs that don't belong to my area */
	memset (&parent_ifmask, 0, sizeof (parent_ifmask));
	hqlip_get_interface_mask (my_area->parent, &parent_ifmask);

	memset (&my_ifmask, 0, sizeof (my_ifmask));
	hqlip_get_interface_mask (my_area, &my_ifmask);
	ifxor (&parent_ifmask, &my_ifmask, &parent_ifmask,
		   sizeof (interface_bitset_t));

	if (!ifzero (&parent_ifmask, sizeof (parent_ifmask))) {
	    int i;

	    for (i = 0; i < MAX_INTERFACES; i++) {
		if (!BITX_TEST (&parent_ifmask, i))
		    continue;
		spath_calc_elink (hqlip, my_area /* just for info */,
				  hqlip->hqlip_interfaces[i], my_area->area);
	    }
	}
    }

    if (!area_is_r_local (my_area->winner->area)) {
	my_area->exwinner = my_area->winner;
	return;
    }

    trace (TR_TRACE, my_area->trace, "update database: (k,j)\n");

    /* I changed so that it's local if it's a center */
    assert (area_is_local (my_area->winner->area));
#ifdef notdef
    if (!area_is_local (my_area->winner->area)) {
	/* the center on another router */
        trace (TR_TRACE, my_area->trace, 
	       "update database: center is on another router\n");
	my_area->exwinner = my_area->winner;
	return;
    }
#endif

    /* 1) (k, j) where k is me */

    /* just follow the existing ones */
    LL_Iterate (my_area->ll_spath_link_qoses, spath_link_qos) {
	/* areas unknown to me */
	if (BIT_TEST (spath_link_qos->flags, LINK_QOS_EXTERNAL) &&
		!area_is_local (spath_link_qos->area2)) {
	    trace (TR_TRACE, my_area->trace, 
		   "follwoing the external link to %d:%a\n",
		   spath_link_qos->area2->level,
		   spath_link_qos->area2->id);
	     /* try ilink calc with its elink area2 */
	    hqlip_calc_ilink (hqlip, my_area, spath_link_qos->area2);
	}
    }

    assert (my_area->area->level >= 1);
    ancestor = my_area;
    while ((ancestor = ancestor->parent) != NULL) {
	LL_Iterate (ancestor->ll_children, child) {
	    if (child != my_area &&
		    !area_is_descendant (child, my_area->area))
	        hqlip_calc_ilink (hqlip, my_area, child->area);
        }
    }
    
    /* 2) (i, k) where k is me */

    trace (TR_TRACE, my_area->trace, "update database: (i,k)\n");

    for (me = my_area; me->parent != NULL; me = me->parent) {
	LL_Iterate (me->parent->ll_children, sister) {
	    if (sister != me &&
		    !area_is_descendant (sister, me->area))
		hqlip_ask_descendant_calc (hqlip, sister, me->area);
	}
    }
    my_area->exwinner = my_area->winner;
    /* to know the center change */

#ifdef notdef
    assert (my_area->area->level > 0);
    if (my_area->winner == NULL) {
	/* lost a center */
	/* XXX all entries have to delete */
	return;
    }
    if (my_area->winner->area->my_area == NULL) {
	/* the center on another router */
	return;
    }

    if (my_area->parent != NULL /* not internet area */) {

        /* 1) update (0, k) elink where k is myself */

	interface_bitset_t parent_ifmask;
	interface_bitset_t my_ifmask;

	/* finding vifs that don't belong to my area */
	memset (&parent_ifmask, 0, sizeof (parent_ifmask));
	hqlip_get_interface_mask (my_area->parent, &parent_ifmask);

	memset (&my_ifmask, 0, sizeof (my_ifmask));
	hqlip_get_interface_mask (my_area, &my_ifmask);
	ifxor (&parent_ifmask, &my_ifmask, &parent_ifmask,
		   sizeof (interface_bitset_t));

	if (!ifzero (&parent_ifmask, sizeof (parent_ifmask))) {
	    int i;

	    for (i = 0; i < MAX_INTERFACES; i++) {
		if (!BITX_TEST (&parent_ifmask, i))
		    continue;
		spath_calc_elink (hqlip, my_area /* just for info */,
				  hqlip->hqlip_interfaces[i], my_area->area);
	    }
	}

	if (my_area_is_center (my_area)) {
            /* update (j, k) link where j is myself */
            LL_Iterate (my_area->ll_spath_link_qoses, spath_link_qos) {
	        if (BIT_TEST (spath_link_qos->flags, LINK_QOS_DELETED))
	            continue;
	        if (!BIT_TEST (spath_link_qos->flags, LINK_QOS_EXTERNAL))
	            continue;
	        hqlip_calc_ilink (hqlip, my_area, spath_link_qos->area2);
            }
	}
    }
#endif
}


static void 
hqlip_update_link_qos (hqlip_t *hqlip, my_area_t *my_area, int level)
{
    my_area_t *child;

    if (my_area->area->level < level)
	return;

    if (my_area->area->level == level) {
	hqlip_update_database (hqlip, my_area);
	return;
    }

    LL_Iterate (my_area->ll_children, child) {
	hqlip_update_link_qos (hqlip, child, level);
    }
}



int
hqlip_update_area_center (hqlip_t *hqlip, my_area_t *my_area,
			  spath_area_center_t *spath_area_center)
{
    spath_area_center_t *winner;

    if (BIT_TEST (my_area->flags, HQLIP_MY_AREA_SYNCING)) {
        trace (TR_TRACE, my_area->trace, "my area is under syncing\n");
	return (0);
    }

    assert (spath_area_center == NULL || 
		spath_area_center->area->level < my_area->area->level);
    if (my_area->winner && 
	    BIT_TEST (my_area->winner->flags, AREA_CENTER_DELETED)) {
	trace (TR_INFO, my_area->trace, 
	       "lost center %d:%a in %s level %d\n",
		my_area->winner->area->level, my_area->winner->area->id,
		my_area->name, my_area->area->level);
	my_area->winner = NULL;
    }

    /* it can't be a candidate */
    if (spath_area_center &&
	BIT_TEST (spath_area_center->flags, AREA_CENTER_DELETED))
	spath_area_center = NULL;
    
    if (my_area->winner) {
	if (spath_area_center) {
	    if (my_area->winner == spath_area_center)
		return (0);
	    if (spath_area_center_compare (my_area->winner, 
					   spath_area_center) > 0) {
		trace (TR_INFO, my_area->trace, 
	       	       "change center %d:%a -> %d:%a in %s level %d\n",
		        my_area->winner->area->level, 
			my_area->winner->area->id,
		        spath_area_center->area->level, 
		        spath_area_center->area->id,
		        my_area->name, my_area->area->level);
		my_area->winner = spath_area_center;
	        return (1);
	    }
	}
    }

    if (my_area->winner == NULL && spath_area_center) {
	trace (TR_INFO, my_area->trace, 
	       "new center %d:%a in %s level %d\n",
		spath_area_center->area->level, spath_area_center->area->id,
		my_area->name, my_area->area->level);
	my_area->winner = spath_area_center;
	return (1);
    }
  
    winner = NULL;
    LL_Iterate (my_area->ll_spath_area_centers, spath_area_center) {
	if (BIT_TEST (spath_area_center->flags, AREA_CENTER_DELETED))
	    continue;
	if (winner == NULL) {
	    winner = spath_area_center;
	}
	if (spath_area_center_compare (winner, spath_area_center) > 0) {
	    winner = spath_area_center;
        }
    }
    if (my_area->winner != winner) {
	if (my_area->winner && winner)
	    trace (TR_INFO, my_area->trace, 
		    "change center %d:%a -> %d:%a in %s level %d\n",
		    my_area->winner->area->level, my_area->winner->area->id,
		    winner->area->level, winner->area->id,
		    my_area->name, my_area->area->level);
	else if (my_area->winner)
	    trace (TR_INFO, my_area->trace, 
		    "lost center %d:%a in %s level %d\n",
		    my_area->winner->area->level, my_area->winner->area->id,
		    my_area->name, my_area->area->level);
	else if (winner)
	    trace (TR_INFO, my_area->trace, 
		    "new center %d:%a in %s level %d\n",
		    winner->area->level, winner->area->id,
		    my_area->name, my_area->area->level);
	my_area->winner = winner;
	return (1);
    }
    return (0);
}


static void
hqlip_recv_area_center (hqlip_t *hqlip, hqlip_neighbor_t *neighbor, 
		        my_area_t *my_area, int flags, 
		        int len, time_t tstamp, u_char *cp)
{
    spath_area_center_t *spath_area_center, *sac;
    u_char *begin = cp;
    u_char *end = cp + len;
    time_t now;
    int dont_forward = 0;

    time (&now);
    spath_area_center = New (spath_area_center_t);
    cp = hqlip_get_area (&spath_area_center->area, cp, neighbor);
    /* MRT_GET_NETLONG (spath_area_center->router_id, cp); */
    if (cp >= end) {
	BIT_SET (spath_area_center->flags, AREA_CENTER_DELETED);
    }
    else {
        MRT_GET_BYTE (spath_area_center->pri, cp);
        cp += 3;
	if (cp != end) {
	    trace (TR_INFO, neighbor->trace, "wrong data boundary (%d)\n",
		   end - cp);
	    len = len - (end - cp); /* adjusted for forwarding XXX */
	}
    }

    spath_area_center->tstamp = tstamp;
    spath_area_center->ctime = now;
    spath_area_center->utime = now;
    spath_area_center->neighbor = neighbor;
    BIT_SET (spath_area_center->flags, AREA_CENTER_CHANGED);

    if (spath_area_center->area->level >= my_area->area->level) {
	trace (TR_WARN, neighbor->trace, "wrong area level %d for %s at %d\n",
	       spath_area_center->area->level, my_area->name, 
	       my_area->area->level);
	Delete (spath_area_center);
	return;
    }
    /* check if there is the same priority */
    if (!BIT_TEST (spath_area_center->flags, AREA_CENTER_DELETED)) {
        LL_Iterate (my_area->ll_spath_area_centers, sac) {
    	    if (BIT_TEST (sac->flags, AREA_CENTER_DELETED))
		continue;
	    /* if area is the same, it's ok */
	    if (sac->area == spath_area_center->area)
		continue;
	    if (sac->pri == spath_area_center->pri) {
		hqlip_trace_area_center (TR_WARN, neighbor->trace, 
			"recv (pri)", my_area, spath_area_center);
		Delete (spath_area_center);
		return;
	    }
        }
    }

    LL_Iterate (my_area->ll_spath_area_centers, sac) {
	if (sac->area == spath_area_center->area &&
		sac->neighbor != spath_area_center->neighbor) {
	    trace (TR_TRACE, neighbor->trace, "the following is being "
			"updated by another router %s -> %s\n",
		 sac->neighbor? prefix_toa (sac->neighbor->prefix): "local",
		 spath_area_center->neighbor? 
		   prefix_toa (spath_area_center->neighbor->prefix): "local");
	    dont_forward++;
	}
	if (sac->area == spath_area_center->area &&
	    sac->neighbor == spath_area_center->neighbor /* &&
	    sac->router_id == spath_area_center->router_id */)
	    break;
    }

    if (BIT_TEST (spath_area_center->flags, AREA_CENTER_DELETED)) {
	if (sac && BIT_TEST (sac->flags, AREA_CENTER_DELETED)) {
            hqlip_trace_area_center (TR_PACKET, neighbor->trace, 
			      "recv (dup)", my_area, spath_area_center);
	}
	else if (sac == NULL) {
            hqlip_trace_area_center (TR_PACKET, neighbor->trace, 
			      "recv (none)", my_area, spath_area_center);
	}
	else {
            hqlip_trace_area_center (TR_PACKET, neighbor->trace, 
			      "recv (del)", my_area, spath_area_center);
	    LL_Remove (my_area->ll_spath_area_centers, sac);
	    Destroy (sac);
	    if (!dont_forward)
	        hqlip_forward_message (hqlip, my_area, neighbor, flags, 
				HQLIP_MSG_AREA_CENTER, my_area->area->level, 
				len, tstamp, begin);
	    if (sac == my_area->winner) {
		my_area->winner = NULL;
        	if (hqlip_update_area_center (hqlip, my_area, 
					      spath_area_center))
            	    hqlip_update_database (hqlip, my_area);
	    }
	}
	Delete (spath_area_center);
	return;
    }

    if (sac == NULL) {
	assert (my_area->area->level > spath_area_center->area->level);
	LL_Add (my_area->ll_spath_area_centers, spath_area_center);
	hqlip_trace_area_center (TR_PACKET, neighbor->trace, 
			"recv (new)", my_area, spath_area_center);
	if (!dont_forward)
	    hqlip_forward_message (hqlip, my_area, neighbor, flags, 
				HQLIP_MSG_AREA_CENTER, my_area->area->level, 
				len, tstamp, begin);
        if (hqlip_update_area_center (hqlip, my_area, spath_area_center))
            hqlip_update_database (hqlip, my_area);
    }
    else {
	if (tstamp > sac->tstamp || 
		BIT_TEST (sac->flags, AREA_CENTER_DELETED)) {
	    /* newer */
	    /* assert (sac->neighbor == spath_area_center->neighbor); */
	    LL_Remove (my_area->ll_spath_area_centers, sac);
	    Destroy (sac);
	    if (my_area->winner == sac)
		my_area->winner = NULL;
	    LL_Add (my_area->ll_spath_area_centers, spath_area_center);
	    hqlip_trace_area_center (TR_PACKET, neighbor->trace, 
			          "recv (update)", my_area, spath_area_center);
	    hqlip_forward_message (hqlip, my_area, neighbor, flags, 
				HQLIP_MSG_AREA_CENTER, my_area->area->level, 
				len, tstamp, begin);
            if (hqlip_update_area_center (hqlip, my_area, spath_area_center))
                hqlip_update_database (hqlip, my_area);
	}
	else {
	    hqlip_trace_area_center (TR_PACKET, neighbor->trace,
                                  "recv (ignore)", my_area, spath_area_center);
	    Delete (spath_area_center);
	}
    }
}


static void
hqlip_trace_area_addr (u_long flags, trace_t *tr, char *head,
	      my_area_t *my_area, spath_area_addr_t *spath_area_addr)
{
    trace (flags, tr, "%s at %d:%s area-addr %d:%a%s\n", head,
		my_area->area->level, my_area->name,
		spath_area_addr->area->level, spath_area_addr->area->id,
		BIT_TEST (spath_area_addr->flags, AREA_ADDR_DELETED)?
			" deleted": "");
    if (!BIT_TEST (spath_area_addr->flags, AREA_ADDR_DELETED)) {
	prefix_t *prefix;
        LL_Iterate (spath_area_addr->ll_prefixes, prefix)
            trace (flags, tr, "  addr %p\n", prefix);
    }
}


static void
hqlip_send_area_addr (hqlip_t *hqlip, my_area_t *my_area, 
		      hqlip_neighbor_t *neighbor, spath_area_addr_t *specified)
{
    spath_area_addr_t *spath_area_addr;
    prefix_t *prefix;
    hqlip_neighbor_t *receiver;

    LL_Iterate (my_area->ll_spath_area_addrs, spath_area_addr) {
	char msgbuf[HQLIP_MSG_SIZE], *cp = msgbuf;
        int flags = 0;

	if (specified && spath_area_addr != specified)
	    continue;
	if (neighbor && BIT_TEST (spath_area_addr->flags, AREA_ADDR_DELETED))
	    continue;

        cp = hqlip_put_area (spath_area_addr->area, cp);
        if (!BIT_TEST (spath_area_addr->flags, AREA_ADDR_DELETED)) {
	    LL_Iterate (spath_area_addr->ll_prefixes, prefix) {
                cp = hqlip_put_addr (prefix, cp);
	    }
	}

	/* if neighbor is supplied, it means the first syncing */
	if (neighbor)
	    flags |= HQLIP_MSGF_NOTSYNCED;

        LL_Iterate (my_area->ll_neighbors, receiver) {
	    if (spath_area_addr->neighbor == receiver)
	        continue;
	    if (neighbor && receiver != neighbor)
	        continue;
            hqlip_send_message (hqlip, receiver, flags,
		        HQLIP_MSG_AREA_ADDR, my_area->area->level, 
		        cp - msgbuf, spath_area_addr->tstamp, msgbuf);
	    hqlip_trace_area_addr (TR_PACKET, receiver->trace,
                                  "sent", my_area, spath_area_addr);
	}
    }
}


static void
destroy_spath_area_addr (spath_area_addr_t *spath_area_addr)
{
    if (spath_area_addr->ll_prefixes)
	LL_DestroyFn (spath_area_addr->ll_prefixes, 
			  (void_fn_t) Deref_Prefix);
    Delete (spath_area_addr);
}


static void
hqlip_recv_area_addr (hqlip_t *hqlip, hqlip_neighbor_t *neighbor, 
		      my_area_t *my_area, int flags, 
		      int len, time_t tstamp, u_char *cp)
{
    spath_area_addr_t *spath_area_addr, *saa;
    u_char *begin = cp;
    u_char *end = cp + len;
    time_t now;
    int dont_forward = 0;

    time (&now);
    spath_area_addr = New (spath_area_addr_t);
    spath_area_addr->ll_prefixes = LL_Create (0);
    cp = hqlip_get_area (&spath_area_addr->area, cp, neighbor);
    if (cp >= end) {
	BIT_SET (spath_area_addr->flags, AREA_ADDR_DELETED);
    }
    else {
	while (end - cp >= 8 /* 12 */) {
	    prefix_t *prefix;
    	    cp = hqlip_get_addr (&prefix, cp, neighbor);
	    /* XXX cp check */
    	    LL_Add2 (spath_area_addr->ll_prefixes, prefix);
	}
	if (cp != end) {
	    trace (TR_INFO, neighbor->trace, "wrong data boundary (%d)\n",
		  end - cp);
	    len = len - (end - cp); /* adjusted for forwarding XXX */
	}
    }

    spath_area_addr->tstamp = tstamp;
    spath_area_addr->ctime = now;
    spath_area_addr->utime = now;
    spath_area_addr->neighbor = neighbor;
    BIT_SET (spath_area_addr->flags, AREA_ADDR_CHANGED);

    LL_Iterate (my_area->ll_spath_area_addrs, saa) {
	if (saa->area == spath_area_addr->area &&
		saa->neighbor != spath_area_addr->neighbor) {
	    trace (TR_TRACE, neighbor->trace, "the following is being "
			"updated by another router %s -> %s\n",
		 saa->neighbor? prefix_toa (saa->neighbor->prefix): "local",
		 spath_area_addr->neighbor? 
		   prefix_toa (spath_area_addr->neighbor->prefix): "local");
	    dont_forward++;
	}
	if (saa->area == spath_area_addr->area &&
		saa->neighbor == spath_area_addr->neighbor)
	    break;
    }

    /* XXX prefix overlap check */

    if (BIT_TEST (spath_area_addr->flags, AREA_ADDR_DELETED)) {
	if (saa && BIT_TEST (saa->flags, AREA_ADDR_DELETED)) {
            hqlip_trace_area_addr (TR_PACKET, neighbor->trace, 
			      "recv (dup)", my_area, spath_area_addr);
	}
	else if (saa == NULL) {
            hqlip_trace_area_addr (TR_PACKET, neighbor->trace, 
			      "recv (none)", my_area, spath_area_addr);
	}
	else {
            hqlip_trace_area_addr (TR_PACKET, neighbor->trace, 
			      "recv (del)", my_area, spath_area_addr);
	    LL_Remove (my_area->ll_spath_area_addrs, saa);
	    destroy_spath_area_addr (saa);
	    if (!dont_forward)
	        hqlip_forward_message (hqlip, my_area, neighbor, flags, 
				HQLIP_MSG_AREA_ADDR, my_area->area->level, 
				len, tstamp, begin);
	}
	destroy_spath_area_addr (spath_area_addr);
	return;
    }

    if (saa == NULL) {
	hqlip_trace_area_addr (TR_PACKET, neighbor->trace,
                                  "recv (new)", my_area, spath_area_addr);  
	LL_Add (my_area->ll_spath_area_addrs, spath_area_addr);
	if (!dont_forward)
	    hqlip_forward_message (hqlip, my_area, neighbor, flags, 
				HQLIP_MSG_AREA_ADDR, my_area->area->level, 
				len, tstamp, begin);
    }
    else {
	if (tstamp > saa->tstamp ||
		BIT_TEST (saa->flags, AREA_ADDR_DELETED)) {
	    /* newer */
	    hqlip_trace_area_addr (TR_PACKET, neighbor->trace,
                                  "recv (update)", my_area, spath_area_addr);  
	    LL_Remove (my_area->ll_spath_area_addrs, saa);
	    destroy_spath_area_addr (saa);
	    LL_Add (my_area->ll_spath_area_addrs, spath_area_addr);
	    hqlip_forward_message (hqlip, my_area, neighbor, flags, 
				HQLIP_MSG_AREA_ADDR, my_area->area->level, 
				len, tstamp, begin);
	}
	else {
	    hqlip_trace_area_addr (TR_PACKET, neighbor->trace,
                                   "recv (ignore)", my_area, spath_area_addr);  
	    destroy_spath_area_addr (spath_area_addr);
	}
    }
}


static int
hqlip_read (hqlip_neighbor_t *neighbor, u_char *ptr, int len)
{
    int n;

    if (neighbor->sockfd < 0)
	return (-1);
    n = read (neighbor->sockfd, ptr, len);

    if (n < 0) {

	switch (errno) {
        case EWOULDBLOCK:
#if     defined(EAGAIN) && EAGAIN != EWOULDBLOCK
        case EAGAIN:
#endif  /* EAGAIN */
        case EINTR:
        case ENETUNREACH:
        case EHOSTUNREACH:
	    trace (TR_INFO, neighbor->trace, 
		   "READ FAILED (%m) -- OKAY TO IGNORE\n");
	    return (0);
	default:
	    trace (TR_WARN, neighbor->trace, "READ FAILED (%m)\n");
	    return (-1);
	}
    }
    else if (n == 0) {
	trace (TR_WARN, neighbor->trace, "READ FAILED EOF???\n");
	return (-1);
    }

    trace (TR_PACKET, neighbor->trace, "read %d bytes\n", n);
    return (n);
}


static int
hqlip_fill_packet (hqlip_neighbor_t *neighbor)
{
    int len, n;

    assert (neighbor);
    assert (neighbor->read_ptr >= neighbor->buffer);
    assert (neighbor->read_ptr <= 
		neighbor->buffer + sizeof (neighbor->buffer));
    assert (neighbor->start_ptr >= neighbor->buffer);
    assert (neighbor->start_ptr <= 
		neighbor->buffer + sizeof (neighbor->buffer));

    if ((len = neighbor->read_ptr - neighbor->start_ptr) == 0) {
	/* reset the pointers */
	neighbor->start_ptr = neighbor->buffer;
	neighbor->read_ptr = neighbor->buffer;
    }

    if (neighbor->buffer + sizeof (neighbor->buffer) - neighbor->read_ptr 
		< HQLIP_MSG_SIZE) {
	/* need to move them to the start to get more */
	memcpy (neighbor->buffer, neighbor->start_ptr, len);
	neighbor->start_ptr = neighbor->buffer;
	neighbor->read_ptr = neighbor->buffer + len;
    }

    if ((n = hqlip_read (neighbor, neighbor->read_ptr, HQLIP_MSG_SIZE)) < 0) {
	return (-1);
    }
    else if (n == 0) {
	return (0);
    }

    neighbor->read_ptr += n;
    assert (neighbor->read_ptr <= 
		neighbor->buffer + sizeof (neighbor->buffer));
    return (len + n);
}


static int
hqlip_get_packet (hqlip_neighbor_t *neighbor)
{
    int pdu_len, len;
    u_char *cp;

    neighbor->packet = NULL;

    /* need to be filled at least a header in buffer */
    /* check if the requested length of data already in buffer */
    if ((len = neighbor->read_ptr - neighbor->start_ptr) 
		< HQLIP_MSG_HDR_SIZE) {
	return (0);
    }

    cp = neighbor->start_ptr;
    HQLIP_PEEK_HDRLEN (pdu_len, cp);
    if (pdu_len < HQLIP_MSG_HDR_SIZE || pdu_len > HQLIP_MSG_SIZE) {
        neighbor->start_ptr = neighbor->read_ptr; /* eat up the input */
	trace (TR_WARN, neighbor->trace, "wrong message size %d\n", pdu_len);
	return (-1);
    }

    /* see if the total length packet in buffer */
    /* check if the requested length of data already in buffer */
    if (len < pdu_len) {
	return (0);
    }

    neighbor->packet = neighbor->start_ptr;
    neighbor->start_ptr += pdu_len;
    return (1);
}


static int
hqlip_get_pdu (hqlip_t *hqlip, hqlip_neighbor_t * neighbor)
{
    int ret;

    /* I know that the return value will not be used, but leave as it was */

    if ((ret = hqlip_fill_packet (neighbor)) < 0) {
	hqlip_neighbor_down (hqlip, neighbor);
	return (-1);
    }
    else if (ret == 0) {
        assert (neighbor->sockfd >= 0);
	select_enable_fd_mask (neighbor->sockfd, SELECT_READ);
	return (ret);
    }

    for (;;) {

        if ((ret = hqlip_get_packet (neighbor)) < 0) {
	    hqlip_neighbor_down (hqlip, neighbor);
	    return (-1);
        }
        else if (ret == 0) {
	    break;
        }
   
        if ((ret = hqlip_process_pdu (hqlip, neighbor)) < 0) {
	    hqlip_neighbor_down (hqlip, neighbor);
	    return (-1);
        }
    }

    if (neighbor->sockfd >= 0)
	select_enable_fd_mask (neighbor->sockfd, SELECT_READ);
    return (1);
}


static void
hqlip_connect_ready (hqlip_t *hqlip, hqlip_neighbor_t *neighbor)
{
    sockunion_t name;
    int namelen = sizeof (name);
#ifdef FIONBIO
    int optval = 0;
#endif /* FIONBIO */

    BIT_RESET (neighbor->flags, HQLIP_OPEN_IN_PROGRESS);

    if (neighbor->sockfd < 0) {
	trace (TR_WARN, neighbor->trace,
	       "connect to %a succeeded but sockfd has been closed\n",
	        neighbor->prefix);
	return;
    }

    /* see if we are really connected */
    if (getpeername (neighbor->sockfd, (struct sockaddr *) &name, 
			&namelen) < 0) {
	trace (TR_INFO, neighbor->trace,
	       "connect to %a failed (%m)\n", neighbor->prefix);
        hqlip_neighbor_down (hqlip, neighbor);
	return;
    }

    trace (TR_INFO, neighbor->trace, "outgoing connection succeeded\n");

#ifndef HAVE_LIBPTHREAD
    socket_set_nonblocking (neighbor->sockfd, 0);
#endif /* HAVE_LIBPTHREAD */
    hqlip_neighbor_start (hqlip, neighbor);
}


static int
hqlip_tcp_connect (hqlip_t *hqlip, hqlip_neighbor_t *neighbor,
		   prefix_t *local)
{
    int ret, port = HQLIP_TCP_PORT;
    int family, len;
    sockunion_t anyaddr;

    memset (&anyaddr, 0, sizeof (anyaddr));
    /* initiate a TCP connection */
    family = neighbor->prefix->family;
#ifdef HAVE_IPV6
    if (family == AF_INET6) {
	anyaddr.sin6.sin6_family = family;
	anyaddr.sin6.sin6_port = htons (port);
	memcpy (&anyaddr.sin6.sin6_addr, prefix_tochar (neighbor->prefix), 16);
	len = sizeof (anyaddr.sin6);
    }
    else
#endif /* HAVE_IPV6 */
    {
	anyaddr.sin.sin_family = family;
	anyaddr.sin.sin_port = htons (port);
	memcpy (&anyaddr.sin.sin_addr, prefix_tochar (neighbor->prefix), 4);
	len = sizeof (anyaddr.sin);
    }

    if ((neighbor->sockfd = socket (family, SOCK_STREAM, 0)) < 0) {
	trace (TR_ERROR, hqlip->trace, "socket open failed (%m)\n");
	return (-1);
    }

    if (local) {
	/* port will not be bound */
	if (socket_bind_port (neighbor->sockfd, family, 
			      prefix_tochar (local), 0) < 0 ) {
	    return (-1);
	}
    }

#ifndef HAVE_LIBPTHREAD
    /* always non-blocking. 
      if connect doesn't return, there is no way to resume it. */
    socket_set_nonblocking (neighbor->sockfd, 1);
#endif /* HAVE_LIBPTHREAD */

    BIT_SET (neighbor->flags, HQLIP_OPEN_IN_PROGRESS);
    trace (TR_TRACE, neighbor->trace,
	   "initiating connect to %a on sockfd %d\n",
	    neighbor->prefix, neighbor->sockfd);
    ret = connect (neighbor->sockfd, (struct sockaddr *)& anyaddr, len);
    if (ret < 0) {
	if (errno != EINPROGRESS) {
	    /* wait open timeout to delete the neighbor */
	    return (-1);
	}
	trace (TR_PACKET, hqlip->trace, "waiting on %d for write\n",
	       neighbor->sockfd);
	select_add_fd_event ("hqlip_connect_ready", neighbor->sockfd, 
			     SELECT_WRITE, TRUE, 
			     neighbor->schedule, hqlip_connect_ready, 
			     2, hqlip, neighbor);
	return (0);
    }
    hqlip_connect_ready (hqlip, neighbor);
    return (1);
}


static void
hqlip_neighbor_area_down (hqlip_t *hqlip, my_area_t *my_area,
			  hqlip_neighbor_t *neighbor)
{
    spath_link_qos_t *spath_link_qos;
    spath_area_center_t *spath_area_center;
    spath_area_addr_t *spath_area_addr;
    time_t now;

    if (my_area->parent != NULL) {
	/* starting with highest level */
	hqlip_neighbor_area_down (hqlip, my_area->parent, neighbor);
    }

    LL_Remove (my_area->ll_neighbors, neighbor);
    trace (TR_TRACE, neighbor->trace, 
   	"neighbor %a on %s removed from %s at %d\n", 
    	neighbor->prefix, neighbor->vif->interface->name,
	my_area->name, my_area->area->level);

    time (&now);
    BIT_RESET (my_area->flags, HQLIP_MY_AREA_SYNCING);
    LL_Iterate (my_area->ll_spath_link_qoses, spath_link_qos) {
	if (spath_link_qos->neighbor == neighbor) {
	    if (!BIT_TEST (spath_link_qos->flags, LINK_QOS_DELETED)) {
		time_t *utimep = New (time_t);
	        BIT_SET (spath_link_qos->flags, LINK_QOS_DELETED);
	        BIT_SET (spath_link_qos->flags, LINK_QOS_CHANGED);
    		hqlip_trace_link_qos (TR_PACKET, neighbor->trace, 
			  "deleted", my_area, spath_link_qos);
		hqlip_send_link_qos (hqlip, my_area, NULL,
				     spath_link_qos);
		*utimep = now;
		LL_Add2 (spath_link_qos->ll_bad_updates, utimep);
		spath_link_qos->ktime = 0;
    	        hqlip_trace_link_qos (TR_TRACE, my_area->trace, 
			"registered as worse", my_area, spath_link_qos);
	    }
	}
    }
    LL_Iterate (my_area->ll_spath_area_centers, spath_area_center) {
	if (spath_area_center->neighbor == neighbor) {
	    if (!BIT_TEST (spath_area_center->flags, 
			   AREA_CENTER_DELETED)) {
	        BIT_SET (spath_area_center->flags, AREA_CENTER_DELETED);
	        BIT_SET (spath_area_center->flags, AREA_CENTER_CHANGED);
    		hqlip_trace_area_center (TR_PACKET, neighbor->trace, 
			  "deleted", my_area, spath_area_center);
		hqlip_send_area_center (hqlip, my_area, NULL,
				        spath_area_center);
		if (my_area->winner == spath_area_center)
		    hqlip_update_area_center (hqlip, my_area, 
					      spath_area_center);
	    }
	}
    }
    LL_Iterate (my_area->ll_spath_area_addrs, spath_area_addr) {
	if (spath_area_addr->neighbor == neighbor) {
	    if (!BIT_TEST (spath_area_addr->flags, 
			   AREA_ADDR_DELETED)) {
	        BIT_SET (spath_area_addr->flags, AREA_ADDR_DELETED);
	        BIT_SET (spath_area_addr->flags, AREA_ADDR_CHANGED);
    		hqlip_trace_area_addr (TR_PACKET, neighbor->trace, 
			  "deleted", my_area, spath_area_addr);
		hqlip_send_area_addr (hqlip, my_area, NULL,
				      spath_area_addr);
	    }
	}
    }
    hqlip_update_database (hqlip, my_area);
    BIT_RESET (neighbor->flags, HQLIP_NEIGHBOR_CONNECTED);
}


static void
hqlip_neighbor_down (hqlip_t *hqlip, hqlip_neighbor_t *neighbor)
{
    if (BIT_TEST (neighbor->flags, HQLIP_NEIGHBOR_DELETED))
	return;

    if (BIT_TEST (neighbor->flags, HQLIP_NEIGHBOR_CONNECTED)) {
        hqlip_interface_t *vif = neighbor->vif;
        spath_link_qos_t *spath_link_qos;

	hqlip_neighbor_area_down (hqlip, vif->my_area0->parent, neighbor);

	spath_link_qos = spath_link_qos_create (hqlip, /* reversed */
                                add_area (0, neighbor->prefix), 
				vif->my_area0->area,
                                vif->metric, NULL, 0);     
    	/* spath_link_qos = neighbor->spath_link_qos; */
	BIT_SET (spath_link_qos->flags, LINK_QOS_DELETED);
        hqlip_inject_spath_link_qos (hqlip, vif->my_area0->parent, 
				     spath_link_qos);
    }
    trace (TR_WARN, neighbor->trace, 
	   "neighbor %a on %s going down\n", 
	    neighbor->prefix, neighbor->vif->interface->name);
    time (&neighbor->utime);
    BIT_SET (neighbor->flags, HQLIP_NEIGHBOR_DELETED);
    Timer_Turn_OFF (neighbor->timeout);
    Timer_Turn_OFF (neighbor->keep_alive);
    if (neighbor->sockfd >= 0) {
        BIT_RESET (neighbor->flags, HQLIP_OPEN_IN_PROGRESS);
	select_delete_fd (neighbor->sockfd);
        neighbor->sockfd = -1;
    }
#ifndef HAVE_LIBPTHREAD
    LL_Clear (neighbor->send_queue);
#endif /* HAVE_LIBPTHREAD */
    LL_Clear (neighbor->ll_packets);
    neighbor->read_ptr = neighbor->buffer;
    neighbor->start_ptr = neighbor->buffer;
    clear_schedule (neighbor->schedule);

}


static void
hqlip_timeout_neighbor (hqlip_t *hqlip, hqlip_neighbor_t *neighbor)
{
   /* since timeout event is queued, it may happen after deletion is done.
      so the info remains and reused later */
    if (BIT_TEST (neighbor->flags, HQLIP_NEIGHBOR_DELETED))
	return;
    trace (TR_WARN, neighbor->trace, 
	   "neighbor timeout on %s\n", neighbor->vif->interface->name);
    hqlip_neighbor_down (hqlip, neighbor);
}


static hqlip_neighbor_t *
hqlip_register_neighbor (hqlip_t *hqlip, prefix_t *prefix, 
		         hqlip_interface_t *vif)
{
    hqlip_neighbor_t *neighbor;
    char name[64];
    interface_t *interface = vif->interface;

    assert (hqlip);
    assert (prefix);

    LL_Iterate (vif->ll_neighbors, neighbor) {
	if (address_equal (neighbor->prefix, prefix)) {
    	    if (BIT_TEST (neighbor->flags, HQLIP_NEIGHBOR_DELETED)) {
    	        BIT_RESET (neighbor->flags, HQLIP_NEIGHBOR_DELETED);
    		trace (TR_INFO, neighbor->trace, 
	   		"neighbor recovered on %s\n", 
			neighbor->vif->interface->name);
	    }
	    assert (neighbor->vif->interface == interface);
	    if (neighbor->sockfd < 0)
		goto open_tcp_connection;
	    return (neighbor);
	}
    }
    neighbor = New (hqlip_neighbor_t);
    neighbor->prefix = Ref_Prefix (prefix);
    neighbor->trace = trace_copy (hqlip->trace);
    sprintf (name, "HQLIP %s", prefix_toa (prefix));
    set_trace (neighbor->trace, TRACE_PREPEND_STRING, name, 0);
    neighbor->sockfd = -1;
    neighbor->vif = vif;
    neighbor->flags = 0;
#ifndef HAVE_LIBPTHREAD
    neighbor->send_queue = LL_Create (LL_DestroyFunction, destroy_packet, 0);
#endif /* HAVE_LIBPTHREAD */
    neighbor->ll_packets = LL_Create (LL_DestroyFunction, Destroy,
				LL_CompareFunction, hqlip_spath_compare,
				LL_AutoSort, True, 0);
    neighbor->read_ptr = neighbor->buffer;
    neighbor->start_ptr = neighbor->buffer;
    time (&neighbor->ctime);
    time (&neighbor->utime);
    neighbor->keep_alive = New_Timer2 ("HQLIP keep alive timer",
                                vif->keep_alive_interval, 0,
                                hqlip->schedule, hqlip_send_keep_alive, 
				2, hqlip, neighbor);
    neighbor->timeout = New_Timer2 ("HQLIP neighbor timeout",
                HQLIP_KEEPALIVE_TIMEOUT (vif->keep_alive_interval),
				TIMER_ONE_SHOT, hqlip->schedule,
                                hqlip_timeout_neighbor, 2, hqlip, neighbor);
    neighbor->schedule  = New_Schedule (name, neighbor->trace);
    mrt_thread_create2 (name, neighbor->schedule, NULL, NULL);
    LL_Add2 (vif->ll_neighbors, neighbor);
    if (vif->prefix) {
	if (address_equal (prefix, vif->prefix)) {
	    /* loop back */
	    vif->myself = neighbor;
	}
    }
    else if (is_prefix_local_on (prefix, interface)) {
	/* loop back */
	vif->myself = neighbor;
    }
    trace (TR_INFO, neighbor->trace, 
	   "neighbor created on %s\n", neighbor->vif->interface->name);

open_tcp_connection:
    /* I need to know my address to compare */
    if (vif->prefix == NULL) {
	return (neighbor);
    }

    /* tcp connection must initiate from small to big */
    if (prefix_compare_wolen (prefix, vif->prefix) > 0) {
	hqlip_tcp_connect (hqlip, neighbor, vif->prefix);
	/* neighbor timeout is for both open timeout and keep alive timeout */
        Timer_Reset_Time (neighbor->timeout);
        Timer_Turn_ON (neighbor->timeout);
    }
    srsvp_create_neighbor (NULL, prefix, interface);
    return (neighbor);
}


static void
hqlip_recv_hello (hqlip_t *hqlip, int sockfd)
{
    u_char buffer[HQLIP_UDP_SIZE];
    prefix_t *source = NULL;
    hqlip_interface_t *vif;
    interface_t *interface = NULL;
    int len, ttl = 1;
    int sport = HQLIP_UDP_PORT;
    int plen = 4;

    if (!hqlip->running)
	return;

    if (sockfd < 0)
	return;

    len = recvmsgfrom (sockfd, buffer, sizeof (buffer), O_NONBLOCK,
                       &source, &sport, &interface, NULL, &ttl);
    select_enable_fd_mask (sockfd, SELECT_READ);
    if (source == NULL)
	return;
    if (interface == NULL) {
	Deref_Prefix (source);
	return;
    }

    if (!BITX_TEST (&hqlip->interface_mask, interface->index)) {
        trace (TR_WARN, hqlip->trace,
               "recv hello from %a on disabled interface %s\n",
               source, interface->name);
	Deref_Prefix (source);
        return;
    }   

    vif = hqlip->hqlip_interfaces[interface->index];
    assert (vif);

    if (sockfd != hqlip->udp_sockfd) {
        trace (TR_WARN, hqlip->trace,
               "recv hello from %a on %s "
	       "with vif sockfd %d (bug report)\n",
               source, interface->name, sockfd);
	Deref_Prefix (source);
	return;
    }

    if (source->family != hqlip->family) {
        trace (TR_WARN, hqlip->trace,
               "recv hello from %a on %s but family must be %s\n",
               source, interface->name, family2string (hqlip->family));
	Deref_Prefix (source);
	return;
    }

    if (sport != HQLIP_UDP_PORT) {
        trace (TR_PACKET, hqlip->trace,
               "recv hello from %a on %s with port %d but must be %d\n",
               source, interface->name, sport, HQLIP_UDP_PORT);
	Deref_Prefix (source);
	return;
    }
    if (ttl != HQLIP_HELLO_TTL) {
        trace (TR_WARN, hqlip->trace,
               "recv hello from %a on %s with port %d but must be %d\n",
               source, interface->name, ttl, HQLIP_HELLO_TTL);
	Deref_Prefix (source);
	return;
    }
#ifdef HAVE_IPV6
    if (hqlip->family == AF_INET6)
	plen = 16;
#endif /* HAVE_IPV6 */
    /* XXXXXX */
    if (len != 0 && len != plen) {
        trace (TR_WARN, hqlip->trace,
               "recv hello from %a on %s with len %d but must be 0 or %d\n",
               source, interface->name, len, plen);
	Deref_Prefix (source);
	return;
    }
    trace (TR_PACKET, hqlip->trace,
           "hello packet received from %a on %s len %d\n",
           source, interface->name, len);
#ifdef notdef
    schedule_event2 ("hqlip_accept_hello",
                 hqlip->schedule, hqlip_accept_hello, 3, 
		 hqlip, Ref_Prefix (source), vif);
#endif
    hqlip_register_neighbor (hqlip, source, vif);
    Deref_Prefix (source);
}


static void
hqlip_open_accept (hqlip_t *hqlip, hqlip_interface_t *vif)
{
    int new_sockfd, len;
    sockunion_t remote;
    prefix_t *local_prefix = NULL, *remote_prefix;
    hqlip_neighbor_t *neighbor;
    interface_t *interface = vif->interface;
    int sockfd = vif->tcp_sockfd;
   
    if (sockfd < 0)
	return;

    len = sizeof (remote);
    if ((new_sockfd = accept (sockfd,
            (struct sockaddr *) &remote, &len)) < 0) {
        trace (TR_ERROR, hqlip->trace, "accept (%m)\n");
        select_enable_fd_mask (sockfd, SELECT_READ);
        return; 
    }
    select_enable_fd_mask (sockfd, SELECT_READ);

    remote_prefix = sockaddr_toprefix ((struct sockaddr *) &remote);
    if (remote_prefix->family != hqlip->family) {
        trace (TR_WARN, hqlip->trace,
               "recv open from %a on %s but family must be %s\n",
               remote_prefix, vif->interface->name, 
	       family2string (hqlip->family));
	Deref_Prefix (remote_prefix);
        close (new_sockfd); 
	return;
    }

    if (!BITX_TEST (&hqlip->interface_mask, interface->index)) {
	/* must not happen */
        trace (TR_ERROR, hqlip->trace, 
	       "connection from %a on %s refused (interface disabled)\n",
	        remote_prefix, interface->name);
	Deref_Prefix (remote_prefix);
        close (new_sockfd); 
        return;
    }

    if (get_socket_addr (sockfd, 0, &local_prefix) < 0) {
        trace (TR_ERROR, hqlip->trace, "getsockname (%m)\n");
	Deref_Prefix (remote_prefix);
        close (new_sockfd); 
        return;
    }
    assert (local_prefix);

    if (local_prefix == NULL || prefix_is_unspecified (local_prefix)) {
	Deref_Prefix (local_prefix);
	local_prefix = Ref_Prefix (vif->prefix);
    }
    else {
        if (!address_equal (vif->prefix, local_prefix)) {
            trace (TR_ERROR, hqlip->trace, 
	           "connection from %a to %a on %s refused "
			"(local address unknown)\n",
		    remote_prefix, local_prefix, interface->name);
	    Deref_Prefix (local_prefix);
	    Deref_Prefix (remote_prefix);
            close (new_sockfd); 
            return;
	}
    }

    if (remote_prefix->family != local_prefix->family) {
        trace (TR_ERROR, hqlip->trace, 
	       "connection from %a to %a on %s refused (family mismatch)\n",
	        remote_prefix, local_prefix, interface->name);
	Deref_Prefix (local_prefix);
	Deref_Prefix (remote_prefix);
        close (new_sockfd); 
        return;
    }
    if (address_equal (remote_prefix, local_prefix)) {
        trace (TR_ERROR, hqlip->trace, 
	       "connection from %a to %a on %s refused (myself)\n",
		remote_prefix, local_prefix, interface->name);
	Deref_Prefix (local_prefix);
	Deref_Prefix (remote_prefix);
        close (new_sockfd); 
        return;
    }

    /* tcp connection must initiate from small to big */
    if (prefix_compare_wolen (remote_prefix, local_prefix) >= 0) {
        trace (TR_ERROR, hqlip->trace, 
	       "connection from %a to %a on %s refused (reverse direction)\n",
		remote_prefix, local_prefix, interface->name);
	Deref_Prefix (local_prefix);
	Deref_Prefix (remote_prefix);
        close (new_sockfd); 
        return;
    }

    LL_Iterate (vif->ll_neighbors, neighbor) {
	if (address_equal (neighbor->prefix, remote_prefix))
	    break;
    }
    if (neighbor == NULL) {
	neighbor = hqlip_register_neighbor (hqlip, remote_prefix, vif);
    }
    else if (neighbor->sockfd >= 0) {
        trace (TR_ERROR, hqlip->trace, 
	       "connection from %a to %a on %s refused (already connected)\n",
		remote_prefix, local_prefix, interface->name);
	Deref_Prefix (local_prefix);
	Deref_Prefix (remote_prefix);
        close (new_sockfd); 
        return;
    }

    trace (TR_INFO, hqlip->trace, 
	       "connection from %a to %a on %s accepted\n",
		remote_prefix, local_prefix, interface->name);
    neighbor->sockfd = new_sockfd;

    hqlip_neighbor_start (hqlip, neighbor);
    Deref_Prefix (local_prefix);
    Deref_Prefix (remote_prefix);
}


void 
hqlip_start (hqlip_t *hqlip)
{
    int level;

    /* initialize from the lowest level */
    for (level = 1; level <= HQLIP_AREA_LEVEL_INTERNET; level++) {
	hqlip_update_link_qos (hqlip, hqlip->root, level);
    }
    hqlip->running = 1;
}


void
hqlip_init (ricd_t *ricd)
{
    char *all_hosts = "224.0.0.1";
    char *name = "HQLIP";

#ifdef HAVE_IPV6
    if (ricd->family == AF_INET6) {
	/* to force the source to be a global */
	/* but ok since the ttl will be 1 */
        all_hosts = "ff0f::1";
        name = "HQLIP6";
    }
#endif /* HAVE_IPV6 */

    ricd->hqlip = New (hqlip_t);
    ricd->hqlip->trace = trace_copy (ricd->trace);
    set_trace (ricd->hqlip->trace, TRACE_PREPEND_STRING, name, 0);
    ricd->hqlip->family = ricd->family;
    ricd->hqlip->all_hosts = ascii2prefix (ricd->family, all_hosts);
    ricd->hqlip->ll_networks = LL_Create (0);
    ricd->hqlip->ll_areas = LL_Create (0);
    ricd->hqlip->ll_hqlip_interfaces = LL_Create (0);
    ricd->hqlip->keep_alive_interval = HQLIP_KEEPALIVE_INTERVAL;
    /* ricd->hqlip->router_id = MRT->default_id; */
    memset (&ricd->hqlip->interface_mask, 0, 
		sizeof (ricd->hqlip->interface_mask));
    ricd->hqlip->schedule  = New_Schedule (name, ricd->trace);
    mrt_thread_create2 (name, ricd->hqlip->schedule, NULL, NULL);
}


static int
hqlip_vif_udp_init (hqlip_t *hqlip, hqlip_interface_t *vif)
{
    int sockfd;
    u_char *bind_addr = (vif->prefix)? prefix_tochar (vif->prefix): NULL;

    if (hqlip->udp_count <= 0) {
	/* we need to have a socket for receiption since binding an address
	   refuses us from receiving a multicast packet */
	/* we have another sending only socket to bind a prefix in case
	   there are a couple of addresses available on a interface */
        sockfd = socket_open (hqlip->family, SOCK_DGRAM, 0);
        if (sockfd < 0)
	    return (sockfd);
        socket_reuse (sockfd, 1);
        socket_bind_port (sockfd, hqlip->family, NULL, HQLIP_UDP_PORT);
#ifdef HAVE_IPV6
        if (hqlip->family == AF_INET6) {
	    ipv6_pktinfo (sockfd, 1);
	    ipv6_recvhops (sockfd, 1);
        }
        else
#endif /* HAVE_IPV6 */
        {
            ip_pktinfo (sockfd, 1);
	    ip_recvttl (sockfd, 1);
        }
        hqlip->udp_sockfd = sockfd;
	hqlip->udp_count = 1;
        select_add_fd_event ("hqlip_recv_hello", sockfd,
                       	      SELECT_READ, TRUE, hqlip->schedule,
                       	      hqlip_recv_hello, 2, hqlip, sockfd);
    }

    sockfd = socket_open (hqlip->family, SOCK_DGRAM, 0);
    if (sockfd < 0)
	return (sockfd);

    socket_reuse (sockfd, 1);
    /* make sure we are a member since solaris requires it */
    /* not binding with vif's udp socket to make sure it doesn't receive */
    join_leave_group (hqlip->udp_sockfd, vif->interface, hqlip->all_hosts, 1);
    socket_bind_port (sockfd, hqlip->family, bind_addr, HQLIP_UDP_PORT);
#ifdef HAVE_IPV6
    if (hqlip->family == AF_INET6) {
	ipv6_multicast_loop (sockfd, 1); 
	ipv6_multicast_hops (sockfd, HQLIP_HELLO_TTL);
	ipv6_pktinfo (sockfd, 1);
	ipv6_recvhops (sockfd, 1);
    }
    else
#endif /* HAVE_IPV6 */
    {
	ip_multicast_loop (sockfd, 1);
	ip_multicast_hops (sockfd, HQLIP_HELLO_TTL);
        ip_pktinfo (sockfd, 1);
	ip_recvttl (sockfd, 1);
    }
    vif->udp_sockfd = sockfd;

    /* on some system, this is needed ... */
    select_add_fd_event ("hqlip_recv_hello", sockfd,
                       	  SELECT_READ, TRUE, hqlip->schedule,
                       	  hqlip_recv_hello, 2, hqlip, sockfd);
    return (sockfd);
}


static int
hqlip_vif_tcp_init (hqlip_t *hqlip, hqlip_interface_t *vif)
{
    int sockfd;
    u_char *bind_addr = (vif->prefix)? prefix_tochar (vif->prefix): NULL;

    if (vif->tcp_sockfd >= 0) {
	select_delete_fd (vif->tcp_sockfd);
	vif->tcp_sockfd = -1;
    }
    sockfd = socket_open (hqlip->family, SOCK_STREAM, 0);
    if (sockfd < 0)
	return (sockfd);
    socket_reuse (sockfd, 1);
    socket_bind_port (sockfd, hqlip->family, bind_addr, HQLIP_TCP_PORT);
    listen (sockfd, 5);
    vif->tcp_sockfd = sockfd;
    select_add_fd_event ("hqlip_open_accept", sockfd, 
			  SELECT_READ, TRUE, hqlip->schedule, 
			  hqlip_open_accept, 2, hqlip, vif);
    return (sockfd);
}


static void
hqlip_set_vif_prefix (hqlip_t *hqlip, hqlip_interface_t *vif, prefix_t *prefix)
{
    Deref_Prefix (vif->prefix);
    if (prefix == NULL) {
#ifdef HAVE_IPV6
	if (hqlip->family == AF_INET6)
	    vif->prefix = vif->interface->primary6->prefix;
	else
#endif /* HAVE_IPV6 */
        vif->prefix = vif->interface->primary->prefix;
    }
    else {
        vif->prefix = Ref_Prefix (prefix);
    }
}


void
hqlip_activate_interface (hqlip_t *hqlip,
			  hqlip_config_network_t *network, int on,
			  my_area_t *my_area0)
{
    hqlip_interface_t *vif;
    interface_t *interface = network->interface;

    if (on > 0 && BITX_TEST (&hqlip->interface_mask, interface->index)) {
	/* updating network */
	hqlip_neighbor_t *neighbor;
	vif = hqlip->hqlip_interfaces [interface->index];
	assert (vif);

	if (vif->keep_alive_interval != network->keep_alive_interval) {
	    vif->keep_alive_interval = (network->keep_alive_interval >= 0)?
						network->keep_alive_interval: 
						hqlip->keep_alive_interval;
	    LL_Iterate (vif->ll_neighbors, neighbor) {
	        Timer_Set_Time (neighbor->keep_alive, 
				vif->keep_alive_interval);
	        /* XXX need to restart timer to adjust immediately */
	    }
	}
	if (network->prefix && 
		!prefix_equal (vif->prefix, network->prefix)) {
	    /* to bind to a specific address to avoid from receiving 
		all hellos */
	    hqlip_set_vif_prefix (hqlip, vif, network->prefix);
	    hqlip_vif_udp_init (hqlip, vif);
	    hqlip_vif_tcp_init (hqlip, vif);
	}
	if (vif->metric != network->metric) {
	    vif->metric = network->metric;
	    /* XXX */
	}
	if (my_area0) {
	    vif->my_area0 = my_area0;
	    my_area0->vif = vif;
	}

	/* if_qos and link_qos are shared */
    }

    else if (on > 0 && !BITX_TEST (&hqlip->interface_mask, interface->index)) {
	/* new */
	if ((vif = hqlip->hqlip_interfaces [interface->index]) != NULL) {
	    Deref_Prefix (vif->prefix);
	    hqlip_set_vif_prefix (hqlip, vif, network->prefix);
	}
	else {
 	    vif = New (hqlip_interface_t);
            vif->interface = interface;
            vif->ll_neighbors = LL_Create (0);
	    vif->keep_alive_interval = (network->keep_alive_interval >= 0)?
						network->keep_alive_interval: 
						hqlip->keep_alive_interval;
	    vif->udp_sockfd = -1;
	    vif->tcp_sockfd = -1;
	    vif->metric = network->metric;
	    vif->if_qos = (network->config_if_qos)? 
				network->config_if_qos->if_qos: NULL;
	    vif->link_qos = copy_link_qos (network->config_link_qos->link_qos, 
					   NULL);
	    hqlip->hqlip_interfaces [interface->index] = vif;
	    if (my_area0) {
	        vif->my_area0 = my_area0;
	        my_area0->vif = vif;
	    }
	    LL_Add2 (hqlip->ll_hqlip_interfaces, vif);

	    hqlip_set_vif_prefix (hqlip, vif, network->prefix);
	    if (vif->my_area0 && BIT_TEST (interface->flags, IFF_LOOPBACK)) {
		spath_link_qos_t *spath_link_qos;
    		spath_link_qos = spath_link_qos_create (hqlip, /* reversed */
			       my_area0->area, my_area0->area,
			       vif->metric, 
			       copy_link_qos (vif->link_qos, NULL), 0);
    		hqlip_inject_spath_link_qos (hqlip, my_area0->parent, 
					     spath_link_qos);
		srsvp_create_neighbor (NULL, vif->prefix, interface);
	    }
	}
	BITX_SET (&hqlip->interface_mask, interface->index);
	assert (vif->udp_sockfd < 0);
	assert (vif->tcp_sockfd < 0);

	hqlip_vif_udp_init (hqlip, vif);
	hqlip_vif_tcp_init (hqlip, vif);

	hqlip_send_hello (hqlip, vif);
        vif->probe = New_Timer2 ("HQLIP hello timer", 
			       HQLIP_HELLO_INTERVAL, 0,
                               hqlip->schedule, 
			       (event_fn_t) hqlip_send_hello, 
			       2, hqlip, vif);
        timer_set_jitter (vif->probe, HQLIP_HELLO_JITTER);
    	Timer_Turn_ON (vif->probe);
    }
    else if (on < 0 && BITX_TEST (&hqlip->interface_mask, interface->index)) {
	vif = hqlip->hqlip_interfaces [interface->index];
	assert (vif);
	if (vif->my_area0 && BIT_TEST (interface->flags, IFF_LOOPBACK)) {
	    spath_link_qos_t *spath_link_qos;
    	    spath_link_qos = spath_link_qos_create (hqlip, /* reversed */
			       my_area0->area, my_area0->area,
			       vif->metric, 
			       copy_link_qos (vif->link_qos, NULL), 0);
	    BIT_SET (spath_link_qos->flags, LINK_QOS_DELETED);
    	    hqlip_inject_spath_link_qos (hqlip, my_area0->parent, 
					 spath_link_qos);
	}
	BITX_RESET (&hqlip->interface_mask, interface->index);
        Timer_Turn_OFF (vif->probe);
	if (vif->udp_sockfd >= 0) {
	    join_leave_group (hqlip->udp_sockfd, vif->interface, 
			      hqlip->all_hosts, 0);
	    select_delete_fd (vif->udp_sockfd);
	    vif->udp_sockfd = -1;
	}
	if (vif->tcp_sockfd >= 0) {
	/* interface_mask was off, hello timer off 
		so that gracefully stopping by protocol timeout */
	    select_delete_fd (vif->tcp_sockfd);
	    vif->tcp_sockfd = -1;
	}
        if (hqlip->udp_count++ <= 1) {
	    select_delete_fd (hqlip->udp_sockfd);
	    hqlip->udp_sockfd = -1;
	    hqlip->udp_count = 0;
        }
	Deref_Prefix (vif->prefix);
	vif->prefix = NULL;
    }
}


static link_qos_t *
hqlip_add_link_qos (link_qos_t *a, link_qos_t *b)
{
    a->flag = 0;
    a->loh = 0;
    /* XXX pps == 0 is considered as infinity */
    if (a->pps == 0 || a->pps > b->pps)
        a->pps = b->pps;
    a->dly += b->dly;
    return (a);
}


static void
hqlip_show_path_sub (uii_connection_t *uii, hqlip_t *hqlip, 
		     my_area_t *my_area, prefix_t *p1, prefix_t *p2,
		     link_qos_t *link_qos, int *metric)
{
    spath_area_addr_t *spath_area_addr;
    area_t *area1 = NULL, *area2 = NULL;
    assert (p1 != NULL || p2 != NULL);

    if (my_area->area->level <= 0) {
	uii_add_bulk_output (uii, 
		"at %s (%d:%a) terminated\n",
		my_area->name, my_area->area->level, my_area->area->id);
        link_qos->flag = 0;
        link_qos->pri = SSPEC_PRI_USER;
        link_qos->loh = 0;
        link_qos->pps = 999999 /* XXX */;
        link_qos->dly = 0;
	*metric = 0;
	return;
    }

    LL_Iterate (my_area->ll_spath_area_addrs, spath_area_addr) {
	prefix_t *prefix;
	if (BIT_TEST (spath_area_addr->flags, AREA_ADDR_DELETED))
	    continue;
	LL_Iterate (spath_area_addr->ll_prefixes, prefix) {
	    if (p1 && a_include_b (prefix, p1))
		area1 = spath_area_addr->area;
	    if (p2 && a_include_b (prefix, p2))
		area2 = spath_area_addr->area;
	    if ((p1 == NULL || area1) && (p2 == NULL || area2))
		break;
	}
    }

	if ((p1 && area1 == NULL) && (p2 && area2 == NULL)) {
	    uii_add_bulk_output (uii, 
		"at %s (%d:%a) both p1 %p and p2 %p not found\n",
		my_area->name, my_area->area->level, my_area->area->id,
		p1, p2);
	    return;
	}
	if (p1 && area1 == NULL) {
	    uii_add_bulk_output (uii, 
		"at %s (%d:%a) p1 %p not found\n",
		my_area->name, my_area->area->level, my_area->area->id, p1);
	    return;
	}
	if (p2 && area2 == NULL) {
	    uii_add_bulk_output (uii, 
		"at %s (%d:%a) p2 %p not found\n",
		my_area->name, my_area->area->level, my_area->area->id, p2);
	    return;
	}

	if (area1 == area2) {
	    if (area1->my_area == NULL) {
	        uii_add_bulk_output (uii, 
		    "at %s (%d:%a) both p1 %p and p2 %p fall into "
		    "foreign area %d:%a\n",
		    my_area->name, my_area->area->level, my_area->area->id,
		    p1, p2,
		    area1->level, area1->id);
		return;
	    }
	    uii_add_bulk_output (uii, 
		"at %s (%d:%a) going down to %s (%d:%a) for both\n",
		my_area->name, my_area->area->level, my_area->area->id,
		area1->my_area->name,
		area1->my_area->area->level, area1->my_area->area->id);
	    hqlip_show_path_sub (uii, hqlip, area1->my_area, p1, p2,
				 link_qos, metric);
	    return;
	}
	if (!area1->my_area && !area2->my_area) {
	    link_qos_t lqos;
	    int mm = 0;

	    uii_add_bulk_output (uii, 
		    "at %s (%d:%a) both p1 %p and p2 %p fall into "
		    "foreign area %d:%a and %d:%a\n",
		    my_area->name, my_area->area->level, my_area->area->id,
		    p1, p2,
		    area1->level, area1->id,
		    area2->level, area2->id);
    	    if (spath_calc_link_qos (hqlip, my_area, area1, area2, 
				     NULL, &lqos, &mm, NULL) == NULL) {
	        uii_add_bulk_output (uii, 
		    "at %s (%d:%a) path not found for %p -> %p\n",
		    my_area->name, my_area->area->level, my_area->area->id,
		    p1, p2);
	    }
	    else {
	        uii_add_bulk_output (uii, 
		    "at %s (%d:%a) path found for %p -> %p: "
			    "pri %d pps %d dly %d loh %d\n",
		    my_area->name, my_area->area->level, my_area->area->id,
		    p1, p2, lqos.pri, lqos.pps, lqos.dly, lqos.loh);

		hqlip_add_link_qos (link_qos, &lqos);
		*metric += mm;
	    }
	    return;
	}
	if (area1->my_area) {
	    link_qos_t lqos;
	    int mm = 0;
	    memset (&lqos, 0, sizeof (lqos));

	    uii_add_bulk_output (uii, 
		"at %s (%d:%a) going down to %s (%d:%a) for p1\n",
		my_area->name, my_area->area->level, my_area->area->id,
		area1->my_area->name,
		area1->my_area->area->level, area1->my_area->area->id);
	    hqlip_show_path_sub (uii, hqlip, area1->my_area, p1, NULL,
				 &lqos, &mm);
	    hqlip_add_link_qos (link_qos, &lqos);
	    *metric += mm;
	}
	else {
	    link_qos_t lqos;
	    int mm = 0;

	    uii_add_bulk_output (uii, 
		    "at %s (%d:%a) p1 %p falls into foreign area %d:%a\n",
		    my_area->name, my_area->area->level, my_area->area->id,
		    p1, area1->level, area1->id);
	    if (my_area->winner == NULL) {
	        uii_add_bulk_output (uii, 
		    "at %s (%d:%a) no center!\n",
		    my_area->name, my_area->area->level, my_area->area->id);
		return;
	    }
    	    if (spath_calc_link_qos (hqlip, my_area, 
				area1, my_area->winner->area, NULL,
				&lqos, &mm, NULL) == NULL) {
	        uii_add_bulk_output (uii, 
		    "at %s (%d:%a) path not found p1 (%d:%a) -> p2 (%d:%a) "
		    "(center)\n",
		    my_area->name, my_area->area->level, my_area->area->id,
		    area1->level, area1->id, 
		    my_area->winner->area->level, my_area->winner->area->id);
	    }
	    else {
	        uii_add_bulk_output (uii, 
		    "at %s (%d:%a) path found p1 (%d:%a) -> p2 (%d:%a) "
			    " (center) "
			    "pri %d pps %d dly %d loh %d\n",
		    my_area->name, my_area->area->level, my_area->area->id,
		    area1->level, area1->id, 
		    my_area->winner->area->level, my_area->winner->area->id,
		    lqos.pri, lqos.pps, lqos.dly, lqos.loh);
	        hqlip_add_link_qos (link_qos, &lqos);
	        *metric += mm;
	    }
	}
	if (area2->my_area) {
	    link_qos_t lqos;
	    int mm = 0;
	    memset (&lqos, 0, sizeof (lqos));

	    uii_add_bulk_output (uii, 
		"at %s (%d:%a) going down to %s (%d:%a) for p2\n",
		my_area->name, my_area->area->level, my_area->area->id,
		area2->my_area->name,
		area2->my_area->area->level, area2->my_area->area->id);
	    hqlip_show_path_sub (uii, hqlip, area2->my_area, NULL, p2,
				 &lqos, &mm);
	    hqlip_add_link_qos (link_qos, &lqos);
	    *metric += mm;
	}
	else {
	    link_qos_t lqos;
	    int mm = 0;
	    memset (&lqos, 0, sizeof (lqos));

	    uii_add_bulk_output (uii, 
		    "at %s (%d:%a) p2 %p falls into foreign area %d:%a\n",
		    my_area->name, my_area->area->level, my_area->area->id,
		    p2, area2->level, area2->id);
	    if (my_area->winner == NULL) {
	        uii_add_bulk_output (uii, 
		    "at %s (%d:%a) no center!\n",
		    my_area->name, my_area->area->level, my_area->area->id);
		return;
	    }
    	    if (spath_calc_link_qos (hqlip, my_area, 
				my_area->winner->area, area2, NULL,
				&lqos, &mm, NULL) == NULL) {
	        uii_add_bulk_output (uii, 
		    "at %s (%d:%a) path not found p1 (%d:%a) (center) "
		    "-> p2 (%d:%a)\n",
		    my_area->name, my_area->area->level, my_area->area->id,
		    my_area->winner->area->level, my_area->winner->area->id,
		    area2->level, area2->id);
	    }
	    else {
	        uii_add_bulk_output (uii, 
		    "at %s (%d:%a) path found p1 (%d:%a) (center) "
			    "-> p2 (%d:%a) pri %d pps %d dly %d loh %d\n",
		    my_area->name, my_area->area->level, my_area->area->id,
		    my_area->winner->area->level, my_area->winner->area->id,
		    area2->level, area2->id, 
		    lqos.pri, lqos.pps, lqos.dly, lqos.loh);
	        hqlip_add_link_qos (link_qos, &lqos);
	        *metric += mm;
	    }
	}

    if (spath_area_addr == NULL) {
	uii_add_bulk_output (uii, 
		"at %s (%d:%a) both p1 %p and p2 %p not found\n",
		my_area->name, my_area->area->level, my_area->area->id,
		p1, p2);
    }
}


int
hqlip_show_path (uii_connection_t *uii, char *ip, prefix_t *p1, prefix_t *p2)
{
    ricd_t *ricd = RICD;
    hqlip_t *hqlip;
    link_qos_t lqos;
    int mm = 0;

    memset (&lqos, 0, sizeof (lqos));
    if (strcasecmp (ip, "ipv6") == 0)
	ricd = RICD6;
    Delete (ip);

    hqlip = ricd->hqlip;
    hqlip_show_path_sub (uii, hqlip, hqlip->root, p1, p2, &lqos, &mm);
    uii_add_bulk_output (uii, 
	    "%p -> %p pri %d pps %d dly %d loh %d metric %d\n",
	    p1, p2, lqos.pri, lqos.pps, lqos.dly, lqos.loh, mm);
    return (1);
}


int
hqlip_show_neighbors (uii_connection_t *uii, char *ip, char *ifname)
{
    hqlip_interface_t *vif;
    hqlip_neighbor_t *neighbor;
    time_t now;
    interface_t *interface = NULL;
    ricd_t *ricd = RICD;
    hqlip_t *hqlip;

    if (strcasecmp (ip, "ipv6") == 0)
	ricd = RICD6;
    Delete (ip);

    if (ricd == NULL || ricd->hqlip == NULL)
	return (0);
    hqlip = ricd->hqlip;

    if (ifname) {
        interface = find_interface_byname (ifname);
        Delete (ifname);
        if (interface == NULL) {
            return (-1);
        }                            
    }                                   

    time (&now);
    uii_add_bulk_output (uii, "%-35s %7s %8s %3s %11s %11s\n",
                "Neighbor Address", "If", "Time", "UP", "KeepAlive", " Sent/Rcvd ");
    LL_Iterate (hqlip->ll_hqlip_interfaces, vif) {

	if (interface != NULL && interface != vif->interface)
	    continue;

	if (vif->ll_neighbors == NULL || LL_GetCount (vif->ll_neighbors) == 0)
	    continue;

	LL_Iterate (vif->ll_neighbors, neighbor) {
	    char buff[64], strbuf[64] = "";

	    if (vif->myself == neighbor)
	        sprintf (strbuf, " (self)");

	    if (neighbor->sockfd >= 0)
	        sprintf (strbuf, " (connected)");

	    if (!BITX_TEST (&hqlip->interface_mask, vif->interface->index))
	        sprintf (strbuf, " (deleted)");
	        
            uii_add_bulk_output (uii, 
		    "%-35a %7s %8s %3d %5d/%-5d %5d/%-5d %s\n",
		    neighbor->prefix, neighbor->vif->interface->name,
		    time2date (now - neighbor->utime, buff),
		    neighbor->num_session_up,
		    (neighbor->timeout->time_next_fire > 0)?
		    time_left (neighbor->timeout): 0,
		    neighbor->timeout->time_interval,
		    neighbor->num_packets_sent, neighbor->num_packets_recv,
		    strbuf);
	}
    }
    return (1);
}


static void
hqlip_show_sub_areas (uii_connection_t *uii, hqlip_t * hqlip, 
			my_area_t *my_area)
{
    spath_link_qos_t *spath_link_qos;
    spath_area_addr_t *spath_area_addr;
    spath_area_center_t *spath_area_center;

    if (my_area->ll_children) {
	my_area_t *child;
	LL_Iterate (my_area->ll_children, child) {
	    hqlip_show_sub_areas (uii, hqlip, child);
	}
    }

    uii_add_bulk_output (uii, "%-10s %2d:%-41a %-23s",
		my_area->name, my_area->area->level, my_area->area->id,
		(my_area->parent)? my_area->parent->name: "");
    if (my_area->center) {
    	uii_add_bulk_output (uii, " %3d %6d", 
			my_area->center->pri, my_area->pps);
    }
    else {
    	uii_add_bulk_output (uii, " %3s %6s", "", "");
    }
    uii_add_bulk_output (uii, " %5s %3s", "", "");
    if (my_area->ll_prefixes) {
	prefix_t *prefix;
	LL_Iterate (my_area->ll_prefixes, prefix) {
    	    uii_add_bulk_output (uii, " %p", prefix);
	}
    }
    uii_add_bulk_output (uii, "\n");

    LL_Iterate (my_area->ll_spath_link_qoses, spath_link_qos) {
	link_qos_t *link_qos;

    if (spath_link_qos->ll_link_qoses)
	LL_Iterate (spath_link_qos->ll_link_qoses, link_qos) {

    	    uii_add_bulk_output (uii, "%2s%s %-6s", 
	        BIT_TEST (spath_link_qos->flags, LINK_QOS_DELETED)? " D": "",
		BIT_TEST (spath_link_qos->flags, LINK_QOS_EXTERNAL)? "E": "I",
			"LINK");

    	    uii_add_bulk_output (uii, " %2d:%-17a -> %2d:%-17a",
		spath_link_qos->area1->level, spath_link_qos->area1->id,
		spath_link_qos->area2->level, spath_link_qos->area2->id);

            if (spath_link_qos->neighbor)
    	        uii_add_bulk_output (uii, " %-23a", 
		    spath_link_qos->neighbor->prefix);
	    else
    	        uii_add_bulk_output (uii, " %23s", "");

    	    uii_add_bulk_output (uii, " %3u %6u %5u",
			    link_qos->pri, link_qos->pps, link_qos->dly,
			    link_qos->loh);
	    if (link_qos->flag) 
		uii_add_bulk_output (uii, " %3u", link_qos->loh);
	    else
		uii_add_bulk_output (uii, " %3s", "");

	}
    	uii_add_bulk_output (uii, "\n");
    }
    LL_Iterate (my_area->ll_spath_area_addrs, spath_area_addr) {
	prefix_t *prefix;

            uii_add_bulk_output (uii, "%2s  %-6s", 
	        BIT_TEST (spath_area_addr->flags, AREA_ADDR_DELETED)? " D": "",
			"ADDR");
    	    uii_add_bulk_output (uii, " %2d:%-41a",
		spath_area_addr->area->level, spath_area_addr->area->id);

            if (spath_area_addr->neighbor)
    	        uii_add_bulk_output (uii, " %-23a", 
		    spath_area_addr->neighbor->prefix);
	    else
    	        uii_add_bulk_output (uii, " %23s", "");

    	    uii_add_bulk_output (uii, " %3s %6s %5s %3s", "", "", "", "");

    if (spath_area_addr->ll_prefixes)
	LL_Iterate (spath_area_addr->ll_prefixes, prefix)
    	    uii_add_bulk_output (uii, " %p", prefix);

    	uii_add_bulk_output (uii, "\n");
    }
    LL_Iterate (my_area->ll_spath_area_centers, spath_area_center) {

        uii_add_bulk_output (uii, "%2s%s %-6s", 
	        BIT_TEST (spath_area_center->flags, AREA_CENTER_DELETED)?
			" D": "",
		(my_area->winner == spath_area_center)?">":" ",
			"CENTER");
    	uii_add_bulk_output (uii, " %2d:%-41a",
		spath_area_center->area->level, spath_area_center->area->id);
        if (spath_area_center->neighbor)
    	        uii_add_bulk_output (uii, " %-23a", 
		    spath_area_center->neighbor->prefix);
	    else
    	        uii_add_bulk_output (uii, " %23s", "");

        uii_add_bulk_output (uii, " %3u", spath_area_center->pri);
    	uii_add_bulk_output (uii, " %6s %5s %3s", "", "", "");
    	uii_add_bulk_output (uii, "\n");
    }
}


int
hqlip_show_areas (uii_connection_t *uii, char *ip)
{
    ricd_t *ricd = RICD;
    hqlip_t *hqlip;

    if (strcasecmp (ip, "ipv6") == 0)
	ricd = RICD6;
    Delete (ip);

    if (ricd == NULL || ricd->hqlip == NULL)
	return (0);
    hqlip = ricd->hqlip;

    if (hqlip->ll_areas == NULL)
	return (0);

    uii_add_bulk_output (uii, "%10s %-44s %-23s %3s %5s %6s %3s %s\n",
	"AREA/TYPE", "   AREA ID(S)", "PARENT/FROM", "PRI", "PPS", 
	"DLY", "LOH", "ADDR(S)");
    hqlip_show_sub_areas (uii, hqlip, hqlip->root);
    return (1);
}


static void
hqlip_neighbor_start (hqlip_t *hqlip, hqlip_neighbor_t *neighbor)
{
    hqlip_interface_t *vif;
    my_area_t *my_area1, *my_area0, *my_area;
    spath_link_qos_t *spath_link_qos;

    time (&neighbor->utime);
    neighbor->num_packets_sent = 0;
    neighbor->num_packets_recv = 0;
    neighbor->num_session_up++;
    BIT_SET (neighbor->flags, HQLIP_NEIGHBOR_CONNECTED);
    neighbor->synced_level_bitset = 0;

    vif = neighbor->vif;
    my_area0 = vif->my_area0;
    my_area1 = vif->my_area0->parent;

    /* this has to be done before syncing to avoid duplicate send */
    /* (i,j) means a qos when area i receives from area j */
    spath_link_qos = spath_link_qos_create (hqlip, /* reversed */
			       add_area (0, neighbor->prefix), my_area0->area,
			       vif->metric, 
			       copy_link_qos (vif->link_qos, NULL), 0);
    /* neighbor->spath_link_qos = spath_link_qos; */
    hqlip_inject_spath_link_qos (hqlip, my_area1, spath_link_qos);

    /* mark sync on all applicable areas */
    my_area = my_area1;
    do {
	LL_Add3 (my_area->ll_neighbors, neighbor);
	BIT_SET (my_area->flags, HQLIP_MY_AREA_SYNCING);
    } while ((my_area = my_area->parent) != NULL);

    /* ready, set, go */
    Timer_Turn_ON (neighbor->keep_alive);
    Timer_Turn_ON (neighbor->timeout);
    select_add_fd_event ("hqlip_get_pdu", neighbor->sockfd, SELECT_READ,
                         1 /* on */, neighbor->schedule,
                         (event_fn_t) hqlip_get_pdu, 2, hqlip, neighbor);
#ifndef HAVE_LIBPTHREAD
    select_add_fd_event ("hqlip_flush_queue", neighbor->sockfd, SELECT_WRITE,
                         0 /* off */, neighbor->schedule,
                         (event_fn_t) hqlip_flush_queue, 2, hqlip, neighbor);
#endif /* HAVE_LIBPTHREAD */

    my_area = my_area1;
    do {
        hqlip_send_link_qos (hqlip, my_area, neighbor, NULL);
        hqlip_send_area_center (hqlip, my_area, neighbor, NULL);
        hqlip_send_area_addr (hqlip, my_area, neighbor, NULL);
        /* hqlip_send_area_qos (hqlip, my_area, neighbor, NULL); */
        hqlip_send_sync (hqlip, my_area->area->level, neighbor);
    } while ((my_area = my_area->parent) != NULL);
}


static int
hqlip_spath_compare (u_char *a, u_char *b)
{
    int a_flags, a_type, a_level, a_len, a_tstamp;
    int b_flags, b_type, b_level, b_len, b_tstamp;
    HQLIP_GET_HEADER (a_flags, a_type, a_level, a_len, a_tstamp, a);
    HQLIP_GET_HEADER (b_flags, b_type, b_level, b_len, b_tstamp, b);
    /* area center goes first */
    if (a_type == HQLIP_MSG_AREA_CENTER && b_type != HQLIP_MSG_AREA_CENTER)
	return (-1);
    if (a_type == HQLIP_MSG_LINK_QOS && b_type == HQLIP_MSG_LINK_QOS) {
	/* internal link qos goes first */
	if (!BIT_TEST (a_flags, LINK_QOS_EXTERNAL) &&
		BIT_TEST (b_flags, LINK_QOS_EXTERNAL))
	    return (-1);
    }
    /* don't care others */
    return (a_tstamp - b_tstamp);
}


static int
hqlip_process_pdu (hqlip_t *hqlip, hqlip_neighbor_t *neighbor)
{
    int flags, type, level, len;
    time_t tstamp;
    int error = 0;
    u_char *cp, *packet;
    my_area_t *my_area = NULL;
    hqlip_interface_t *vif;

    assert (neighbor);
    assert (neighbor->packet);
    vif = neighbor->vif;

    neighbor->num_packets_recv++;

    cp = neighbor->packet;
    HQLIP_GET_HEADER (flags, type, level, len, tstamp, cp);

    if (type >= HQLIP_MSG_KEEP_ALIVE && type <= HQLIP_MSG_SYNC) {
        trace (TR_PACKET, neighbor->trace, 
		"recv %s flags 0x%x level %d (%d bytes)\n",
	        hqlip_pdus[type], flags, level, len);
    }

    if (len < HQLIP_MSG_HDR_SIZE) {
        trace (TR_ERROR, neighbor->trace, 
	    "recv a message with too short length %d\n", len);
	return (-1);
    }

    if (level > HQLIP_AREA_LEVEL_INTERNET) {
        trace (TR_ERROR, neighbor->trace, 
	    "recv a message with too large level %d\n", level);
	return (-1);
    }

    switch (type) {
	case HQLIP_MSG_LINK_QOS:
	case HQLIP_MSG_AREA_CENTER:
	case HQLIP_MSG_AREA_ADDR:
	case HQLIP_MSG_AREA_QOS:
	case HQLIP_MSG_SYNC:
	    my_area = vif->my_area0;
	    while (my_area->area->level < level)
	        my_area = my_area->parent;
	    /* must stop at internet */
	    if (my_area->area->level != level) {
		trace (TR_PACKET, neighbor->trace,
	       		"no such a level %d here\n", level);
		return (0);
	    }
	    break;
    }

    switch (type) {
	case HQLIP_MSG_LINK_QOS:
	case HQLIP_MSG_AREA_CENTER:
	case HQLIP_MSG_AREA_ADDR:
	case HQLIP_MSG_AREA_QOS:
	    if (!BITM_TEST (neighbor->synced_level_bitset, level)) {
		packet = NewArray (u_char, len);
		memcpy (packet, neighbor->packet, len);
		LL_Append (neighbor->ll_packets, packet);
		return (0);
	    }
	    break;
    }

    switch (type) {
        case HQLIP_MSG_KEEP_ALIVE:
	    if (len != HQLIP_MSG_HDR_SIZE) {
		error = 1;
		break;
	    }
	    break;
	case HQLIP_MSG_LINK_QOS:
	    hqlip_recv_link_qos (hqlip, neighbor, my_area, flags, 
				 len - HQLIP_MSG_HDR_SIZE, tstamp, cp);
	    break;
	case HQLIP_MSG_AREA_CENTER:
	    hqlip_recv_area_center (hqlip, neighbor, my_area, flags, 
				    len - HQLIP_MSG_HDR_SIZE, tstamp, cp);
	    break;
	case HQLIP_MSG_AREA_ADDR:
	    hqlip_recv_area_addr (hqlip, neighbor, my_area, flags, 
				  len - HQLIP_MSG_HDR_SIZE, tstamp, cp);
	    break;
	case HQLIP_MSG_AREA_QOS:
	    break;
	case HQLIP_MSG_SYNC:
	    if (len != HQLIP_MSG_HDR_SIZE) {
		error = 1;
		break;
	    }
	    if (BITM_TEST (neighbor->synced_level_bitset, level)) {
		trace (TR_ERROR, neighbor->trace,
	       		"duplicate sync at %d\n", level);
	    }
	    LL_Iterate (neighbor->ll_packets, packet) {
		/* we can not change packet since ll_iterate gets confused */
		cp = packet;
    		HQLIP_GET_HEADER (flags, type, level, len, tstamp, cp);
    		switch (type) {
		case HQLIP_MSG_LINK_QOS:
	            hqlip_recv_link_qos (hqlip, neighbor, my_area, flags, 
				         len - HQLIP_MSG_HDR_SIZE, tstamp, cp);
	            break;
	        case HQLIP_MSG_AREA_CENTER:
	            hqlip_recv_area_center (hqlip, neighbor, my_area, flags, 
				    	    len - HQLIP_MSG_HDR_SIZE, tstamp, 
					    cp);
	            break;
		case HQLIP_MSG_AREA_ADDR:
	            hqlip_recv_area_addr (hqlip, neighbor, my_area, flags, 
				          len - HQLIP_MSG_HDR_SIZE, tstamp, 
					  cp);
	            break;
		case HQLIP_MSG_AREA_QOS:
	    	    break;
		default:
		    assert (0);
		    break;
		}
	    }
	    LL_Clear (neighbor->ll_packets);
	    BITM_SET (neighbor->synced_level_bitset, level);
	    /* XXX need to wait to finish sending? */
	    BIT_RESET (my_area->flags, HQLIP_MY_AREA_SYNCING);
    	    hqlip_update_area_center (hqlip, my_area, NULL);
	    /* children couldn't calculate since I'm syncing */
	    if (level > 1) {
    		my_area_t *child;
	        LL_Iterate (my_area->ll_children, child) {
                    hqlip_update_database (hqlip, child);
	        }
	    }
	    break;
	default:
            trace (TR_ERROR, neighbor->trace, 
		"recv unknown message type %d (%d bytes)\n", type, len);
	    return (-1);
    }
    if (error > 0) {
        trace (TR_ERROR, neighbor->trace, 
	    "recv %s with bad length %d\n", hqlip_pdus[type], len);
	return (-1);
    }
    else {
	Timer_Reset_Time (neighbor->timeout);
    }
    return (1);
}


hqlip_neighbor_t *
hqlip_find_nexthop (hqlip_t *hqlip, my_area_t *my_area, prefix_t *destin,
		    req_qos_t *req_qos, link_qos_t *link_qos, int *metric,
		    u_long *errcode)
{
    spath_area_addr_t *spath_area_addr;
    area_t *area2 = NULL;
    hqlip_neighbor_t *neighbor = NULL;

    if (my_area->area->level <= 0) {
	assert (area_is_local (my_area->area));
        link_qos->flag = 0;
        link_qos->pri = (req_qos)? req_qos->pri: SSPEC_PRI_USER;
        link_qos->loh = 0;
        link_qos->pps = (req_qos)? req_qos->pps: 999999 /* XXX */;
        link_qos->dly = 0;
	*metric = 0;
 	*errcode = 0;
	return (my_area->vif->myself);
    }

    LL_Iterate (my_area->ll_spath_area_addrs, spath_area_addr) {
	prefix_t *prefix;
	if (BIT_TEST (spath_area_addr->flags, AREA_ADDR_DELETED))
	    continue;
	LL_Iterate (spath_area_addr->ll_prefixes, prefix) {
	    if (a_include_b (prefix, destin)) {
		area2 = spath_area_addr->area;
		neighbor = spath_area_addr->neighbor;
		break;
	    }
	}
    }

    if (area2 == NULL) {
	*errcode = SRSVP_MSG_ERR_UNREACH;
	return (NULL);
    }
    if (!area_is_local (area2)) {
    	if (spath_calc_link_qos (hqlip, my_area, NULL, area2, req_qos,
				link_qos, metric, errcode) == NULL) {
	    return (NULL);
	}
	return (neighbor);
    }

    return (hqlip_find_nexthop (hqlip, area2->my_area, destin,
		     req_qos, link_qos, metric, errcode));
}


void 
hqlip_link_status (hqlip_t *hqlip, req_qos_t *req_qos, interface_t *interface,
		   int on)
{
    hqlip_interface_t *vif;
    hqlip_neighbor_t *neighbor;
    my_area_t *my_area0, *my_area1;
    spath_link_qos_t *spath_link_qos;

    assert (hqlip);
    assert (req_qos);
    assert (interface);
    vif = hqlip->hqlip_interfaces[interface->index];
    if (vif == NULL) {
        trace (TR_WARN, hqlip->trace, 
		"hqlip_link_status: interface %s not found\n",
		interface->name);
        Destroy (req_qos);
	return;
    }

    my_area0 = vif->my_area0;
    my_area1 = vif->my_area0->parent;

    trace (TR_TRACE, hqlip->trace, 
	  "hqlip_link_status: %s pps %d %s %d\n",
	   interface->name, vif->link_qos->pps, 
	   (on)? "minus": "plus", req_qos->pps);
    if (on) {
	vif->link_qos->pps -= req_qos->pps;
    }
    else {
	vif->link_qos->pps += req_qos->pps;
    }

    LL_Iterate (vif->ll_neighbors, neighbor) {
        if (BIT_TEST (neighbor->flags, HQLIP_NEIGHBOR_DELETED))
	    continue;
        if (!BIT_TEST (neighbor->flags, HQLIP_NEIGHBOR_CONNECTED))
	    continue;

        /* XXX */
        spath_link_qos = spath_link_qos_create (hqlip, /* reversed */
			add_area (0, neighbor->prefix), my_area0->area,
			vif->metric, 
			copy_link_qos (vif->link_qos, NULL), 0);
        hqlip_inject_spath_link_qos (hqlip, my_area1, spath_link_qos);
    }
    Destroy (req_qos);
}
