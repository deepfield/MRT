/*
 * $Id: dvmrp.c,v 1.1.1.1 2000/08/14 18:46:12 labovit Exp $
 */

#include "mrt.h"
#ifdef HAVE_MROUTING
#include "array.h"
#include "config_file.h"
#include "igmp.h"
#include "dvmrp.h"
#include <netinet/in_systm.h>
/*#include <netinet/ip.h>*/
/*#include <netinet/igmp.h>*/


dvmrp_t *DVMRP;

char *s_dvmrp [] =
{
    "Null",
    "Neighbor Probe",
    "Route Report",
    "Neighbor Request",
    "Neighbor List",
    "Neighbor Request 2",
    "Neighbor List 2",
    "Prune Message",
    "Graft Message",
    "Graft Message Ack",
    "Info Request",
    "Info Reply",
};


#define DVMRP_MAJOR_VERSION 3 
#define DVMRP_MINOR_VERSION 255 
#define DVMRP_CAPABILITY_FLAGS  0x0e

static int
dvmrp_send (int code, prefix_t *dst, u_char *data, int len, 
	    interface_t *interface)
{
    igmp_t *igmp = IGMP;
    u_long level = htonl (DVMRP->level);
    prefix_t *group = New_Prefix (AF_INET, &level, 32);
    int ret;

    if (dst == NULL)
	dst = DVMRP->all_routers;

    trace (TR_PACKET, DVMRP->trace,
	   "send [%s] %d bytes to %a on %s\n", s_dvmrp[code],
	   len, dst, (interface)?interface->name:"?");
    ret = igmp_send (igmp, dst, group, 
		     IGMP_DVMRP, code, data, len, interface);
    Deref_Prefix (group);
    return (ret);
}


/* vif is always available */
static int
dvmrp_send_probe (dvmrp_interface_t *vif, prefix_t *addr)
{
    dvmrp_neighbor_t *nbr;
    u_char sendbuf[MAX_DVMRP_DATA_LEN];
    u_char *cp = sendbuf;

    if (!BITX_TEST (&DVMRP->interface_mask, vif->interface->index))
	return (0);

    MRT_PUT_LONG (DVMRP->genid, cp);
    if (addr) {
	trace (TR_PACKET, DVMRP->trace,
               "send neighbor %a on %s (only)\n", addr, vif->interface->name);
    }
    else LL_Iterate (vif->ll_neighbors, nbr) {
	/* skip dummy neighbor */
	if (nbr->ctime == 0)
	    continue;
	trace (TR_PACKET, DVMRP->trace,
               "send neighbor %a on %s\n", nbr->prefix, vif->interface->name);
	MRT_PUT_NETLONG (prefix_tolong (nbr->prefix), cp);
    }

    /* I don't know but mrouted does so */
    MRT_PUT_LONG (0L, cp);

    return (dvmrp_send (DVMRP_PROBE, NULL, sendbuf, cp - sendbuf, 
	        	vif->interface));
}


static int
dvmrp_send_prune (prefix_t *src, prefix_t *dst, int lifetime, 
		  dvmrp_neighbor_t *neighbor)
{
    u_char sendbuf[MAX_DVMRP_DATA_LEN];
    u_char *cp = sendbuf;

    assert (neighbor);
    MRT_PUT_NETLONG (prefix_tolong (src), cp);
    MRT_PUT_NETLONG (prefix_tolong (dst), cp);
    MRT_PUT_LONG (lifetime, cp);
    MRT_PUT_LONG (0, cp);
    trace (TR_PACKET, DVMRP->trace,
           "send prune for src %a dst %a lifetime %d to %a\n",
	   src, dst, lifetime, neighbor->prefix);
    return (dvmrp_send (DVMRP_PRUNE, neighbor->prefix, sendbuf, cp - sendbuf, 
	        	neighbor->interface));
}


static void
dvmrp_delete_neighbor (dvmrp_neighbor_t *nbr)
{
    if (nbr->timeout)
        Destroy_Timer (nbr->timeout);
    Deref_Prefix (nbr->prefix);
    Delete (nbr);
}


static void
dvmrp_neighbor_timeout (dvmrp_neighbor_t *nbr)
{
    dvmrp_interface_t *vif;
   /* since timeout event is queued, it may happen after deletion is done.
      so the info remains and reused later */
    if (BIT_TEST (nbr->flags, DVMRP_NEIGHBOR_DELETE))
        return;

    BIT_SET (nbr->flags, DVMRP_NEIGHBOR_DELETE);
    trace (TR_TRACE, DVMRP->trace, 
	   "neighbor %a on %s index %d level %x genid %x timed out\n",
	   nbr->prefix, nbr->interface->name, nbr->index, 
	   nbr->level, nbr->genid);
    vif = DVMRP->dvmrp_interfaces[nbr->interface->index];
    assert (vif);
    if (--vif->nbr_count <= 0) {
        vif->flags |= DVMRP_VIF_LEAF;
    }
}


static dvmrp_neighbor_t *
dvmrp_lookup_neighbor (interface_t *interface, u_long level, prefix_t *source)
{
    dvmrp_neighbor_t *nbr;
    dvmrp_interface_t *vif;

    /* assert (interface->vif_index >= 0); */
    vif = DVMRP->dvmrp_interfaces[interface->index];
    assert (vif);

    LL_Iterate (vif->ll_neighbors, nbr) {
	if (prefix_compare2 (source, nbr->prefix) == 0)
	    break;
    }

    return (nbr);
}


static dvmrp_neighbor_t *
dvmrp_register_neighbor (dvmrp_interface_t *vif, u_long level, u_long genid,
			 prefix_t *source)
{
    dvmrp_neighbor_t *nbr;
    int i;

#ifdef notdef
    assert (!BITX_TEST (&DVMRP->force_leaf_mask, vif->interface->index));
#endif /* notdef */

	/* zero is reserved for now */
	for (i = 1; i < MAX_NEIGHBORS; i++) {
	    if (DVMRP->index2neighbor[i] == NULL)
		break;
	}
	if (i >= MAX_NEIGHBORS) {
	    trace (TR_ERROR, DVMRP->trace, 
		   "too many DVMRP neighbors (%d)\n", i);
	    return (NULL);
	}
	nbr = New (dvmrp_neighbor_t);
	nbr->prefix = Ref_Prefix (source);
	nbr->interface = vif->interface;
	nbr->level = level;
	nbr->index = i;
	nbr->genid = genid;
	/* special neighbor */
	DVMRP->index2neighbor[i] = nbr;
	LL_Add (vif->ll_neighbors, nbr);
	if (genid != 0) {
	    if (!BITX_TEST (&DVMRP->force_leaf_mask, vif->interface->index)) {
	        if (vif->nbr_count++ <= 0)
                    vif->flags &= ~DVMRP_VIF_LEAF;
	    }
            nbr->utime = time (&nbr->ctime);
	    nbr->timeout = New_Timer2 ("DVMRP neighbor timeout timer",
                                DVMRP_NEIGHBOR_EXPIRE_TIME, TIMER_ONE_SHOT,
                                DVMRP->schedule, dvmrp_neighbor_timeout, 
				1, nbr);
            Timer_Turn_ON (nbr->timeout);
	}
	return (nbr);
}


static void
dvmrp_recover_neighbor (dvmrp_interface_t *vif, dvmrp_neighbor_t *nbr)
{
    assert (BIT_TEST (nbr->flags, DVMRP_NEIGHBOR_DELETE));
    BIT_RESET (nbr->flags, DVMRP_NEIGHBOR_DELETE);
    Timer_Reset_Time (nbr->timeout);
    Timer_Turn_ON (nbr->timeout);
    trace (TR_WARN, DVMRP->trace,
           "router %a on %s index %d recovered\n",
           nbr->prefix, nbr->interface->name, nbr->index);
    if (vif->nbr_count++ <= 0) {
        vif->flags &= ~DVMRP_VIF_LEAF;
    }
}


static void
dvmrp_recv_probe (interface_t *interface, 
	          u_long level, prefix_t *source, u_char *data, int datalen)
{
    dvmrp_neighbor_t *nbr;
    u_long genid;
    u_char *endp = data + datalen;
    int i_am_on = 0;
    dvmrp_interface_t *vif;

   /* don't listen to things from our own interface */
    if (find_interface_local (source)) {
        trace (TR_PACKET, DVMRP->trace,
               "ignore own probe from %a on %s, ignore!\n",
               source, interface->name);
        return;
    }

#ifdef notdef
    if (/* interface->vif_index < 0 || */
	    !BITX_TEST (&DVMRP->interface_mask, interface->index) ||
	    BITX_TEST (&DVMRP->force_leaf_mask, interface->index)) {
        trace (TR_WARN, DVMRP->trace,
               "probe from %a on disabled interface %s\n",                     
               source, interface->name);         
        return;
    }
#endif /* notdef */

    if (endp - data < 4) {
	trace (TR_ERROR, DVMRP->trace, 
	       "too short datalen (%d) to get generation id\n",
	       endp - data);
	return;
    }
    MRT_GET_LONG (genid, data);
    trace (TR_PACKET, DVMRP->trace, "genid 0x%x\n", genid);

    while (endp - data > 0) {
	prefix_t *prefix;
	u_long addr;

	if (endp - data < 4) {
	    trace (TR_ERROR, DVMRP->trace, 
	           "too short datalen (%d) to get a neighbor\n",
	           endp - data);
	    return;
	}
	MRT_GET_NETLONG (addr, data);
	prefix = New_Prefix (AF_INET, &addr, 32);
	if (is_prefix_local_on (prefix, interface)) {
	   trace (TR_PACKET, DVMRP->trace, 
	   	  "recv neighbor %a on %s (mine)\n", prefix,
	   	  interface->name);
	   i_am_on++;
	}
	else
	   trace (TR_PACKET, DVMRP->trace, 
		  "recv neighbor %a on %s (someone else)\n", 
		  prefix, interface->name);
	Deref_Prefix (prefix);
    }

    vif = DVMRP->dvmrp_interfaces[interface->index];
    assert (vif);

    nbr = dvmrp_lookup_neighbor (interface, level, source);
    if (nbr == NULL) {
	nbr = dvmrp_register_neighbor (vif, level, genid, source);
	/* this is new to me */
	if (!BITX_TEST (&DVMRP->force_leaf_mask, vif->interface->index))
	    dvmrp_send_probe (vif, source);
    }
    else if (BIT_TEST (nbr->flags, DVMRP_NEIGHBOR_DELETE)) {
        dvmrp_recover_neighbor (vif, nbr);
    }
    else {
	if (nbr->genid != genid) {
	    trace (TR_WARN, DVMRP->trace, 
		   "router %a genid changed (0x%x -> 0x%x)\n", 
		    source, nbr->genid, genid);
	    nbr->genid = genid;
            time (&nbr->ctime);
	}
        time (&nbr->utime);
	Timer_Reset_Time (nbr->timeout);
    }
    /* XXX check to see if bi-directional */
}


static void
dvmrp_prune_expire (void)
{                            
    cache_entry_t *entry;
    dvmrp_prune_t *prune;
    time_t now;

    trace (TR_TRACE, DVMRP->trace, "timer (expire) fired\n");
    time (&now);

    HASH_Iterate (CACHE->hash, entry) { 
        if (entry->ll_prunes == 0)
	    continue;
	LL_Iterate (entry->ll_prunes, prune) {
	    if (prune->expire > 0 && prune->expire > now) {
		dvmrp_prune_t *prev = LL_GetPrev (entry->ll_prunes, prune);
	        trace (TR_WARN, DVMRP->trace, 
		       "prune source %a group %a from %s on %s expired\n", 
		        entry->source, entry->group, prune->neighbor->prefix, 
			prune->neighbor->interface);
                LL_Remove (entry->ll_prunes, prune);
                prune = prev;
		/* don't need to send a graft 
		   since the neighbor should have timed out before this */
	    }
	}
    }
}


static void
dvmrp_recv_prune (interface_t *interface, 
	          u_long level, prefix_t *source, u_char *data, int datalen)
{
    dvmrp_neighbor_t *nbr;
    u_long prune_src, prune_grp;
    prefix_t *prune_source, *prune_group;
    int lifetime, min_lifetime = AVERAGE_PRUNE_LIFETIME;
    u_char *endp = data + datalen;
    cache_entry_t e, *entry;
    dvmrp_route_t *route;
    time_t now;
    neighbor_bitset_t bitset;
    dvmrp_prune_t *prune;

#ifdef notdef
    if (/* interface->vif_index < 0 || */
	    !BITX_TEST (&DVMRP->interface_mask, interface->index) ||
	    BITX_TEST (&DVMRP->force_leaf_mask, interface->index)) {
        trace (TR_WARN, DVMRP->trace,
               "prune from %a on disabled interface %s\n",                     
               source, interface->name);         
        return;
    }
#endif /* notdef */

    if (endp - data < 12) {
	trace (TR_ERROR, DVMRP->trace, 
	       "too short datalen (%d) for prune\n",
	       endp - data);
	return;
    }

    nbr = dvmrp_lookup_neighbor (interface, level, source);
    if (nbr == NULL) {
	trace (TR_PACKET, DVMRP->trace, 
	       "unknown neighbor %a on %s\n", source, interface->name);
	return;
    }

    MRT_GET_LONG (prune_src, data);
    prune_source = New_Prefix (AF_INET, &prune_src, 32);
    MRT_GET_LONG (prune_grp, data);
    prune_group = New_Prefix (AF_INET, &prune_grp, 32);
    MRT_GET_LONG (lifetime, data);
    trace (TR_PACKET, DVMRP->trace, 
	   "recv prune source %a group %a lifetime %d\n", 
	   prune_source, prune_group, lifetime);
    if (lifetime < MIN_PRUNE_LIFETIME) {
        trace (TR_PACKET, DVMRP->trace, 
	       "too short prune lifetime %d (< %d) from %a on %s\n", 
	       lifetime, MIN_PRUNE_LIFETIME, source, interface->name);
	goto ignore;
    }

    e.source = prune_source;
    e.group = prune_group;
    entry = HASH_Lookup (CACHE->hash, &e);
    if (entry == NULL) {
        trace (TR_PACKET, DVMRP->trace, 
	       "no cache entry for group %a source %a from %a on %s\n", 
	       prune_source, prune_group,
	       source, interface->name);
	goto ignore;
    }

    route = (dvmrp_route_t *) entry->data;
    if (BITX_TEST (&route->dependents, nbr->index)) {
        trace (TR_PACKET, DVMRP->trace, 
	       "prune from non-dependent router %a on %s\n", 
	       source, interface->name);
	goto ignore;
    }

    bitset = route->dependents;
    time (&now);
    LL_Iterate (entry->ll_prunes, prune) {
	assert (BITX_TEST (&bitset, prune->neighbor->index));
	BITX_RESET (&bitset, prune->neighbor->index);
	if (prune->neighbor == nbr) {
	    prune->received = now;
	    prune->lifetime = lifetime;
	    prune->expire = now + lifetime;
            trace (TR_PACKET, DVMRP->trace, 
	           "update prune for group %a source %a lifetime %d from %a on %s\n", 
	           prune_source, prune_group, lifetime, source, interface->name);
	    break;
	}
	if (min_lifetime > prune->expire - now)
	    min_lifetime = prune->expire - now;
    }
    if (prune == NULL) {
        prune = New (dvmrp_prune_t);
        prune->neighbor = nbr;
        prune->received = now;
        prune->lifetime = lifetime;
	prune->expire = now + lifetime;
        if (entry->ll_prunes == NULL)
	    entry->ll_prunes = LL_Create (LL_DestroyFunction, FDelete, 0);
        LL_Add (entry->ll_prunes, prune);
        trace (TR_PACKET, DVMRP->trace, 
	       "new prune for group %a source %a lifetime %d from %a on %s\n", 
	       prune_source, prune_group, lifetime, source, interface->name);
	assert (BITX_TEST (&bitset, prune->neighbor->index));
	BITX_RESET (&bitset, prune->neighbor->index);
	if (min_lifetime > prune->expire - now)
	    min_lifetime = prune->expire - now;
	if (ifzero (&bitset, sizeof (bitset))) {
	    dvmrp_send_prune (entry->source, entry->group, 
		  min_lifetime /* XXX */, route->neighbor);
	}
    }


  ignore:
    Deref_Prefix (prune_source);
    Deref_Prefix (prune_group);
}


/* 
 * run policy on a dvmrp route 
 * returns -1 when policy rejects it
 * otherwise returns ajusted metric
 */
static int
dvmrp_policy_in (prefix_t * prefix, int metric, dvmrp_interface_t *vif)
{
    int num;

    assert (prefix->family == AF_INET);

    if (metric < 1 || metric >= DVMRP_UNREACHABLE * 2) {
	trace (TR_PACKET, DVMRP->trace,
		"  x %p metric %d + %d (invalid metric)\n",
		prefix, metric, vif->metric_in);
	return (-1);
    }

    assert (vif);

    /* check distribute-list for in */
    if ((num = vif->dlist_in) >= 0) {
        if (apply_access_list (num, prefix) == 0) {
	    trace (TR_PACKET, DVMRP->trace,
	           "  x %p metric %d + %d (a-list %d)\n",
	           prefix, metric, vif->metric_in, num);
	    return (-1);
        }
    }
    metric = metric + vif->metric_in;
    if (metric > DVMRP_UNREACHABLE)
        metric = DVMRP_UNREACHABLE;
    return (metric);
}


static int
dvmrp_policy_out (prefix_t * prefix, int metric, dvmrp_interface_t *vif,
		  dvmrp_interface_t *out)
{
    int num, ajusted_metric;

    assert (vif);
    assert (out);

    ajusted_metric = metric + out->metric_out;
    if (ajusted_metric > DVMRP_UNREACHABLE)
        ajusted_metric = DVMRP_UNREACHABLE;

    if (metric == 0 /* directly connected */ && vif == out) {
	trace (TR_PACKET, DVMRP->trace,
		"  x %p metric %d + %d (direct)\n", prefix, metric,
		out->metric_out);
	return (-1);
    }

    /* split horizon w/ poisoned reverse */
    if (vif == out && ajusted_metric != DVMRP_UNREACHABLE) {
	trace (TR_PACKET, DVMRP->trace,
		"  o %p metric %d + %d (poisoned reverse)\n",
		prefix, ajusted_metric, DVMRP_UNREACHABLE);
	ajusted_metric += DVMRP_UNREACHABLE;
	return (ajusted_metric);
    }

    /* check distribute-list for out */
    if ((num = out->dlist_out) >= 0) {
	if (apply_access_list (num, prefix) == 0) {
	    trace (TR_PACKET, DVMRP->trace,
		   "  x %p metric %d + %d (a-list %d)\n",
		   prefix, metric, out->metric_out, num);
	    return (-1);
	}
    }
    trace (TR_PACKET, DVMRP->trace,
	   "  o %p metric %d + %d\n",
	    prefix, metric, out->metric_out);
    return (ajusted_metric);
}


/* 
 * contiguous check
 */
int
inet_valid_mask (u_char *mask)
{
    u_long lmask = ntohl (*(u_long *)mask);
    
    return (~(((lmask & -lmask) - 1) | lmask) == 0);
} 


static dvmrp_route_t *
dvmrp_new_route (int proto, prefix_t *prefix, interface_t *interface, 
		 dvmrp_neighbor_t *neighbor, int metric)
{
    dvmrp_route_t *route;

    route = New (dvmrp_route_t);
    route->proto = proto;
    route->prefix = Ref_Prefix (prefix);
    route->metric = metric & 0x7f;
    route->interface = interface;
    route->neighbor = neighbor;
    if (neighbor && interface) {
	assert (interface == neighbor->interface);
    }
    route->flags |= DVMRP_RT_CHANGE;
    DVMRP->changed++;
    return (route);
}


static void
dvmrp_del_route (dvmrp_route_t *route)
{
    Deref_Prefix (route->prefix);
    Delete (route);
}


static void
dvmrp_set_flash_timer (void)
{
    time_t now, t = 0;

    if (DVMRP->flash_update_waiting) {
        trace (TR_TRACE, DVMRP->trace, "flash timer already running\n");
        return;
    }
    time (&now);
#define DVMRP_FLASH_INTERVAL 5
#define DVMRP_FLASH_DELAY_MIN 1
#define DVMRP_FLASH_DELAY_MAX 5
    if (DVMRP->update_last_run != 0 &&
	(now - DVMRP->update_last_run < DVMRP_FLASH_INTERVAL))
	t = DVMRP_FLASH_INTERVAL;
    t = t + DVMRP_FLASH_DELAY_MIN +
        rand () % (DVMRP_FLASH_DELAY_MAX - DVMRP_FLASH_DELAY_MIN + 1);
    Timer_Set_Time (DVMRP->flash, t);
    Timer_Turn_ON (DVMRP->flash);
    DVMRP->flash_update_waiting++;
}


static void
dvmrp_timeout_routes (void)
{
    time_t now, t;
    time_t nexttime = 0;
    LINKED_LIST *deletes = NULL;
    radix_node_t *node;

    trace (TR_TRACE, DVMRP->trace, "timer (age) fired\n");

    time (&now);
    nexttime = now + DVMRP_TIMEOUT_INTERVAL;

    RADIX_WALK (DVMRP->radix->head, node) {
	dvmrp_route_t *route = RADIX_DATA_GET (node, dvmrp_route_t);
        /* garbage collect and delete route */
        if (BIT_TEST (route->flags, DVMRP_RT_DELETE)) {
            if (now - route->dtime >= DVMRP_GARBAGE_INTERVAL) {
                trace (TR_TRACE, DVMRP->trace,
                       "deleted %p neighbor %a (garbage collection)\n",
                       route->prefix, route->neighbor->prefix);
		/* XXX DELETE */
	        if (deletes == NULL)
		    deletes = LL_Create (0);
		LL_Add (deletes, node);
            }
            else {
                if ((t = route->dtime + DVMRP_GARBAGE_INTERVAL)
                        < nexttime)
                    nexttime = t;
            }
	}
        /* timeout route -- set metric to 16 and set change flag */
        else if (route->utime > 0 /* timeout is on */ &&
                now - route->utime >= DVMRP_TIMEOUT_INTERVAL) {

            trace (TR_TRACE, DVMRP->trace,
                   "timing out %p neighbor %a (shift to delete)\n",
                   route->prefix, route->neighbor->prefix);
            route->dtime = now;
	    /* keep metric */
            route->flags |= DVMRP_RT_DELETE;
            route->flags |= DVMRP_RT_CHANGE;
            DVMRP->changed++;
            if ((t = route->dtime + DVMRP_GARBAGE_INTERVAL) < nexttime) {
                nexttime = t;
            }
	}
    } RADIX_WALK_END;

    if (deletes) {
        LL_Iterate (deletes, node) {
	    dvmrp_route_t *route = RADIX_DATA_GET (node, dvmrp_route_t);
	    radix_remove (DVMRP->radix, node);
	    dvmrp_del_route (route);
        }
        LL_Destroy (deletes);
    }

    if (DVMRP->changed)
        dvmrp_set_flash_timer ();

#define DVMRP_MIN_TIMEOUT_INTERVAL 5
    if ((t = nexttime - time (NULL)) <= 0)
        t = DVMRP_MIN_TIMEOUT_INTERVAL;   /* don't want so strict? */
    Timer_Set_Time (DVMRP->age, t);
    Timer_Turn_ON (DVMRP->age);
}


#define DVMRP_UNREACHABLE 32

static int
dvmrp_update_route (prefix_t *prefix, int metric,
		    dvmrp_neighbor_t *nbr, time_t now)
{
    dvmrp_interface_t *vif;
    interface_t *interface;
    int metric_in;
    int adjusted_metric;
    dvmrp_route_t *route;
    radix_node_t *node;

    assert ((metric & 0x80) == 0);
    assert (nbr);

    interface = nbr->interface;
    assert (interface);
    /* assert (interface->vif_index >= 0); */
    vif = DVMRP->dvmrp_interfaces[interface->index];
    assert (vif);
    metric_in = vif->metric_in;

    if ((adjusted_metric = dvmrp_policy_in (prefix, metric, vif)) < 0)
	return (-1);

    adjusted_metric = metric + metric_in;
    if (adjusted_metric > DVMRP_UNREACHABLE)
	adjusted_metric = DVMRP_UNREACHABLE;

    node = radix_lookup (DVMRP->radix, prefix);
    route = RADIX_DATA_GET (node, dvmrp_route_t);

    if (route == NULL) {
	if (adjusted_metric >= DVMRP_UNREACHABLE) {
            trace (TR_PACKET, DVMRP->trace,
                   "  x %p metric %d + %d (infinity)\n",
                   prefix, metric, metric_in);
	    radix_remove (DVMRP->radix, node);
	    return (0);
	}
	route = dvmrp_new_route (PROTO_DVMRP, prefix, interface, 
				  nbr, adjusted_metric);
	route->ctime = route->utime = now;
	RADIX_DATA_SET (node, route);
        trace (TR_PACKET, DVMRP->trace,
               "  o %p metric %d + %d (new)\n",
               prefix, metric, metric_in);
	return (1);
    }

    /* dependencies check */
    if (metric <= DVMRP_UNREACHABLE) {
	BITX_RESET (&route->dependents, nbr->index);
    }
    else {
	BITX_SET (&route->dependents, nbr->index);
    }

    if (route->metric >= DVMRP_UNREACHABLE) {
	if (adjusted_metric >= DVMRP_UNREACHABLE) {
            trace (TR_PACKET, DVMRP->trace,
                   "  x %p metric %d + %d (infinity)\n",
                   prefix, metric, metric_in);
	    return (0);
	}
        trace (TR_PACKET, DVMRP->trace,
               "  o %p metric %d + %d (recover from hold)\n",
               prefix, metric, metric_in);
	route->metric = adjusted_metric;
	route->flags &= ~DVMRP_RT_DELETE;
	route->flags |= DVMRP_RT_CHANGE;
	route->neighbor = nbr;
	route->interface = interface;
	route->utime = now;
	DVMRP->changed++;
	return (1);
    }
    else if (route->neighbor == nbr) {

	assert (route->interface == nbr->interface);
	/* update time anyway */
	route->utime = now;

	if (route->metric == adjusted_metric) {
            trace (TR_PACKET, DVMRP->trace,
                   "  o %p metric %d + %d (update)\n",
                   prefix, metric, metric_in);
	    return (0);
	}
	if (adjusted_metric >= DVMRP_UNREACHABLE) {
	    route->flags |= DVMRP_RT_DELETE;
            trace (TR_PACKET, DVMRP->trace,
                   "  o %p metric %d + %d (shift to hold)\n",
                   prefix, route->metric, metric_in);
	}
	else {
            trace (TR_PACKET, DVMRP->trace,
                   "  o %p metric %d + %d (change from %d)\n",
                   prefix, route->metric, metric_in, route->metric);
	}
	route->flags |= DVMRP_RT_CHANGE;
	route->metric = adjusted_metric;
	DVMRP->changed++;
	return (1);
    }
#define DVMRP_TIMEOUT_INTERVAL 200
    else if (route->metric > adjusted_metric ||
		(route->metric == adjusted_metric &&
		 route->utime > 0 &&
		 (now - route->utime) >= DVMRP_ROUTE_SWITCH_TIME)) {
	route->flags |= DVMRP_RT_CHANGE;
	route->metric = adjusted_metric;
	route->neighbor = nbr;
	route->interface = interface;
	route->utime = now;
	DVMRP->changed++;
        trace (TR_PACKET, DVMRP->trace,
               "  o %p metric %d + %d (change from %d)\n",
               prefix, route->metric, metric_in, route->metric);
	return (1);
    }
    else {
        trace (TR_PACKET, DVMRP->trace,
               "  x %p metric %d + %d (current %d)\n",
               prefix, route->metric, metric_in, route->metric);
	return (0);
    }
    return (0);
}


static int
dvmrp_process_report (LINKED_LIST *ll_dvmrp_report)
{
    dvmrp_report_t *dvmrp_report;
    int n = 0;
    time_t now;

    time (&now);
    LL_Iterate (ll_dvmrp_report, dvmrp_report) {
	n += dvmrp_update_route (dvmrp_report->prefix, dvmrp_report->metric,
                    dvmrp_report->neighbor, now);
    }
    if (n > 0) {
	assert (DVMRP->changed);
	dvmrp_set_flash_timer ();
    }
    return (n);
}


static void
dvmrp_delete_report (dvmrp_report_t *report)
{
    Deref_Prefix (report->prefix);
    Delete (report);
}


static void
dvmrp_recv_report (interface_t *interface, 
	      u_long level, prefix_t *source, u_char *data, int datalen)
{
    u_char *endp = data + datalen;
    dvmrp_neighbor_t *nbr;
    LINKED_LIST *ll_dvmrp_report = NULL;

#ifdef notdef
    if (/* interface->vif_index < 0 || */
	    !BITX_TEST (&DVMRP->interface_mask, interface->index)) {
        trace (TR_WARN, DVMRP->trace,
               "report from %a on disabled interface %s\n",                     
               source, interface->name);         
        return;
    }
#endif /* notdef */

    nbr = dvmrp_lookup_neighbor (interface, level, source);
    if (nbr == NULL) {
	trace (TR_PACKET, DVMRP->trace, 
	       "unknown neighbor %a on %s\n", source, interface->name);
	return;
    }

    while (endp - data > 0) {
	u_char mask[4];
	int prefixlen, bytes;
        dvmrp_report_t *dvmrp_report;
	int metric;

	if (endp - data < 3) {
	    trace (TR_ERROR, DVMRP->trace, 
	           "truncated route report from %a on %s\n",
	           source, interface->name);
	    break;
	}
	mask[0] = 0xff;
	MRT_GET_BYTE (mask[1], data);
	MRT_GET_BYTE (mask[2], data);
	MRT_GET_BYTE (mask[3], data);
	if (!inet_valid_mask (mask)) {
	    trace (TR_ERROR, DVMRP->trace, 
	           "non-contiguous route mask 0x%x from %a on %s\n",
	           ntohl (*(u_long *)mask), source, interface->name);
	}
	prefixlen = mask2len (mask, 4);
	bytes = (prefixlen + 7) / 8;

	do {
	    prefix_t *prefix;
	    u_char origin[4];
	    int i;

	    if (endp - data < bytes + 1) {
	        trace (TR_ERROR, DVMRP->trace, 
	               "truncated route report from %a on %s\n",
	               source, interface->name);
	        goto finish;
	    }
	    memset (origin, 0, sizeof (origin));
	    for (i = 0; i < bytes; i++)
	        MRT_GET_BYTE (origin[i], data);
	    MRT_GET_BYTE (metric, data);
	    if (* (u_long *) origin == 0L && prefixlen == 8) {
		/* special case for default route */
		prefixlen = 0;
	    }
	    prefix = New_Prefix (AF_INET, origin, prefixlen);
	    trace (TR_PACKET, DVMRP->trace, 
	           "route %p metric %d from %a on %s\n", prefix,
	           metric & 0x7f, source, interface->name);
	    if (ll_dvmrp_report == NULL)
		ll_dvmrp_report = LL_Create (LL_DestroyFunction, 
					    dvmrp_delete_report, 0);
	    dvmrp_report = New (dvmrp_report_t);
	    dvmrp_report->prefix = prefix;
	    dvmrp_report->metric = metric & 0x7f;
	    dvmrp_report->neighbor = nbr;
	    LL_Add (ll_dvmrp_report, dvmrp_report);
	} while (!(metric & 0x80));
    }
finish:
    if (ll_dvmrp_report) {
        dvmrp_process_report (ll_dvmrp_report);
	LL_Destroy (ll_dvmrp_report);
    }
}


static void
dvmrp_neighbors2 (interface_t *from_if, prefix_t *from)
{
    u_char sendbuf[MAX_DVMRP_DATA_LEN];
    u_char *cp = sendbuf;
    dvmrp_interface_t *vif;

    LL_Iterate (DVMRP->ll_dvmrp_interfaces, vif) {
	u_long flags;
        u_char *num_p = NULL;
        dvmrp_neighbor_t *nbr;
	prefix_t *prefix;
        interface_t *interface = vif->interface;
        int count = 0;

	/* assert (interface->vif_index >= 0); */
	flags = vif->flags;
	if (igmp_is_querier (IGMP, interface))
	    flags |= DVMRP_VIF_QUERIER;
	if (BIT_TEST (interface->flags, IFF_VIF_TUNNEL))
	    flags |= DVMRP_VIF_TUNNEL;
	if (!BIT_TEST (interface->flags, IFF_UP))
	    flags |= DVMRP_VIF_DOWN;

	if (BIT_TEST (interface->flags, IFF_VIF_TUNNEL))
	    prefix = interface->tunnel_source;
	else
	    prefix = interface->primary->prefix;
	assert (prefix);
	assert (prefix->family == AF_INET);

	LL_Iterate (vif->ll_neighbors, nbr) {
	    if (nbr->ctime != 0)
		count++;
	}
	if (count == 0) {
	    /* no neighbors */
	    if (BIT_TEST (interface->flags, IFF_VIF_TUNNEL))
		flags |= DVMRP_VIF_DOWN;
	    if (cp - sendbuf > MAX_DVMRP_DATA_LEN - 12) {
    	        dvmrp_send (DVMRP_NEIGHBORS2, from, 
			    sendbuf, cp - sendbuf, from_if);
                cp = sendbuf;
	    }
	    MRT_PUT_NETLONG (prefix_tolong (prefix), cp);
	    MRT_PUT_BYTE (vif->metric_in, cp);
	    MRT_PUT_BYTE (interface->threshold, cp);
	    MRT_PUT_BYTE (flags, cp);
	    MRT_PUT_BYTE (1, cp); /* number of neighbors */
	    if (BIT_TEST (interface->flags, IFF_VIF_TUNNEL))
	        MRT_PUT_NETLONG (prefix_tolong (interface->tunnel_destination),
				 cp);
	    else
	        MRT_PUT_NETLONG (0L, cp);
	}
	else LL_Iterate (vif->ll_neighbors, nbr) {
	    if (cp - sendbuf > MAX_DVMRP_DATA_LEN - 12) {
    	        dvmrp_send (DVMRP_NEIGHBORS2, from, 
			    sendbuf, cp - sendbuf, from_if);
                cp = sendbuf;
		num_p = NULL;
	    }
	    if (num_p == NULL) {
	        MRT_PUT_NETLONG (prefix_tolong (prefix), cp);
	        MRT_PUT_BYTE (vif->metric_in, cp);
	        MRT_PUT_BYTE (interface->threshold, cp);
	        MRT_PUT_BYTE (flags, cp);
		num_p = cp;
	        MRT_PUT_BYTE (0, cp); /* number of neighbors */
	    }
	    assert (nbr->prefix);
	    assert (nbr->prefix->family == AF_INET);
	    MRT_PUT_NETLONG (prefix_tolong (nbr->prefix), cp);
	    (*num_p)++;
	}
    }
    if (cp - sendbuf > 0) {
        dvmrp_send (DVMRP_NEIGHBORS2, from, 
		    sendbuf, cp - sendbuf, from_if);
    }
}


int
recv_dvmrp (interface_t *interface, u_long level, prefix_t *source, 
	    int igmp_code, u_char *data, int datalen)
{
    u_char *data_end = data + datalen;
    u_char sendbuf[DVMRP_MAX_PDU];
    u_char *cp = sendbuf;
    int major = level & 0xff;
    int minor = (level >> 8) & 0xff;

#ifdef notdef
    if (interface->vif_index < 0 ||
	    !BITX_TEST (&DVMRP->interface_mask, interface->index)) {
        trace (TR_WARN, DVMRP->trace,
               "packet from %a on disabled interface %s\n",                     
               source, interface->name);         
        return (0);
    }
#endif /* notdef */

    if (igmp_code <= 0 || igmp_code > DVMRP_INFO_REPLY) {
	trace (TR_WARN, DVMRP->trace,
	       "unsupported message [type %d] from %a on %s, ignore!\n",
	       igmp_code, source, interface->name);
	return (0);
    }

    trace (TR_PACKET, DVMRP->trace,
	   "recv [%s] %d bytes from %a on %s\n", s_dvmrp[igmp_code],
	   datalen, source, interface->name);

    if (major == 10 || major == 11 || major < 3 || (major == 3 &&
	minor < 5)) {
	trace (TR_WARN, DVMRP->trace,
	       "Too old mrouted version (major %d, minor %d) "
	       "from %a on %s, ignore!\n",
	       major, minor,
	       source, interface->name);
	return (0);
    }

    switch (igmp_code) {
    case DVMRP_PROBE:
	dvmrp_recv_probe (interface, level, source, data, datalen);
	break;
    case DVMRP_REPORT:
	dvmrp_recv_report (interface, level, source, data, datalen);
	break;
    case DVMRP_ASK_NEIGHBORS:
    case DVMRP_NEIGHBORS:   
	break;
    case DVMRP_ASK_NEIGHBORS2:
	dvmrp_neighbors2 (interface, source);
	break;
    case DVMRP_NEIGHBORS2:
	break;
    case DVMRP_PRUNE:    
	dvmrp_recv_prune (interface, level, source, data, datalen);
	break;
    case DVMRP_GRAFT:   
    case DVMRP_GRAFT_ACK:
	break;
    case DVMRP_INFO_REQUEST:
	while (data + 4 < data_end) {
	    if (*data == DVMRP_INFO_VERSION) {
		int len = strlen (MRT->version);

		len = ((len + 3) / 4) * 4;
		memset (cp, 0, len);
		*cp++ = DVMRP_INFO_VERSION;
		*cp++ = len; 
		*cp++ = 0;
		*cp++ = 0;
		strcpy ((char *)cp, MRT->version);
		cp += len;
	    }
	    else  {
		trace (TR_PACKET, DVMRP->trace, 
		       "ignoring unknown info type %d", *data);
	    }
	    data += (4 + data[1] * 4);
	}
	if (cp > sendbuf) {
	    dvmrp_send (DVMRP_INFO_REPLY, source, 
		        sendbuf, cp - sendbuf, interface);
	}
	break;
    case DVMRP_INFO_REPLY: 
    default:
	break;
    }
    return (1);
}


static int
dvmrp_mask_comp (dvmrp_ann_rt_t *a, dvmrp_ann_rt_t *b)
{
    return (a->prefix->bitlen - b->prefix->bitlen);
}


static int
dvmrp_send_routes (LINKED_LIST *ll_dvmrp_ann_rt, dvmrp_interface_t *vif)
{
    u_char sendbuf[MAX_DVMRP_DATA_LEN];
    u_char *cp = sendbuf;
    dvmrp_ann_rt_t *ann_rt;
    int count = 0;
    int bitlen = -1;

    assert (ll_dvmrp_ann_rt);
    assert (vif);

    LL_SortFn (ll_dvmrp_ann_rt, (LL_CompareProc) dvmrp_mask_comp);

    LL_Iterate (ll_dvmrp_ann_rt, ann_rt) {
	int bytes = (ann_rt->prefix->bitlen + 7) / 8;
	u_char *addr = prefix_touchar (ann_rt->prefix);
        int i;

	if (cp - sendbuf + ((bitlen == ann_rt->prefix->bitlen)?
				(bytes + 1): (3 + bytes + 1))
		>= MAX_DVMRP_DATA_LEN) {
	    *(cp - 1) |= 0x80;
	    dvmrp_send (DVMRP_REPORT, NULL, 
		        sendbuf, cp - sendbuf, vif->interface);
	    cp = sendbuf;
	    bitlen = -1;
	}
	if (bitlen != ann_rt->prefix->bitlen) {
	    u_char mask[4];
	    bitlen = ann_rt->prefix->bitlen;
	    if (cp != sendbuf)
		*(cp - 1) |= 0x80;
	    assert (ann_rt->prefix->bitlen <= 32);
	    len2mask (ann_rt->prefix->bitlen, &mask, sizeof (mask));
	    assert (ann_rt->prefix->bitlen == 0 || mask[0] == 0xff);
	    MRT_PUT_BYTE (mask[1], cp);
	    MRT_PUT_BYTE (mask[2], cp);
	    MRT_PUT_BYTE (mask[3], cp);
	}
	for (i = 0; i < bytes; i++)
	    MRT_PUT_BYTE (addr[i], cp);
	if (ann_rt->metric == 0)
	    MRT_PUT_BYTE (1, cp); /* direct */
	else
	    MRT_PUT_BYTE (ann_rt->metric, cp);
	count++;
    }
    if (cp - sendbuf > 0) {
	*(cp - 1) |= 0x80;
	dvmrp_send (DVMRP_REPORT, NULL, 
		    sendbuf, cp - sendbuf, vif->interface);
    }
    return (count);
}



/* if vif == NULL, no policy will be applied */
static void
dvmrp_prepare_routes (int all, dvmrp_interface_t *vif, 
		      LINKED_LIST **ll_dvmrp_ann_rt_p)
{
    radix_node_t *node;
    LINKED_LIST *ll_dvmrp_ann_rt = NULL;

    RADIX_WALK (DVMRP->radix->head, node) {
	dvmrp_route_t *route = RADIX_DATA_GET (node, dvmrp_route_t);
	int metric = route->metric;

	prefix_t *prefix = route->prefix;
	dvmrp_ann_rt_t *dvmrp_ann_rt;

	/* doing ouput processing and only sending changed routes */
	if (!all && !BIT_TEST (route->flags, DVMRP_RT_CHANGE))
	    goto skip;

	/* skip dummy route */
	if (route->interface == NULL && route->neighbor == NULL)
	    goto skip;

	if (vif) {
	    dvmrp_interface_t *neighbor_vif;
	    assert (route->interface);
	    neighbor_vif = DVMRP->dvmrp_interfaces[route->interface->index];
	    if ((metric = dvmrp_policy_out (prefix, route->metric, 
						neighbor_vif, vif)) < 0)
	    	goto skip;
	}
	else {
            trace (TR_PACKET, DVMRP->trace,
                   "  o %p metric %d + %d\n",
                   prefix, route->metric, vif->metric_out);
	}

	if (ll_dvmrp_ann_rt == NULL)
	    ll_dvmrp_ann_rt = LL_Create (LL_DestroyFunction, FDelete, 0);
	dvmrp_ann_rt = New (dvmrp_ann_rt_t);
	dvmrp_ann_rt->prefix = prefix;
	dvmrp_ann_rt->metric = metric;
	LL_Add (ll_dvmrp_ann_rt, dvmrp_ann_rt);
skip:
	do {} while (0);
    } RADIX_WALK_END;
    *ll_dvmrp_ann_rt_p = ll_dvmrp_ann_rt;
}


void
dvmrp_advertise_route (int all)
{
    dvmrp_interface_t *vif;
    radix_node_t *node;

    /* nothing changed */
    if (!DVMRP->changed && !all)
	return;

    /* announce routes */
    LL_Iterate (DVMRP->ll_dvmrp_interfaces, vif) {
        LINKED_LIST *ll_dvmrp_ann_rt;

	assert (BITX_TEST (&DVMRP->interface_mask, vif->interface->index));
	if (!BIT_TEST (vif->interface->flags, IFF_UP))
	    continue;
	if (BIT_TEST (vif->flags, DVMRP_VIF_LEAF))
	    continue;

	dvmrp_prepare_routes (all, vif, &ll_dvmrp_ann_rt);
	if (ll_dvmrp_ann_rt) {
 	    dvmrp_send_routes (ll_dvmrp_ann_rt, vif);
	    LL_Destroy (ll_dvmrp_ann_rt);
	}
    }

    RADIX_WALK (DVMRP->radix->head, node) {
	dvmrp_route_t *route = RADIX_DATA_GET (node, dvmrp_route_t);
        /* clearing change flag */
	route->flags &= ~(DVMRP_RT_CHANGE);
    } RADIX_WALK_END;
    DVMRP->changed = 0;
}


static void
dvmrp_timer_update (void)
{
    trace (TR_TRACE, DVMRP->trace, "timer (update) fired\n");
    if (DVMRP->flash_update_waiting)
        DVMRP->flash_update_waiting = 0;  /* clear flash update */
    dvmrp_advertise_route (TRUE);
    time (&DVMRP->update_last_run);
}


static void
dvmrp_timer_probe (void)
{
    dvmrp_interface_t *vif;

    trace (TR_TRACE, DVMRP->trace, "timer (probe) fired\n");
    LL_Iterate (DVMRP->ll_dvmrp_interfaces, vif) {
	if (!BITX_TEST (&DVMRP->force_leaf_mask, vif->interface->index))
	    dvmrp_send_probe (vif, NULL);
    }
}


static void
dvmrp_flash_update (void)
{
    trace (TR_TRACE, DVMRP->trace, "timer (flash update) fired\n");
    if (DVMRP->flash_update_waiting) {
        DVMRP->flash_update_waiting = 0;
        dvmrp_advertise_route (FALSE);
	time (&DVMRP->update_last_run);
    }
}



static int
dvmrp_update_call_fn (int code, cache_t *cache, cache_entry_t *entry)
{
    dvmrp_interface_t *vif;
    radix_node_t *node;
    dvmrp_route_t *route;
    int prune = 1;
    time_t now;

    time (&now);
    switch (code) {
    case MRTMSG_NOCACHE:

	node = radix_search_best (DVMRP->radix, entry->source);
	assert (node != NULL);
	/* we have default so that must match */
    	route = RADIX_DATA_GET (node, dvmrp_route_t);
	assert (route);

	if (route->proto == PROTO_DVMRP && route->neighbor == NULL) {
	    /* this is the special route to trap all others */
            trace (TR_WARN, DVMRP->trace,
                   "no route found (source %a group %a)\n",
                    entry->source, entry->group);
            entry->parent = NULL;
            return (-1);
        }

	assert (route->interface);
	entry->parent = route->interface;
	trace (TR_TRACE, DVMRP->trace,
               "found %p proto %s parent %s for source %a group %a\n",
                route->prefix, proto2string (route->proto), 
		entry->parent->name, entry->source, entry->group);

        LL_Iterate (DVMRP->ll_dvmrp_interfaces, vif) {
            if (vif->interface == route->interface)
                continue;
            if (vif->flags & DVMRP_VIF_LEAF) {
                if (igmp_test_membership (entry->group, vif->interface)) {
                    BITX_SET (&entry->children, vif->interface->index);
                    prune = 0;
                }
            }
            else {
                BITX_SET (&entry->children, vif->interface->index);
                prune = 0;
            }
        }
	/* excepting a direct connected source */
        if (prune && route->neighbor) {
	    entry->holdtime = PRUNE_REXMIT_VAL << entry->count;
            entry->count++;
	    dvmrp_send_prune (entry->source, entry->group, 
		  AVERAGE_PRUNE_LIFETIME /* XXX */, route->neighbor);
        }
        else {
            entry->holdtime = DEFAULT_CACHE_LIFETIME;
	}
	entry->data = route;
	return (1);

    case MRTMSG_EXPIRE:
	break;
    case MRTMSG_WRONGIF:
        break;
    default:
	assert (0);
	break;
    }
    return (0);
}


/*
 * initialize dvmrp stuff
 */
int
dvmrp_init (trace_t * tr)
{
    char *name = "DVMRP";
    char *dvmrp_all_routers = "224.0.0.4";

    assert (DVMRP == NULL);
    DVMRP = New (dvmrp_t);
    DVMRP->trace = trace_copy (tr);
    DVMRP->proto = PROTO_DVMRP;
    DVMRP->level = DVMRP_CAPABILITY_FLAGS << 16 |
                          DVMRP_MINOR_VERSION << 8 |
                          DVMRP_MAJOR_VERSION;
    DVMRP->all_routers = ascii2prefix (AF_INET, dvmrp_all_routers);
    set_trace (DVMRP->trace, TRACE_PREPEND_STRING, name, 0);
    /* DVMRP->schedule = New_Schedule (name, DVMRP->trace); */
    DVMRP->ll_networks = LL_Create (LL_DestroyFunction, Deref_Prefix, 0);
    DVMRP->ll_networks2 = LL_Create (LL_DestroyFunction, FDelete, 0);
    DVMRP->ll_leafs = LL_Create (LL_DestroyFunction, FDelete, 0);
    DVMRP->ll_dlists = LL_Create (LL_DestroyFunction, FDelete, 0);
    DVMRP->ll_dvmrp_interfaces = LL_Create (0);
    memset (&DVMRP->interface_mask, 0, sizeof (DVMRP->interface_mask));
    DVMRP->radix = New_Radix (32);
    /* share the schedule with IGMP */
    DVMRP->schedule = IGMP->schedule;

    DVMRP->timer = New_Timer2 ("DVMRP update timer", DVMRP_UPDATE_INTERVAL, 0,
                               DVMRP->schedule, dvmrp_timer_update, 0);
    timer_set_jitter2 (DVMRP->timer, -50, 50);
    DVMRP->age = New_Timer2 ("DVMRP aging timer", DVMRP_TIMEOUT_INTERVAL,
                             TIMER_ONE_SHOT, DVMRP->schedule,
                             dvmrp_timeout_routes, 0);
    DVMRP->flash = New_Timer2 ("DVMRP flash timer", 0, TIMER_ONE_SHOT,
                               DVMRP->schedule, dvmrp_flash_update, 0);
#define DVMRP_PRUNE_TIMEOUT_INTERVAL 10
    DVMRP->expire = New_Timer2 ("DVMRP prune expiration timer", 
			       DVMRP_PRUNE_TIMEOUT_INTERVAL, 0,
                               DVMRP->schedule, dvmrp_prune_expire, 0);
    return (1);
}


static void
dvmrp_inject_direct_route (dvmrp_interface_t *vif)
{
    time_t now;
    ll_addr_t *ll_addr;
    interface_t *interface = vif->interface;
    dvmrp_neighbor_t *nbr = NULL;

    time (&now);

    if (interface->ll_addr == NULL)
	return;
    if (!BIT_TEST (interface->flags, IFF_UP))
	return;
    if (BIT_TEST (interface->flags, IFF_VIF_TUNNEL))
	return;
    if (BIT_TEST (interface->flags, IFF_LOOPBACK))
	return;

#ifdef notdef
    local_prefix = ascii2prefix (AF_INET, "127.0.0.1");
    nbr = dvmrp_register_neighbor (vif, DVMRP->level, 0,
				   Ref_Prefix (local_prefix));
#endif /* notdef */

    LL_Iterate (interface->ll_addr, ll_addr) {
	dvmrp_route_t *route;
	radix_node_t *node;
	prefix_t *network;
	prefix_t *pointopoint = NULL;
	int pplen = 32;

	    if (ll_addr->prefix == NULL)
		continue;

	    network = ll_addr->prefix;
	    if (BIT_TEST (interface->flags, IFF_POINTOPOINT))
		pointopoint = ll_addr->broadcast;

	    if (network->family == AF_INET) {
	        /* create new one for masking */
	        network = New_Prefix (network->family, prefix_tochar (network),
				  BIT_TEST (interface->flags, IFF_POINTOPOINT)?
					pplen: network->bitlen);
	        /* masking may not be needed */
	        netmasking (network->family, prefix_tochar (network),
			    network->bitlen);

    		route = dvmrp_new_route (PROTO_CONNECTED, network, interface, nbr, 0);
    		route->ctime = now;
    		route->utime = 0; /* timeout off */
    		node = radix_lookup (DVMRP->radix, network);
    		RADIX_DATA_SET (node, route);

	        trace (TR_INFO, DVMRP->trace, "interface route %p for %s\n",
		       network, interface->name);
	        Deref_Prefix (network);
	    }

	    if (pointopoint && pointopoint->family == AF_INET) {
		/* create new one for masking */
		pointopoint = New_Prefix (pointopoint->family,
					  prefix_tochar (pointopoint),
					  pplen);
		/* masking may not be needed */
		netmasking (pointopoint->family, prefix_tochar (pointopoint),
			    pointopoint->bitlen);

    		route = dvmrp_new_route (PROTO_CONNECTED, pointopoint, interface, nbr, 0);
    		route->ctime = now;
    		route->utime = 0; /* timeout off */
    		node = radix_lookup (DVMRP->radix, pointopoint);
    		RADIX_DATA_SET (node, route);

	        trace (TR_INFO, DVMRP->trace, "interface route %p for %s\n",
		       pointopoint, interface->name);
		Deref_Prefix (pointopoint);
	    }
    }
#ifdef notdef
    Deref_Prefix (local_prefix);
#endif /* notdef */
}


void
dvmrp_start (void)
{
    interface_t *interface;
    dvmrp_route_t *route;
    radix_node_t *node;
    prefix_t *default_prefix = ascii2prefix (AF_INET, "0.0.0.0/0");

    DVMRP->genid = time (0);
    IGMP->recv_dvmrp_call_fn = recv_dvmrp;
    if (CACHE == NULL) {
	cache_init (AF_INET, IGMP->trace);
    }
    CACHE->update_call_fn = dvmrp_update_call_fn;
    Timer_Turn_ON (DVMRP->timer);
    Timer_Turn_ON (DVMRP->age);
    Timer_Turn_ON (DVMRP->expire);

    /* copy all interfaces at this point, so all new interfaces created later
       by the kernel should be entered individually into ll_dvmrp_interfaces 
       structure */
    LL_Iterate (INTERFACE_MASTER->ll_interfaces, interface) {
	dvmrp_interface_t *vif;

	vif = New (dvmrp_interface_t);
	vif->interface = interface;
	vif->ll_neighbors = LL_Create (LL_DestroyFunction, 
				       dvmrp_delete_neighbor, 0);
	vif->flags = 0;
	vif->metric_in = 1;
	vif->metric_out = 0;
        vif->dlist_in = -1;
        vif->dlist_out = -1;
        vif->flags |= DVMRP_VIF_LEAF;
	DVMRP->dvmrp_interfaces[interface->index] = vif;
    }

    route = dvmrp_new_route (PROTO_DVMRP, default_prefix, NULL, NULL, DVMRP_UNREACHABLE);
    time (&route->ctime);
    route->utime = 0; /* timeout off */
    node = radix_lookup (DVMRP->radix, default_prefix);
    RADIX_DATA_SET (node, route);
    Deref_Prefix (default_prefix);
}


void
dvmrp_stop (void)
{
    int i;

    Timer_Turn_OFF (DVMRP->timer);
    Timer_Turn_OFF (DVMRP->age);
    Timer_Turn_OFF (DVMRP->expire);
    IGMP->recv_dvmrp_call_fn = NULL;
    LL_Clear (DVMRP->ll_dvmrp_interfaces);
    /* stop all interfaces */
    LL_Clear (DVMRP->ll_networks);
    LL_Clear (DVMRP->ll_networks2);
    LL_Clear (DVMRP->ll_leafs);
    dvmrp_interface_recheck ();
    LL_Clear (DVMRP->ll_dlists);
    dvmrp_distribute_list_recheck ();
    memset (&DVMRP->interface_mask, 0, sizeof (DVMRP->interface_mask));

    for (i = 0; i < MAX_INTERFACES; i++) {
	dvmrp_interface_t *vif;
	vif = DVMRP->dvmrp_interfaces[i];
	DVMRP->dvmrp_interfaces[i] = NULL;
	LL_Destroy (vif->ll_neighbors);
    	Timer_Turn_OFF (vif->probe);
	Destroy_Timer (vif->probe);
	Delete (vif);
    }
    Clear_Radix (DVMRP->radix, dvmrp_del_route);
}


/*
 * turn on/off the interface
 */
static int
dvmrp_activate_interface (dvmrp_interface_t *vif, int on)
{
    interface_t *interface = vif->interface;

    if (!BIT_TEST (interface->flags, IFF_MULTICAST) &&
        !BIT_TEST (interface->flags, IFF_VIF_TUNNEL)) {
        trace (TR_ERROR, DVMRP->trace,
               "on interface %s ignored due to NBMA\n",
               interface->name);
        return (-1);
    }

    if (on) {
	if (BITX_TEST (&DVMRP->force_leaf_mask, interface->index))
	    on = 2; /* XXX */
        if (igmp_interface (PROTO_IGMP, interface, on) < 0)
	    return (-1);
        if (!BIT_TEST (interface->flags, IFF_VIF_TUNNEL))
	    dvmrp_inject_direct_route (vif);
    }

    /*
     * Join the specified multicast address
     */

    assert (IGMP->sockfd >= 0);
    if (!BITX_TEST (&DVMRP->force_leaf_mask, interface->index)) {
        if (!BIT_TEST (interface->flags, IFF_VIF_TUNNEL))
            join_leave_group (IGMP->sockfd, interface, DVMRP->all_routers, on);
        if (on) {
	    dvmrp_send_probe (vif, NULL);
            vif->flags |= DVMRP_VIF_LEAF;
            vif->probe = New_Timer2 ("DVMRP probe timer", 
			       DVMRP_NEIGHBOR_PROBE_INTERVAL, 0,
                               DVMRP->schedule, (event_fn_t) dvmrp_send_probe, 
			       2, vif, NULL);
            timer_set_jitter2 (vif->probe, -50, 50);
    	    Timer_Turn_ON (vif->probe);
	}
	else {
    	    Timer_Turn_OFF (vif->probe);
	}
    }

    if (!on) {
	/* dvmrp_remove_direct_route (vif); */
        igmp_interface (PROTO_IGMP, interface, on);
    }
    return (0);
}


/* run under DVMRP thread */
/* run for all the interfaces. it is an easier way
   because MRT allows two ways to specify prefix and interface name */
void
dvmrp_interface_recheck (void)
{
    prefix_t *prefix;
    char *name;
    interface_t *table[MAX_INTERFACES];
    LINKED_LIST *ll;
    int i;
    interface_t *interface;
    dvmrp_interface_t *dvmrp_interface;
    
    memset (table, 0, sizeof (table));
    memset (&DVMRP->force_leaf_mask, 0, sizeof (DVMRP->force_leaf_mask));

    LL_Iterate (DVMRP->ll_networks, prefix) {
        if ((ll = find_network (prefix)) != NULL) {
	    LL_Iterate (ll, interface) {
		table[interface->index] = interface;
	    }
	    LL_Destroy (ll);
	}
    }
    LL_Iterate (DVMRP->ll_networks2, name) {
	if ((ll = find_interface_byname_all (name)) != NULL) {
	    LL_Iterate (ll, interface) {
		table[interface->index] = interface;
	    }
	    LL_Destroy (ll);
	}
    }
    LL_Iterate (DVMRP->ll_leafs, name) {
	if ((ll = find_interface_byname_all (name)) != NULL) {
	    LL_Iterate (ll, interface) {
		BITX_SET (&DVMRP->force_leaf_mask, interface->index);
	    }
	    LL_Destroy (ll);
	}
    }

    for (i = 0; i < sizeof (table)/sizeof (table[0]); i++) {
	interface = table[i];
	dvmrp_interface = DVMRP->dvmrp_interfaces[i];
	if (interface == NULL) {
	    if (!BITX_TEST (&DVMRP->interface_mask, i))
		continue;

	    assert (dvmrp_interface);
	    assert (dvmrp_interface->interface->index == i);
	    trace (TR_TRACE, DVMRP->trace, "interface %s (off)\n",
		   interface->name);
            dvmrp_activate_interface (dvmrp_interface, OFF);
	    BITX_RESET (&DVMRP->interface_mask, i);
	    BGP4_BIT_RESET (interface->protocol_mask, PROTO_DVMRP);
	    LL_Remove (DVMRP->ll_dvmrp_interfaces, dvmrp_interface);
	}
	else {
	    assert (interface->index == i);
    	    if (BGP4_BIT_TEST (interface->protocol_mask, PROTO_PIM))
		continue;
	    if (BITX_TEST (&DVMRP->interface_mask, i))
		continue;

            if (dvmrp_activate_interface (dvmrp_interface, ON) < 0)
		continue;
	    trace (TR_TRACE, DVMRP->trace, "interface %s (on)\n",
				       interface->name);
	    BITX_SET (&DVMRP->interface_mask, i);
	    BGP4_BIT_SET (interface->protocol_mask, PROTO_DVMRP);
	    LL_Add (DVMRP->ll_dvmrp_interfaces, dvmrp_interface);
	}
    }
}


void
dvmrp_distribute_list_recheck (void)
{
    dvmrp_interface_t *dvmrp_interface;
    dlist_t *dlist;

    /* check distribute-list */
    /* reset all first */
    LL_Iterate (DVMRP->ll_dvmrp_interfaces, dvmrp_interface) {
	dvmrp_interface->dlist_out = -1;
	dvmrp_interface->dlist_in = -1;
    }

    /* find out distribute-list without interface */
    /* this is default */
    LL_Iterate (DVMRP->ll_dlists, dlist) {
	if (dlist->interface)
	    continue;
        LL_Iterate (DVMRP->ll_dvmrp_interfaces, dvmrp_interface) {
	    if (dlist->out)
		dvmrp_interface->dlist_out = dlist->num;
	    else
		dvmrp_interface->dlist_in = dlist->num;
	}
    }

    LL_Iterate (DVMRP->ll_dlists, dlist) {
	if (dlist->interface == NULL)
	    continue;
	if (!BITX_TEST (&DVMRP->interface_mask, dlist->interface->index))
	    continue;
	dvmrp_interface = DVMRP->dvmrp_interfaces[dlist->interface->index];
	assert (dvmrp_interface);
	if (dlist->out)
	    dvmrp_interface->dlist_out = dlist->num;
	else
	    dvmrp_interface->dlist_in = dlist->num;
	
    }
}


static int
dvmrp_route_compare (dvmrp_route_t * a, dvmrp_route_t * b)
{
    return (prefix_compare2 (a->prefix, b->prefix));
}


/*
 * dump routing table to socket. Usually called by user interactive interface
 */
int
dvmrp_show_routing_table (uii_connection_t * uii, int numopt, char *ifname)
{
    interface_t *interface = NULL;
    time_t now;
    char stmp[MAXLINE];
    int c, t;
    radix_node_t *node;

    if (numopt > 0) {
	interface = find_interface_byname (ifname);
	Delete (ifname);
	if (interface == NULL) {
	    /* can not call uii from dvmrp thread */
/*
	    config_notice (TR_ERROR, uii,
	    		   "no such interface: %s\n", ifname);
*/
	    return (-1);
	}
    }

    if (DVMRP->radix == NULL)
        return (0);

    time (&now);
    sprintf (stmp, "%-4s %-4s", "Cost", "Time");
    rib_show_route_head (uii, stmp);

    RADIX_WALK (DVMRP->radix->head, node) {
	dvmrp_route_t *route = RADIX_DATA_GET (node, dvmrp_route_t);

	if (route->interface == NULL && route->neighbor == NULL)
	    goto skip;

	if (interface == NULL || interface == route->interface) {
		t = 0;

		c = '>';
		if (route->utime > 0)
		    t = now - route->utime;
		if (route->neighbor == NULL) {
		    /* connected */
		    t = 0;
		}
		else if (BIT_TEST (route->flags, DVMRP_RT_DELETE)) {
		    c = 'D';
		    t = now - route->dtime;
		}
	        sprintf (stmp, "%4d %4d", route->metric, t);
	        rib_show_route_line (uii, c, ' ', route->proto,
				     0, now - route->ctime,
				     route->prefix, 
				     (route->neighbor)? route->neighbor->prefix:
					route->interface->primary->prefix,
				     route->interface, stmp);
	}
skip:
	do {} while (0);
    } RADIX_WALK_END;
    return (1);
}


int
dvmrp_show_neighbors (uii_connection_t *uii, int numopt, char *ifname)
{
    dvmrp_interface_t *vif;
    dvmrp_neighbor_t *nbr;
    time_t now;
    interface_t *interface = NULL;

    if (numopt > 0) {
        interface = find_interface_byname (ifname);
        Delete (ifname);
        if (interface == NULL) {
            return (-1);
        }                            
    }                                   

    time (&now);
    uii_add_bulk_output (uii, "%-25s %7s %8s %8s %5s\n",
                "Neighbor Address", "If", "Timeleft", "Holdtime", "Index");
    LL_Iterate (DVMRP->ll_dvmrp_interfaces, vif) {
	char strbuf[64] = "";

	if (interface != NULL && interface != vif->interface)
	    continue;

	if (vif->ll_neighbors == NULL || LL_GetCount (vif->ll_neighbors) == 0)
	    continue;

	if (vif->flags & DVMRP_VIF_LEAF)
	    sprintf (strbuf, " (leaf)");

	LL_Iterate (vif->ll_neighbors, nbr) {
            uii_add_bulk_output (uii, "%-25a %7s %8d %8d %5d%s\n",
		    nbr->prefix, nbr->interface->name,
		    (nbr->timeout)?time_left (nbr->timeout):0,
                    (nbr->timeout)?DVMRP_NEIGHBOR_EXPIRE_TIME:0,
		    nbr->index, strbuf);
	}
    }
    return (1);
}

#endif /* HAVE_MROUTING */
