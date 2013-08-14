/*
 * $Id: cache.c,v 1.1.1.1 2000/08/14 18:46:12 labovit Exp $
 */

#include "mrt.h"
#if defined(HAVE_MROUTING) || defined(HAVE_MROUTING6)
#include "config_file.h"
#include "igmp.h"
#include "dvmrp.h"
#include "pim.h"
#include "cache.h"
/*#include <stdarg.h>*/
/*#include <netinet/in_systm.h>*/
/*#include <netinet/ip.h>*/
/*#include <netinet/igmp.h>*/


#ifdef HAVE_MROUTING
cache_t *CACHE;
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
cache_t *CACHE6;
#endif /* HAVE_MROUTING6 */


static cache_t *
family2cache (int family)
{
    cache_t *cache = NULL;
#ifdef HAVE_MROUTING
    if (family == AF_INET)
        cache = CACHE;
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
    if (family == AF_INET6)
        cache = CACHE6;
#endif /* HAVE_MROUTING6 */
    return (cache);
}


cache_t *
proto2cache (int proto)
{
    cache_t *cache = NULL;
#ifdef HAVE_MROUTING
    if (proto == PROTO_PIM)
        cache = CACHE;
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
    if (proto == PROTO_PIMV6)
        cache = CACHE6;
#endif /* HAVE_MROUTING6 */
    return (cache);
}


cache_entry_t *
cache_lookup (prefix_t *source, prefix_t *group)
{
    cache_entry_t e;
    cache_t *cache = NULL;
    assert (source && group);
#ifdef HAVE_MROUTING
    if ((source && source->family == AF_INET) ||
        (group && group->family == AF_INET))
	cache = CACHE;
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
    if ((source && source->family == AF_INET6) ||
        (group && group->family == AF_INET6))
	cache = CACHE6;
#endif /* HAVE_MROUTING6 */
    e.source = source;
    e.group = group;
    assert (cache);
    return (HASH_Lookup (cache->hash, &e));
}


void
cache_update_mfc (cache_entry_t *entry)
{
    cache_t *cache = NULL;
    interface_bitset_t bitset;

    assert (entry);
    if (ifor (&entry->children, &entry->routers, &bitset, sizeof (bitset))) {
	entry->flags &= ~CACHE_NEGATIVE;
    }
    else {
	entry->flags |= CACHE_NEGATIVE;
    }
#ifdef HAVE_MROUTING
    if (entry->group->family == AF_INET) {
	cache = CACHE;
	mc_add_mfc (entry->group, entry->source, entry->parent, &bitset);
    }
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
    if (entry->group->family == AF_INET6) {
	cache = CACHE6;
	mc6_add_mfc (entry->group, entry->source, entry->parent, &bitset);
    }
#endif /* HAVE_MROUTING6 */

    assert (cache);
    trace (TR_TRACE, cache->trace,
	   "%s cache updated "
	    "(source %a group %a parent %s count %d holdtime %d)\n",
	    BIT_TEST (entry->flags, CACHE_NEGATIVE)? "negative": "forward",
            entry->source, entry->group, 
	    (entry->parent)?entry->parent->name:"?",
	    entry->count, entry->holdtime);
}



/* non-leaf to leaf transition */
void
cache_update_to_leaf (int proto, int index)
{
    cache_entry_t *entry;
    cache_t *cache = proto2cache (proto);

    HASH_Iterate (cache->hash, entry) {
	if (BIT_TEST (entry->flags, CACHE_DELETE))
	    continue;
	assert (entry->parent);
	if (entry->parent->index == index) {
	    assert (!BITX_TEST (&entry->routers, index));
	    continue;
	}
	if (BITX_TEST (&entry->routers, index)) {
            BITX_RESET (&entry->routers, index);
            if (!BITX_TEST (&entry->children, index))
	        cache_update_mfc (entry);
	}
    }
}


/* leaf to non-leaf transition */
void
cache_update_to_router (int proto, int index)
{
    cache_entry_t *entry;
    cache_t *cache = proto2cache (proto);

    HASH_Iterate (cache->hash, entry) {
	if (BIT_TEST (entry->flags, CACHE_DELETE))
	    continue;
	assert (entry->parent);
	if (entry->parent->index == index) {
	    assert (!BITX_TEST (&entry->routers, index));
	    continue;
	}
	if (!BITX_TEST (&entry->routers, index)) {
            BITX_SET (&entry->routers, index);
            if (!BITX_TEST (&entry->children, index))
	        cache_update_mfc (entry);
	}
    }
}


/* non-leaf or leaf to down transition */
void
cache_update_to_down (int proto, int index)
{
    cache_entry_t *entry;
    cache_t *cache = proto2cache (proto);

    HASH_Iterate (cache->hash, entry) {
	if (BIT_TEST (entry->flags, CACHE_DELETE))
	    continue;
	assert (entry->parent);
	if (entry->parent->index == index) {
	    assert (!BITX_TEST (&entry->routers, index));
	    continue;
	}
	if (BITX_TEST (&entry->routers, index) ||
	    BITX_TEST (&entry->children, index)) {
            BITX_RESET (&entry->routers, index);
            BITX_RESET (&entry->children, index);
	    cache_update_mfc (entry);
	}
    }
}


void
cache_update_parent_up (int proto, int index)
{
    cache_entry_t *entry;
    cache_t *cache = proto2cache (proto);

    HASH_Iterate (cache->hash, entry) {
	if (BIT_TEST (entry->flags, CACHE_DELETE))
	    continue;
	assert (entry->parent);
	if (entry->parent_index != index)
	    continue;

	if (cache->update_call_fn)
	    cache->update_call_fn (MRTMSG_UPDATE, cache, entry);
	cache_update_mfc (entry);
    }
}


void
cache_update_parent_down (int proto, int index)
{
    cache_entry_t *entry;
    cache_t *cache = proto2cache (proto);

    HASH_Iterate (cache->hash, entry) {
	if (BIT_TEST (entry->flags, CACHE_DELETE))
	    continue;
	assert (entry->parent);
	if (entry->parent_index != index)
	    continue;

	memset (&entry->routers, 0, sizeof (entry->routers));
	memset (&entry->children, 0, sizeof (entry->children));
	cache_update_mfc (entry);
    }
}


#ifdef HAVE_MROUTING
static int
index2vindex (int index)
{
    if (index <= 0)
	return (-1);
    assert (index > 0 && index < MAX_INTERFACES);
    if (INTERFACE_MASTER->index2if[index] == NULL)
	return (-1);
    return (INTERFACE_MASTER->index2if[index]->vif_index);
}
#endif /* HAVE_MROUTING */


static cache_entry_t *
cache_new_entry (prefix_t *source, prefix_t *group, interface_t *parent)
{
    cache_entry_t *entry;

    entry = New (cache_entry_t);
    entry->source = Ref_Prefix (source);
    entry->group = Ref_Prefix (group);
    entry->parent = parent;
    entry->parent_index = -1;
    entry->count = 0;
    entry->use = 0;
    entry->lastuse = 0;
    entry->holdtime = DEFAULT_CACHE_LIFETIME;
    entry->expire = 0;
    memset (&entry->children, 0, sizeof (entry->children));
    memset (&entry->routers, 0, sizeof (entry->routers));
    return (entry);
}


static void
cache_del_entry (cache_entry_t *entry)
{
    Deref_Prefix (entry->source);
    Deref_Prefix (entry->group);
    if (entry->ll_prunes)
	LL_DestroyFn (entry->ll_prunes, NULL);
    if (entry->ll_joins)
	LL_DestroyFn (entry->ll_joins, NULL);
    Delete (entry);
}


static void
cache_timer_expire (cache_t *cache)
{                            
    cache_entry_t *entry;
    time_t now;

    assert (cache);
    trace (TR_TRACE, cache->trace, "timer (expire) fired\n");
    time (&now);

    HASH_Iterate (cache->hash, entry) { 
next_entry:
        if (entry->expire == 0)
	    continue;
	if (entry->lastuse != entry->use) {
	    entry->lastuse = entry->use;
	    entry->expire = now + entry->holdtime;
	}
        if (entry->expire > now) {
	    int n;
	    if (BIT_TEST (entry->flags, CACHE_DELETE))
		continue;
#ifdef HAVE_MROUTING
	    if (cache->family == AF_INET) {
	        if ((n = mc_req_mfc (entry->group, entry->source)) >= 0)
		    entry->use = n;
		continue;
	    }
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
	    if (cache->family == AF_INET6) {
		/* this is an asyncronous call in INRIA */
	        if ((n = mc6_req_mfc (entry->group, entry->source)) >= 0)
		    entry->use = n;
		continue;
	    }
#endif /* HAVE_MROUTING6 */
	    assert (0);
	}

	if (BIT_TEST (entry->flags, CACHE_DELETE)) {
            cache_entry_t *next = HASH_GetNext (cache->hash, entry);
            trace (TR_TRACE, cache->trace,
	           "cache entry removed "
		    "(source %a group %a count %d parent %s)\n",
                    entry->source, entry->group, entry->count, 
		    (entry->parent)?entry->parent->name:"?");
            HASH_Remove (cache->hash, entry);
            if (next == NULL)
                break;
            entry = next;
            goto next_entry;
	}

#ifdef HAVE_MROUTING
	if (cache->family == AF_INET)
	    mc_del_mfc (entry->group, entry->source);
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
	if (cache->family == AF_INET6)
	    mc6_del_mfc (entry->group, entry->source);
#endif /* HAVE_MROUTING6 */
	if (cache->update_call_fn)
	    cache->update_call_fn (MRTMSG_EXPIRE, cache, entry);

        trace (TR_TRACE, cache->trace,
	       "cache expired (source %a group %a count %d parent %s)\n",
                entry->source, entry->group, entry->count, 
		(entry->parent)?entry->parent->name:"?");
	BIT_SET (entry->flags, CACHE_DELETE);
	entry->expire += entry->holdtime;
	/* will be deleted after the same time goes */
    }
}   


int
cache_control_from_kernel (int type, prefix_t *group, prefix_t *source, 
			   interface_t *parent, int n)
{
    cache_t *cache = NULL;
    cache_entry_t *entry, e;
    time_t now;

    assert (group);
#ifdef HAVE_MROUTING
    if (group->family == AF_INET)
	cache = CACHE;
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
    if (group->family == AF_INET6)
	cache = CACHE6;
#endif /* HAVE_MROUTING6 */

    if (cache == NULL)
	return (0);

    /* I don't know why kernel doesn't provide information 
       on incoming interface in v4 */
    time (&now);

    switch (type) {
    case MRTMSG_NOCACHE:

	e.source = source;
	e.group = group;
	entry = HASH_Lookup (cache->hash, &e);

	if (entry) {
	    if (!BIT_TEST (entry->flags, CACHE_DELETE)) {
            	trace (TR_TRACE, cache->trace,
	           	"inconsistent cache "
		   	"(source %a group %a count %d parent %s expire %d)\n",
                   	entry->source, entry->group, entry->count, 
			(entry->parent)?entry->parent->name:"?", 
			entry->expire - now);
	    }
	    else {
		/* cancel deletion */
		BIT_RESET (entry->flags, CACHE_DELETE);
	    }
	} else {
            entry = cache_new_entry (source, group, parent);
	    entry->ctime = now;
	    HASH_Insert (cache->hash, entry);
	}

	entry->flags &= ~CACHE_NEGATIVE;
	memset (&entry->children, 0, sizeof (entry->children));
	memset (&entry->routers, 0, sizeof (entry->routers));
	if (cache->update_call_fn) {
	    cache->update_call_fn (type, cache, entry);
	    /* holdtime has to be set. count may be updated */
	}

	if (entry->parent == NULL) {
	   /* just leave this entry, but expires later */
	    BIT_SET (entry->flags, CACHE_DELETE);
	    entry->expire = now + DEFAULT_CACHE_LIFETIME;
	    /* this must be the dummy route to catch no-route ones */
            trace (TR_TRACE, cache->trace,
                   "no cache no route found (source %a group %a)\n",
                   entry->source, entry->group);
	    /* can't send a prune since it's unknown who forwarded it */
	    break;
	}
	entry->expire = now + entry->holdtime;
	cache_update_mfc (entry);
	break;
    case MRTMSG_WRONGIF:
	/* XXX */
        break;
/* called from kernel thru igmp thread */
    case MRTMSG_NEWMEMBER:
    case MRTMSG_DELMEMBER:
	/* XXX I know the better way */
        HASH_Iterate (cache->hash, entry) {
	    int notify = 0;
	    if (BIT_TEST (entry->flags, CACHE_DELETE))
	        continue;
	    if (prefix_compare2 (entry->group, group) != 0)
		continue;

            trace (TR_TRACE, cache->trace,
                   "%s on %s found an entry source %a group %a parent %s\n",
		   (type == MRTMSG_NEWMEMBER)?"new memeber":"del member",
		    parent->name,
                   entry->source, entry->group,
		   (entry->parent)?entry->parent->name:"?");
	    /* in this case, parent is interface it's joining on */
	    assert (parent);
	    if (parent == entry->parent) {
	    /* if (prefix_compare2 (entry->source, source) == 0) */
		/* the source is the root */
	        /* assert (parent == entry->parent); */
		/* XXX do I have to do something? */
		continue;
	    }
	    assert (parent != entry->parent);
	    if (type == MRTMSG_NEWMEMBER) {
		if (ifor (&entry->children, &entry->routers, NULL,
			  sizeof (entry->children)) == 0)
		    notify++;
	        /* assert (!BITX_TEST (&entry->children, parent->index)); */
	        BITX_SET (&entry->children, parent->index);
	    }
	    else {
	        /* assert (BITX_TEST (&entry->children, parent->index)); */
	        BITX_RESET (&entry->children, parent->index);
		if (ifor (&entry->children, &entry->routers, NULL,
			  sizeof (entry->children)) == 0)
		    notify++;
	    }
	    if (cache->update_call_fn && notify) {
	        cache->update_call_fn (type, cache, entry);
	        /* holdtime has to be set. count may be updated */
	    }
	    /* entry->expire = now + entry->holdtime; */
	    cache_update_mfc (entry);
	}
	break;
    case MRTMSG_USAGE:
	e.source = source;
	e.group = group;
	entry = HASH_Lookup (cache->hash, &e);

	if (entry == NULL) {
           trace (TR_TRACE, cache->trace,
	         "usage no cache (source %a group %a)\n", source, group);
	}
	else if (BIT_TEST (entry->flags, CACHE_DELETE)) {
            trace (TR_TRACE, cache->trace,
	           "usage expired cache "
		   "(source %a group %a count %d parent %s expire %d)\n",
                   entry->source, entry->group, entry->count, 
		   (entry->parent)?entry->parent->name:"?", 
		   now - entry->expire);
	}
	else {
	    entry->use = n;
	}
	Deref_Prefix (group);
	Deref_Prefix (source);
	break;
    case MRTMSG_CACHE:
	e.source = source;
	e.group = group;
	entry = HASH_Lookup (cache->hash, &e);
	if (entry == NULL || BIT_TEST (entry->flags, CACHE_DELETE)) {
            trace (TR_TRACE, cache->trace,
	          "kernel cache deleted (source %a group %a parent %s)\n", 
		   source, group, (parent)?parent->name:"?");
#ifdef HAVE_MROUTING
	    if (cache->family == AF_INET)
	        mc_del_mfc (group, source);
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
	    if (cache->family == AF_INET6)
	        mc6_del_mfc (group, source);
#endif /* HAVE_MROUTING6 */
	}
	break;
    default:
	assert (0);
	break;
    }
    return (0);
}


void
cache_init (int family, trace_t * tr)
{
    char *name = NULL;
    cache_t *cache;

    cache = New (cache_t);
#ifdef HAVE_MROUTING
    if (family == AF_INET) {
        CACHE = cache;
        IGMP->recv_km_call_fn = cache_control_from_kernel;
        name = "CACHE";
    }
#endif /* HAVE_MROUTING */
#ifdef HAVE_MROUTING6
    if (family == AF_INET6) {
	CACHE6 = cache;
        name = "CACHE6";
        IGMPv6->recv_km_call_fn = cache_control_from_kernel;
    }
#endif /* HAVE_MROUTING6 */
    assert (name);
    cache->trace = trace_copy (tr);
    /* set_trace (cache->trace, TRACE_PREPEND_STRING, name, 0); */
    cache->family = family;
    cache->hash = HASH_Create (CACHE_TABLE_HASH_SIZE,
			       HASH_EmbeddedKey, True,
                    	       HASH_KeyOffset, 0,
                               HASH_LookupFunction, ip_pair_lookup_fn,
                               HASH_HashFunction, ip_pair_hash_fn,
                               HASH_DestroyFunction, cache_del_entry,
                               0);
    cache->schedule = New_Schedule (name, cache->trace);
    cache->expire = New_Timer2 ("CACHE expiration timer", 
			       CACHE_UPDATE_INTERVAL, 0,
                               cache->schedule, cache_timer_expire, 1, cache);
    timer_set_jitter2 (cache->expire, -50, 50);
    mrt_thread_create2 (name, cache->schedule, NULL, NULL);
#ifdef HAVE_MROUTING6
    if (family == AF_INET6)
        mc6_kernel_read_rt_table ();
#endif /* HAVE_MROUTING6 */
    Timer_Turn_ON (cache->expire);
    trace (TR_TRACE, cache->trace, "%s initialized\n", name);
}


static char *
bitset2name (interface_bitset_t *bitset, char *buffer, int buflen)
{
    int i;
    char *cp = buffer;
    char *cpend = buffer + buflen - 1 - 3;

    for (i = 1; i < sizeof (*bitset) * 8; i++) {
	if (BITX_TEST (bitset, i)) {
	    interface_t *interface = find_interface_byindex (i);
	    int len;
	    assert (interface);
 	    len = strlen (interface->name);
	    /* don't need to be so strict */
	    if (cp + len + 1 >= cpend) {
		strcpy (cp, " ...");
		break;
	    }
	    if (cp != buffer)
		*cp++ = ' ';
	    strcpy (cp, interface->name);
	    cp += len;
	}
    }
    *cp = '\0';
    return (buffer);
}


int
show_cache_entries (uii_connection_t * uii, int family, char *ifname)
{
    cache_t *cache = family2cache (family);
    cache_entry_t *entry;
    interface_t *interface = NULL;
    time_t now;
    char stmp[MAXLINE];
    int c;
    interface_bitset_t bitset;

    if (cache == NULL || cache->hash == NULL)
        return (0);

    if (ifname) {
	interface = find_interface_byname (ifname);
	if (interface == NULL) {
	    /* can not call uii from this thread */
	    uii_add_bulk_output (uii, "no such interface: %s\n", ifname);
	    return (-1);
	}
    }

    sprintf (stmp, "%-4s %-4s %8s %s", "Life", "Hold", "Use", "Downstreams");
    rib_show_route_head (uii, stmp);

    time (&now);
    HASH_Iterate (cache->hash, entry) {
	int t = -1;

	if (interface && interface != entry->parent)
	    continue;

	c = '>';
	if (BIT_TEST (entry->flags, CACHE_NEGATIVE))
	    c = '-';
	if (BIT_TEST (entry->flags, CACHE_DELETE))
	    c = 'x';
	if (entry->ctime == 0 || entry->expire == 0) {
	    c = '*';
	    sprintf (stmp, "----");
	}
	else
	    sprintf (stmp, "%4ld", entry->expire - now);
	sprintf (stmp + strlen (stmp), " %4d", entry->holdtime);
	sprintf (stmp + strlen (stmp), " %8d", entry->use);
	ifor (&entry->children, &entry->routers, &bitset, sizeof (bitset));
	sprintf (stmp + strlen (stmp), " ");
	bitset2name (&bitset, stmp + strlen (stmp), 
		     sizeof (stmp) - strlen (stmp));

	if (entry->ctime)
	    t = now - entry->ctime;

	rib_show_route_line (uii, c, ' ', -1, 0, t,
			     entry->group, entry->source,
			     entry->parent, stmp);
    }
    return (1);
}

#endif /* HAVE_MROUTING || HAVE_MROUTING6 */
