/*  
 * $Id: area.c,v 1.1.1.1 2000/08/14 18:46:14 labovit Exp $
 */ 
        
#include "ricd.h"


static u_int
area_hash_fn (area_t *area, u_int size)
{
    int val = 0;
    val += ip_hash_fn (area->id, size);
    val += area->level;
    val = val % size;
    return (val);
}


static int
area_lookup_fn (area_t *a, area_t *b)
{
    return (address_equal (a->id, b->id) &&
	   (a->level == b->level));
}


area_t *
ref_area (area_t *area)
{
    if (area) {
        pthread_mutex_lock (&area->mutex_lock);
        assert (area->ref_count > 0);
        area->ref_count++;
        pthread_mutex_unlock (&area->mutex_lock);
    }
    return (area);
}


#define AREA_HASH_SIZE 1023
static mrt_hash_table_t area_hash_table;
#ifdef HAVE_IPV6
static mrt_hash_table_t area_hash_table6;
#endif /* HAVE_IPV6 */

area_t *
add_area (int level, prefix_t *id)
{
    area_t a, *area;
    mrt_hash_table_t *hash = &area_hash_table;
    char sbuf[128];
    prefix_t sprefix;

    assert (id != NULL);
    assert (0 <= level && level <= HQLIP_AREA_LEVEL_INTERNET);

#ifdef HAVE_IPV6
    if (id->family == AF_INET6)
	hash = &area_hash_table6;
#endif /* HAVE_IPV6 */

    if (hash == NULL) {
	hash = New (mrt_hash_table_t);
        pthread_mutex_init (&hash->mutex_lock, NULL);
    }

    pthread_mutex_lock (&hash->mutex_lock);

    if (hash->table == NULL) {
        hash->table = HASH_Create (AREA_HASH_SIZE, 
		    HASH_EmbeddedKey, True,
		    HASH_KeyOffset, 0,
                    HASH_LookupFunction, area_lookup_fn,
                    HASH_HashFunction, area_hash_fn, 0);
    }

#ifdef HAVE_IPV6
    if (id->family == AF_INET6) {
	struct in6_addr addr6;
	u_long *ul = (u_long *)&addr6;
	memcpy (&addr6, prefix_tochar (id), 16);
	if (level == 0 && (ul[0] || ul[1])) {
	    ul[0] = 0;
	    ul[1] = 0;
	    id = New_Prefix2 (AF_INET6, &addr6, -1, &sprefix);
	}
	else if (level > 0 && (ul[2] || ul[3])) {
	    ul[2] = 0;
	    ul[3] = 0;
	    id = New_Prefix2 (AF_INET6, &addr6, -1, &sprefix);
	}
    }
#endif /* HAVE_IPV6 */

    a.level = level;
    a.id = id;

    if ((area = HASH_Lookup (hash->table, &a))) {
        pthread_mutex_unlock (&hash->mutex_lock);
	area = ref_area (area);
	return (area);
    }

    area = New (area_t);
    area->level = level;
    area->id = Ref_Prefix (id);
    area->ref_count = 1;

    pthread_mutex_init (&area->mutex_lock, NULL);
    HASH_Insert (hash->table, area);
    pthread_mutex_unlock (&hash->mutex_lock);

    trace (TR_TRACE, MRT->trace, "add area: %d:%a\n", area->level, area->id);
    return (area);
}


void
deref_area (area_t *area)
{
    if (area == NULL)
	return;
    pthread_mutex_lock (&area->mutex_lock);
    assert (area->ref_count > 0);
    if (area->ref_count <= 1) {
	mrt_hash_table_t *hash = &area_hash_table;
#ifdef HAVE_IPV6
	if (area->id->family == AF_INET6)
	    hash = &area_hash_table6;
#endif /* HAVE_IPV6 */
	assert (hash);
        pthread_mutex_lock (&hash->mutex_lock);
        /* someone may be searching in the table 
	       and found this at the same time */
	if (area->ref_count <= 1) {
	    HASH_Remove (hash->table, area);
            pthread_mutex_unlock (&hash->mutex_lock);
	    pthread_mutex_destroy (&area->mutex_lock);
	    Deref_Prefix (area->id);
	    Delete (area);
	    return;
	}
        pthread_mutex_unlock (&hash->mutex_lock);
    }
    area->ref_count--;
    pthread_mutex_unlock (&area->mutex_lock);
    return;
}


area_t *
find_area (int level, prefix_t *id)
{
    area_t a, *area;
    mrt_hash_table_t *hash = &area_hash_table;

    if (id == NULL)
	return (NULL);

#ifdef HAVE_IPV6
    if (id->family == AF_INET6)
	hash = &area_hash_table6;
#endif /* HAVE_IPV6 */

    if (hash == NULL || hash->table == NULL)
	return (NULL);

    a.level = level;
    a.id = id;

    pthread_mutex_lock (&hash->mutex_lock);
    area = HASH_Lookup (hash->table, &a);
    pthread_mutex_unlock (&hash->mutex_lock);
    return (area);
}
