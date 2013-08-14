/*
 * $Id: community.c,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#include <ctype.h>
#include <mrt.h>
#include <aspath.h>
#include <bgp.h>


/* 
 * Given a bytelength and byte string from a BGP packet, 
 * return a community structure
 */
community_t *
munge_community (int plen, u_char * cp)
{
    /* check if multiple of 4 bytes */
    if (plen % 4 != 0) {
	trace (TR_ERROR, MRT->trace, "community length %d remains\n",
	       plen % 4);
	return (NULL);
    }
    return (New_community (plen / 4, cp, 1));
}


/* 
 * Given an community and a pointer to memory, fill in memory
 * with community values and return pointer to end of memory. 
 *
 * NOTE: We assume enough memory has been allocated.
 */

u_char *
unmunge_community (community_t * community, u_char * cp)
{
    int i;

    if (community && community->len) {
	for (i = 0; i < community->len; i++)
	    BGP_PUT_LONG (community->value[i], cp);
    }
    return (cp);
}


/*
 * Create and fill in an community_t structure. Len is number of
 * community values -- NOT length of buffer
 * values are stored in network byte order and converted into host byte order
 */
community_t *
New_community (int len, u_char * cp, int conversion)
{
    community_t *community;

    community = New (community_t);
    community->len = len;
    community->value = NewArray (u_long, len);
    if (!conversion) {
	/* as they are */
	BGP_GET_DATA (community->value, len * 4, cp);
    }
    else {
	int i;
        for (i = 0; i < len; i++) {
	    /* includes network-to-host conversion */
	    BGP_GET_LONG (community->value[i], cp);
	}
    }
    return (community);
}

/* Delete_community 
 */
void 
Delete_community (community_t * community)
{
    Delete (community->value);
    Delete (community);
}


community_t *
community_copy (community_t *community)
{
    assert (community);
    return (New_community (community->len, (u_char *) community->value, 0));
}


community_t *
community_from_string (char *cp)
{
    u_long community[PA_COMMUNITY_MAXLEN];
    u_int low = 0, high = 0;	/* low should be int for case of no ':' */
    u_int len = 0, flag = 0;

    while (*cp != '\0') {
	if (isdigit (*cp)) {
	    low *= 10;
	    low += (*cp - '0');
	    flag = 1;
	}
	else if (*cp == ':') {
	    high = low;
	    low = 0;
	    flag = 1;		/* single ':' means zero value */
	}
	else {
	    if (flag) {
		/* do i need to mask low like low & 0xffff ? */
		community[len++] = (high << 16) + low;
		low = high = flag = 0;
	    }
	}
	cp++;
    }
    if (flag) {
	community[len++] = (high << 16) + low;
    }

    if (len > 0) {
	return (New_community (len, (u_char *) community, 0));
    }

    return (NULL);
}


char *
community_toa2 (u_long value, char *strbuf)
{
    static char stmp[64];

    if (strbuf == NULL)
	strbuf = stmp;

    if (value == COMMUNITY_NO_EXPORT)
	sprintf (strbuf, "%s", "no-export");
    else if (value == COMMUNITY_NO_ADVERTISE)
	sprintf (strbuf, "%s", "no-advertise");
    else if (value == COMMUNITY_NO_EXPORT_SUBCONFED)
	sprintf (strbuf, "%s", "no-export-subconfed");
    else {
	if (value > 0xffff) 
            sprintf (strbuf, "%lu:%lu", 
	             (value >> 16) & 0xffff,
	             value & 0xffff);
	else
            sprintf (strbuf, "%lu", value);
    }
    return (strbuf);
}


/*
 */
char *
community_toa (community_t * community)
{
    char *stmp, *cp;
    register int i;

    THREAD_SPECIFIC_STORAGE (stmp);
    cp = stmp;
    if (community && community->len) {
	for (i = 0; i < community->len; i++) {
	    /* very rough estimation */
	    if (cp + 5+1+5+1 + 4 /* length of "..." */  
		    >= stmp + THREAD_SPECIFIC_STORAGE_LEN) {
		sprintf (cp, "...");
		return (stmp);
	    }
	    community_toa2 (community->value[i], cp);
	    cp += strlen (cp);
	    *cp++ = ' ';
	}
	cp--;
    }
    *cp = '\0';
    return (stmp);
}


int
community_compare (community_t *a, community_t *b) 
{
    if (a->len != b->len)
	return (-1);
    if (memcmp (a->value, b->value, a->len * sizeof (u_long)) != 0)
	return (-1);
    return (1);
}


static LINKED_LIST *community_list[MAX_CLIST];

static community_condition_t * 
find_community_list (int num, int permit, u_long value)
{
  community_condition_t *condition;

  if (num < 0 || num >= MAX_CLIST)
    return (NULL);
  if (community_list[num] == NULL) {
    return (NULL);
  }

   LL_Iterate (community_list[num], condition) {
     if (permit == condition->permit && value == condition->value)
        return (condition);
   }

   return (NULL);
}


int
add_community_list (int num, int permit, u_long value)
{
   community_condition_t *condition = NULL;

   if (num < 0 || num >= MAX_CLIST)
	 return (-1);
   if (find_community_list (num, permit, value))
	return (0);

   if (community_list[num] == NULL) {
      community_list[num] = LL_Create (0);
   }
   condition = New (community_condition_t);
   condition->permit = permit;
   condition->value = value;
   LL_Add (community_list[num], condition);
   return (LL_GetCount (community_list[num]));
}


int 
remove_community_list (int num, int permit, u_long value)
{
  community_condition_t *condition;

  if (num < 0 || num >= MAX_CLIST)
    return (-1);
  if (community_list[num] == NULL) {
    return (-1);
  }
  condition = find_community_list (num, permit, value);
  if (condition == NULL)
    return (-1);

   LL_Remove (community_list[num], condition);
   return (LL_GetCount (community_list[num]));
}


int
del_community_list (int num) {

   if (num < 0 || num >= MAX_CLIST)
	 return (-1);
    if (community_list[num] == NULL) {
        return (-1);
    }
    Delete (community_list[num]);
    community_list[num] = NULL;
    return (1);
}


int 
community_test (community_t * community, u_long value)
{
    int i;

    if (community == NULL || community->len == 0)
	return (0);

    for (i = 0; i < community->len; i++) {
        if (value == community->value[i])
            return (1);
    }    
    return (0);
}


/*
 * return 1 if permit, 0 if denied, -1 if not matched
 */
int 
apply_community_condition (community_condition_t *condition, 
			   community_t *community)
{
    assert (condition);

    if (community == NULL || community->len <= 0)
	return (-1);
    if (condition->value == 0 /* all */)
	return (condition->permit);

    if (community_test (community, condition->value))
        return (condition->permit);
    return (-1);
}


/*
 * return 1 if permit, 0 otherwise
 */
int 
apply_community_list (int num, community_t *community)
{
   community_condition_t *condition;

   if (num < 0 || num >= MAX_CLIST)
      return (0);
   if (num == 0)
      return (1); /* cisco feature ? */
   if (community_list[num] == NULL) {
      /* I'm not sure how cisco works for undefined access lists */
      return (0); /* assuming deny for now */
   }

   LL_Iterate (community_list[num], condition) {
      int ok;
      if ((ok = apply_community_condition (condition, community)) >= 0)
	 return (ok);
   }
   /* deny */
   return (0);
}


void
community_list_out (int num, void_fn_t fn)
{
    community_condition_t *condition;
  
    if (community_list[num] == NULL)
        return;

    LL_Iterate (community_list[num], condition) {
	char strbuf[64];
	char *tag = "deny";

        if (condition->permit) 
	    tag = "permit";
        if (condition->value == 0) {
	    fn ("community-list %d %s all\n", num, tag);
	}
        else {
	    fn ("community-list %d %s %s\n", num, tag,
				 community_toa2 (condition->value, strbuf));
	}
    }	
}


/* 
 * Given a bytelength and byte string from a BGP packet, 
 * return a cluster_list structure
 */
cluster_list_t *
munge_cluster_list (int plen, u_char * cp)
{
    /* check if multiple of 4 bytes */
    if (plen % 4 != 0) {
	trace (TR_ERROR, MRT->trace, "cluster length %d remains\n",
	       plen % 4);
	return (NULL);
    }
    return (New_cluster_list (plen / 4, cp));
}


/* 
 * Given a cluster_list and a pointer to memory, fill in memory
 * with cluster_list values and return pointer to end of memory. 
 *
 * NOTE: We assume enough memory has been allocated.
 */

u_char *
unmunge_cluster_list (cluster_list_t * cluster_list, u_char * cp)
{
    DATA_PTR id;

    LL_Iterate (cluster_list, id) {
	BGP_PUT_NETLONG ((u_long) id, cp);
    }
    return (cp);
}


/*
 * Create and fill in a cluster_list_t structure. Len is number of
 * cluster_list values
 */
cluster_list_t *
New_cluster_list (int len, u_char * cp)
{
    int i;
    cluster_list_t *cluster_list;

    cluster_list = LL_Create (0);
    for (i = 0; i < len; i++) {
	u_long id;
	BGP_GET_NETLONG (id, cp);
	LL_Add (cluster_list, (DATA_PTR) id);
    }
    return (cluster_list);
}


void 
Delete_cluster_list (cluster_list_t * cluster_list)
{
    LL_Destroy (cluster_list);
}


cluster_list_t *
cluster_list_copy (cluster_list_t *cluster_list)
{
    cluster_list_t *newone = LL_Create (0);
    DATA_PTR id;

    LL_Iterate (cluster_list, id) {
        LL_Add (newone, id);
    }
    return (newone);
}


char *
cluster_list_toa (cluster_list_t * cluster_list)
{
    char *stmp, *cp;

    THREAD_SPECIFIC_STORAGE (stmp);
    cp = stmp;
    if (cluster_list && LL_GetCount (cluster_list)) {
        DATA_PTR id;
	u_long uid;
	LL_Iterate (cluster_list, id) {
	    /* very rough estimation */
	    if (cp + LL_GetCount (cluster_list) * 15 + 4 /* length of "..." */  
		    >= stmp + THREAD_SPECIFIC_STORAGE_LEN) {
		sprintf (cp, "...");
		return (stmp);
	    }
	    uid = (u_long) id;
	    inet_ntop (AF_INET, &uid, cp, 
				     stmp + THREAD_SPECIFIC_STORAGE_LEN - cp);
	    strcat (cp, " ");
	    cp += strlen (cp);
	}
    }
    *cp = '\0';
    return (stmp);
}


cluster_list_t *
cluster_list_from_string (char *cp)
{
    char word[MAXLINE];
    cluster_list_t *cluster_list = NULL;

    while (uii_parse_line2 (&cp, word)) {
        u_long id;
	if (inet_pton (AF_INET, word, &id) <= 0)
	    return (cluster_list);
	if (cluster_list == NULL)
	    cluster_list = LL_Create (0);
	LL_Add (cluster_list, (DATA_PTR) id);
    }
    return (cluster_list);
}

