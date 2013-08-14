/*
 * $Id: aspath.c,v 1.2 2000/08/15 01:03:28 labovit Exp $
 */

#include <mrt.h>
#include <aspath.h>
#include <bgp.h>


static int num_active_aspath = 0;
static int num_active_aspath_seg = 0;

/*
 */
static void 
Delete_ASPATH_segment (aspath_segment_t * aspath_segment)
{
    assert (aspath_segment);
    Delete (aspath_segment->as);
    Delete (aspath_segment);
    num_active_aspath_seg--;
}

/*
 */
aspath_t *
New_ASPATH ()
{
    num_active_aspath++;
    return (LL_Create (LL_DestroyFunction, Delete_ASPATH_segment, NULL));
}


/*
 * Create and fill in an aspath_segment_t structure. Len is number of
 * AS's -- NOT length of buffer
 */
static aspath_segment_t *
New_ASPATH_segment (int type, int len, u_char *cp, int conversion)
{
    aspath_segment_t *as_seg;

    as_seg = New (aspath_segment_t);
    as_seg->type = type;
    as_seg->len = len;
    as_seg->as = NewArray (u_short, len);
    num_active_aspath_seg++;

    if (!conversion) {
	/* as they are */
	BGP_GET_DATA (as_seg->as, len * 2, cp);
    }
    else {
        int i;
        for (i = 0; i < len; i++) {
	    /* includes network-to-host conversion */
	    BGP_GET_SHORT (as_seg->as[i], cp);
	}
    }
    if (type == PA_PATH_SET) {
	/* XXX we should sort and remove duplicates */
    }
    return (as_seg);
}


#ifdef notdef
aspath_t *
New_NULL_ASPATH ()
{
    aspath_t *aspath = New_ASPATH ();
    LL_Add (aspath, New_ASPATH_segment (PA_PATH_SEQ, 0, NULL, 0));
    return (aspath);
}
#endif


/*
 */
void 
Delete_ASPATH (aspath_t * aspath)
{
    if (aspath == NULL)
        return;
    num_active_aspath--;
    LL_Destroy (aspath);
}


/* 
 * Given a bitlength and byte string from a BGP packet, 
 * return an aspath structure
 * Note that NULL is returned if an error
 */
aspath_t *
munge_aspath (int len, u_char * cp)
{
    int seg_type, seg_len;
    aspath_segment_t *as_seg;
    aspath_t *aspath = New_ASPATH ();

    while (len > 0) {
	if (len < 2) {
	    trace (TR_ERROR, MRT->trace, "bad byte count %d (aspath)\n", len);
    	    Delete_ASPATH (aspath);
	    return (NULL);
	}
	BGP_GET_BYTE (seg_type, cp);
	BGP_GET_BYTE (seg_len, cp);
	len -= 2;

	/* ignore an aspath with len == 0 */
	if (seg_len > 0) {
	    len -= (2 * seg_len);

	    if (seg_type != PA_PATH_SET && seg_type != PA_PATH_SEQ) {
	        trace (TR_ERROR, MRT->trace, "bad as path segnment type %d\n",
		       seg_type);
    	        Delete_ASPATH (aspath);
		return (NULL);
	    }
	    if (len < 0) {
	        trace (TR_ERROR, MRT->trace, "too large segment len %d\n",
		       seg_len);
    	        Delete_ASPATH (aspath);
		return (NULL);
	    }

	    /* XXX we should merge two SEQ segments */
	    as_seg = New_ASPATH_segment (seg_type, seg_len, cp, 1);
	    cp += (2 * seg_len);
	    LL_Add (aspath, as_seg);
	}
    }
    if (len != 0) {
	trace (TR_ERROR, MRT->trace, "AS path length %d remains\n", len);
    	Delete_ASPATH (aspath);
	return (NULL);
    }
    return (aspath);
}


/*
 * Given an aspath and a pointer to memory, fill in memory
 * with ASPATH and return pointer to end of ASPATH.
 *
 * NOTE: We assume enough memory has been allocated.
 */

u_char *
unmunge_aspath (aspath_t * aspath, u_char * cp)
{
    aspath_segment_t *aspath_segment;

    if (aspath == NULL)
	return (cp);

    LL_Iterate (aspath, aspath_segment) {
        int i;

	BGP_PUT_BYTE (aspath_segment->type, cp);
	BGP_PUT_BYTE (aspath_segment->len, cp);
	for (i = 0; i < aspath_segment->len; i++)
	    BGP_PUT_SHORT (aspath_segment->as[i], cp);
    }
    return (cp);
}


char *
aspath_toa (aspath_t * aspath)
{
    register int i;
    char *stmp, *cp;
    aspath_segment_t *as_seg;

    if (aspath == NULL)
	return ("");

    THREAD_SPECIFIC_STORAGE (stmp);
    cp = stmp;

    LL_Iterate (aspath, as_seg) {

	/* very rough estimation */
	if (cp - stmp + 1 + as_seg->len*6 + 7 + 1 + 4 /* ... */ >= 
		THREAD_SPECIFIC_STORAGE_LEN) {
	    sprintf (cp, "...");
	    return (stmp);
	}
	if (cp > stmp)
	    *cp++ = ' ';

	if (as_seg->type == PA_PATH_SET)
	    *cp++ = '[';
	else if (as_seg->type == PA_PATH_SEQ)
	    /* *cp++ = '|' */;
	else {
	    sprintf (cp, "?%d?", as_seg->type);
	    cp += strlen (cp);
	}

	for (i = 0; i < as_seg->len; i++) {
	    if (i != 0)
		*cp++ = ' ';
	    sprintf (cp, "%d", as_seg->as[i]);
	    cp += strlen (cp);
	}

	if (as_seg->type == PA_PATH_SET)
	    *cp++ = ']';
	else if (as_seg->type == PA_PATH_SEQ)
	    /* *cp++ = '|' */;
	else
	    *cp++ = '?';
    }
    *cp = '\0';
    return (stmp);
}


/* 
 * Return HOMEAS (the first AS in AS segment list) when 
 * given a bgp_attr_t structure
 */
int
bgp_get_home_AS (aspath_t * aspath)
{
    aspath_segment_t *segment;

    if (aspath == NULL || LL_GetCount (aspath) <= 0)
	return (0);

    segment = LL_GetHead (aspath);
    assert (segment);
    if (segment->type != PA_PATH_SEQ || segment->len <= 0)
	return (0);

    return (segment->as[0]);
}


/*
 * don't care about as segment type
 */
int
bgp_check_aspath_in (aspath_segment_t *as_seg, int as)
{
    int i;

    if (as_seg->len <= 0)
         return (0);

    for (i = 0; i < as_seg->len; i++) {
        if (as == as_seg->as[i])
            return (1);
    }
    return (0);
}


/* detect a loop in aspath */
int
bgp_check_aspath_loop (aspath_t * aspath, int as)
{
    aspath_segment_t *as_seg;

    if (aspath == NULL)
	return (0);

    /* XXX this only checks own as in the aspath */
    LL_Iterate (aspath, as_seg) {
	if (bgp_check_aspath_in (as_seg, as) > 0)
	    return (1);
    }
    return (0);
}


/* 
 * Given an aspath (really a linked list of AS_PATH_SEG 
 * structs), calculate total length of aspath attribute for
 * inclusion in BGP packet
 */
int 
aspath_attrlen (aspath_t * aspath)
{
    aspath_segment_t *segment;
    int len = 0;

    if (aspath == NULL) {
	return (len);
    }

    LL_Iterate (aspath, segment) {
	len += (1 /* type */ + 1 /* length */);
	len += (2 * segment->len);
    }

    return (len);
}


int 
aspath_length (aspath_t * aspath)
{
    aspath_segment_t *segment;
    int len = 0;

    if (aspath == NULL) {
	return (len);
    }

    LL_Iterate (aspath, segment) {
        if (segment->type == PA_PATH_SEQ)
	    len += segment->len;
        else if (segment->type == PA_PATH_SET)
	    len++;
    }

    return (len);
}


/*
 * should have special code for sets! But none uses sets 
 */
int 
compare_aspaths (aspath_t * aspath1, aspath_t * aspath2)
{
    aspath_segment_t *seg1, *seg2;

    if (aspath1 == NULL && aspath2 == NULL)
	return (1);

    if (aspath1 == NULL || aspath2 == NULL)
	return (-1);

    seg1 = LL_GetHead (aspath1);
    seg2 = LL_GetHead (aspath2);

    while (seg1 && seg2) {
	if (seg1->type != seg2->type)
	    return (-1);
	if (seg1->len != seg2->len)
	    return (-1);
	if (memcmp (seg2->as, seg1->as, seg1->len * 2))
	    return (-1);

	seg1 = LL_GetNext (aspath1, seg1);
	seg2 = LL_GetNext (aspath2, seg2);

	/* both NULL */
	if (seg1 == seg2)
	    return (1);
    }

    /* one is NULL and one is not */
    return (-1);
}

u_int 
aspath_hash_fn (aspath_t * aspath, u_int size)
{
    u_int val, i;
    aspath_segment_t *as_seg;

    val = 0;
    if (aspath == NULL || aspath == NULL)
	return (0);

    LL_Iterate (aspath, as_seg) {
	for (i = 0; i < as_seg->len; i++)
	    val += as_seg->as[i];
    }

    val = val % size;
    return (val);
}


/*
 * no error checks -- stop at a wrong char
 */
aspath_t *
aspth_from_string (char *path)
{
    aspath_t *aspath;
    char *cp = path;
    u_short segment[PA_PATH_MAXSEGLEN];
    int length, set;

    aspath = New_ASPATH ();

    while (isspace (*cp))
	cp++;

    while (*cp && strchr ("[|0123456789", *cp)) {
	set = 0;
	length = 0;

	if (*cp == '[' || *cp == '|') {
	    if (*cp == '[')
	        set = 1;
	    cp++;
	    while (isspace (*cp))
		cp++;
	}

	while (isdigit (*cp)) {
	    if (length >= PA_PATH_MAXSEGLEN) {
		trace (TR_ERROR, MRT->trace, "as segment len exceeded > %d\n",
		       PA_PATH_MAXSEGLEN);
		Delete_ASPATH (aspath);
		return (NULL);
	    }
	    segment[length++] = atoi (cp);

	    /* skip digits */
	    while (isdigit (*cp))
		cp++;
	    while (isspace (*cp))
		cp++;
	}

	if (set) {
	    LL_Add (aspath, New_ASPATH_segment (PA_PATH_SET, length, 
					(u_char *) segment, 0));
	    set = 0;
	}
	else {
	    LL_Add (aspath,
		    New_ASPATH_segment (PA_PATH_SEQ, length, 
					(u_char *) segment, 0));
	}
	if (*cp == ']' || *cp == '|') {
	    cp++;
	    while (isspace (*cp))
		cp++;
	}
    }
    return (aspath);
}


aspath_t *
aspath_copy (aspath_t * aspath)
{
    aspath_segment_t *seg;
    aspath_t *result;

    if (aspath == NULL /* || LL_GetCount (aspath) <= 0 */)
	return (NULL);
    result = New_ASPATH ();
    LL_Iterate (aspath, seg) {
	assert (seg);
	LL_Add (result, New_ASPATH_segment (seg->type, seg->len, 
				   (u_char *) seg->as, 0));
    }
    return (result);
}


/* reduce two contiguous AS-SEQs into one */
aspath_t *
aspath_reduce (aspath_t *aspath)
{
    aspath_segment_t *seg1;
    aspath_segment_t *seg2;

    if (aspath == NULL)
	return (NULL);
    if (LL_GetCount (aspath) <= 0) {
	Delete_ASPATH (aspath);
	return (NULL);
    }

    seg1 = LL_GetHead (aspath);
    do {
	if (seg1->type == PA_PATH_SEQ) {
	    seg2 = LL_GetNext (aspath, seg1);
	    if (seg2 == NULL)
		break;
	    if (seg2->type == PA_PATH_SEQ && 
		    seg1->len + seg2->len < PA_PATH_MAXSEGLEN) {
		/* reduction */
		seg1->as = ReallocateArray (seg1->as, u_short, 
					    seg1->len + seg2->len);
		memcpy (seg1->as + seg1->len, seg2->as, 
			seg2->len * sizeof (u_short));
		seg1->len += seg2->len;
		LL_Remove (aspath, seg2);
	    }
	    else {
		seg1 = seg2;
	    }
	}
    } while ((seg1 = LL_GetNext (aspath, seg1)) != NULL);
    return (aspath);
}


aspath_t *
aspath_prepend (aspath_t * result, aspath_t * aspath)
{
    aspath_segment_t *seg;
    aspath_segment_t *head = NULL;

    if (aspath == NULL || LL_GetCount (aspath) <= 0)
	return (NULL);

    if (result == NULL)
        result = New_ASPATH ();

    LL_Iterate (aspath, seg) {
	assert (seg);
	if (head == NULL) {
	    head = New_ASPATH_segment (seg->type, seg->len, 
				       (u_char *) seg->as, 0);
	    LL_Prepend (result, head);
	}
	else {
	    aspath_segment_t *tmp_seg = 
		New_ASPATH_segment (seg->type, seg->len, (u_char *) seg->as, 0);
	    LL_InsertAfter (result, tmp_seg, head);
	}
    }
    result = aspath_reduce (result);
    return (result);
}


aspath_t *
aspath_append (aspath_t * result, aspath_t * aspath)
{
    aspath_segment_t *seg;

    if (aspath == NULL || LL_GetCount (aspath) <= 0)
	return (result);

    if (result == NULL)
        result = New_ASPATH ();

    LL_Iterate (aspath, seg) {
	assert (seg);
	LL_Add (result, New_ASPATH_segment (seg->type, seg->len, 
				   (u_char *) seg->as, 0));
    }
    result = aspath_reduce (result);
    return (result);
}


aspath_t *
aspath_prepend_as (aspath_t * aspath, int as)
{
    u_short us = as;
    aspath_segment_t *seg;

    seg = New_ASPATH_segment (PA_PATH_SEQ, 1, (u_char *) &us, 0);

    if (aspath == NULL) {
        aspath = New_ASPATH ();
	LL_Add (aspath, seg);
	return (aspath);
    }

    LL_Prepend (aspath, seg);
    aspath = aspath_reduce (aspath);
    return (aspath);
}


static int
as_compare (const void * a, const void * b)
{
    return (*(u_short *)a - *(u_short *)b);
}


/* merge aspath2 into aspath1
   and return aspath1 leaving unique as set in tail */
aspath_t *
aspath_merge (aspath_t * aspath1, aspath_t * aspath2, aspath_t *tail)
{
    aspath_segment_t *seg1, *seg2;
    u_short ases[PA_PATH_MAXSEGLEN];
    int i, j, numas = 0;
    int start_index = 0, save;

    if ((aspath1 == NULL || LL_GetCount (aspath1) <= 0) &&
        (aspath2 == NULL || LL_GetCount (aspath2) <= 0)) {
	return (NULL);
    }
    else if (aspath1 == NULL || LL_GetCount (aspath1) <= 0) {
	seg1 = NULL;
	seg2 = LL_GetHead (aspath2);
    }
    else if (aspath2 == NULL || LL_GetCount (aspath2) <= 0) {
	seg1 = LL_GetHead (aspath1);
	seg2 = NULL;
    }
    else {
        seg1 = LL_GetHead (aspath1);
        seg2 = LL_GetHead (aspath2);

        while (seg1 && seg2) {

	    int len = seg1->len;
	    if (len > seg2->len)
		len = seg2->len;

	    if (seg1->type != seg2->type)
		break;

	    for (i = 0; i < len; i++) {
		if (seg1->as[i] != seg2->as[i]) {
		    if (seg1->type == PA_PATH_SEQ)
			start_index = i;
		    goto out;
		}
	    }
	    if (seg1->len != seg2->len) {
		if (seg1->type == PA_PATH_SEQ)
		    start_index = i;
		break;
	    }
	    seg1 = LL_GetNext (aspath1, seg1);
	    seg2 = LL_GetNext (aspath2, seg2);
	}
    }

out:
    save = start_index;
    while (seg1) {
	aspath_segment_t *ptr;

	for (i = start_index; i < seg1->len; i++) {
	    for (j = 0; j < numas; j++) {
		if (ases[j] == seg1->as[i])
		    break;
	    }
	    if (j >= numas)
	        ases[numas++] = seg1->as[i];
	}
	ptr = LL_GetNext (aspath1, seg1);
	if (start_index > 0) {
	    if (start_index >= seg1->len) {
	        /* OK, skip this */
	    }
	    else {
	        /* shrink the as seq */
	        seg1->len = start_index;
	        seg1->as = ReallocateArray (seg1->as, u_short, seg1->len);
	    }
	    start_index = 0;
	}
	else {
	    LL_Remove (aspath1, seg1);
	}
	seg1 = ptr;
    }

    start_index = save;
    while (seg2) {
	for (i = start_index; i < seg2->len; i++) {
	    for (j = 0; j < numas; j++) {
		if (ases[j] == seg2->as[i])
		    break;
	    }
	    if (j >= numas)
	        ases[numas++] = seg2->as[i];
	}
	seg2 = LL_GetNext (aspath2, seg2);
	start_index = 0;
    }

    if (numas > 0 && tail) {
        assert (numas < PA_PATH_MAXSEGLEN);
	if (LL_GetCount (tail) > 0) {
	    assert (LL_GetCount (tail) == 1);
	    seg2 = LL_GetHead (tail);
	    assert (seg2->type == PA_PATH_SET);
	    /* I know there is a smarter way */
	    for (i = 0; i < seg2->len; i++) {
	        for (j = 0; j < numas; j++) {
	            if (ases[j] == seg2->as[i])
		        break;
	        }
	        if (j >= numas)
	            ases[numas++] = seg2->as[i];
	    }
	    LL_Remove (tail, seg2); /* destory seg2, too */
	}
        qsort (ases, numas, sizeof (ases[0]), &as_compare);
        LL_Add (tail,
	        New_ASPATH_segment (PA_PATH_SET, numas, (u_char *) ases, 0));
    }
    return (aspath1);
}


/* removes immediate ases whose range a thru b from aspath */
aspath_t *
aspath_remove (aspath_t *aspath, int a, int b)
{
    aspath_segment_t *seg;

    assert (a <= b);
    if (aspath == NULL || LL_GetCount (aspath) <= 0) {
	return (NULL);
    }

    /* while ((seg = LL_GetHead (aspath)) != NULL) { */
      LL_Iterate (aspath, seg) {
	int n = 0;
	int nn = 0;
	int skipped = 0;


	/* remove immediate ases. 
	   continue if all ases in the both seq and set match */
	//if (seg->len == 0) {
	  //LL_Remove (aspath, seg);
	    /* XXX I'm not sure if this is OK */
	  //	    continue;
	//}


	for (n = 0; n < seg->len; n++) { 
	  if (seg->as[n] > a && seg->as[n] < b) {
	    for (nn = n; nn < seg->len-1; nn++) {
	      seg->as[nn] = seg->as[nn+1];
	    }
	    skipped++;
	  }
	}

	seg->len -=  skipped;

	if (seg->len == 0) {
	    //LL_Remove (aspath, seg);
	    // need to do something else here -- can't remove
             // while iterating
	}
    }


#ifdef notdef
	for (n = 0; n < seg->len; n++) { 
	  if (seg->as[n] < a || seg->as[n] > b)
	    break;
	}

	if (n == 0)
	    break;

	/* removal */
	if (seg->len == n) {
	    LL_Remove (aspath, seg);
	}
	else {
	    int i;
	    assert (n < seg->len);
	    seg->len = seg->len - n;
	    for (i = 0; i < seg->len; i++)
		seg->as[i] = seg->as[i + n];
	    /* XXX compaction? */
	    break;
	}
#endif


    return (aspath);
}
