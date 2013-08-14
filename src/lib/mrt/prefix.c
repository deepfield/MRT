/* 
 * $Id: prefix.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <mrt.h>
#ifndef NT
#include <netdb.h>
#endif /* NT */

#ifdef NT
#include <winsock2.h>
#ifdef HAVE_IPV6
#include <ws2ip6.h>
#endif /* HAVE_IPV6 */
#include <ws2tcpip.h>
#endif /* NT */


#ifndef __GLIBC__
#ifdef __osf__

/* apparently, OSF's gethostby{name,addr}_r's are different, broken, and
   deprecated! The normal versions are, in fact, thread safe (sayeth the
   fine man page), so we're defining to use those instead. --dogcow */

#define gethostbyname_r(a,b,c,d,e)   gethostbyname(a,b,c,d,e)
#define gethostbyaddr_r(a,b,c,d,e,f,g) gethostbyaddr(a,b,c)
#endif

/* Prototypes for netdb functions that aren't in the 
 * gcc include files (argh!) */
/* The reason they're not there is because SOMEBODY installed the
   FREAKING BIND-4 INCLUDES, which you AIN'T SUPPOSED TO DO WITH
   SOLARIS! GRRRR!
   In addition, it seems somewhat bad that the functions don't
   exist in the bind include files... if the regular equivs are,
   in fact, threadsafe, the #ifdef __osf__ may have to be expanded.
   -- dogcow
 */

struct hostent  *gethostbyname_r 
	(const char *, struct hostent *, char *, int, int *h_errnop);
struct hostent  *gethostbyaddr_r
        (const char *, int, int, struct hostent *, char *, int, int *h_errnop);

#else /* Linux GNU C here */

   /* I'd hope that this doesn't conflict with the above.
      gethostXX_r seems to be different among platforms.
      I need to learn more about them to write a more portable code.
      For the time being, this part tries to convert Linux glibc 2.X
      gethostXX_r into Solaris's that we use to code MRT. -- masaki
    */
#if __GLIBC__ >= 2
   /* Glibc 2.X

    int gethostbyname_r (const char *name, struct hostent *result_buf, 
			 char *buf, size_t buflen, struct hostent **result,
                         int *h_errnop);
    int gethostbyaddr_r (const char *addr, int len, int type,
                         struct hostent *result_buf, char *buf,
                         size_t buflen, struct hostent **result,
                         int *h_errnop));
    */

struct hostent *p_gethostbyname_r (const char *name,
    struct hostent *result, char *buffer, int buflen, int *h_errnop) {

    struct hostent *hp;
    if (gethostbyname_r (name, result, buffer, buflen, &hp, h_errnop) < 0)
	return (NULL);
    return (hp);
}

struct hostent *p_gethostbyaddr_r (const char *addr,
    int length, int type, struct hostent *result,
    char *buffer, int buflen, int *h_errnop) {

    struct hostent *hp;
    if (gethostbyaddr_r (addr, length, type, result, buffer, buflen, 
			 &hp, h_errnop) < 0)
	return (NULL);
    return (hp);
}

#define gethostbyname_r(a,b,c,d,e)     p_gethostbyname_r(a,b,c,d,e)
#define gethostbyaddr_r(a,b,c,d,e,f,g) p_gethostbyaddr_r(a,b,c,d,e,f,g)
#endif  /* __GLIBC__ >= 2 */

#endif /* __GLIBC__ */
 

int num_active_prefixes = 0;

/* 
   this is a new feature introduced by masaki. This is intended to shift to
   use a static memory as much as possible. If ref_count == 0, the prefix
   memory must be allocated in a static memory or on a stack instead of
   in the heap, i.e. not allocated by malloc(), that doesn't need to be freed
   later.
*/

prefix_t *
New_Prefix2 (int family, void *dest, int bitlen, prefix_t *prefix)
{
    int dynamic_allocated = 0;
    int default_bitlen = 32;

#ifdef HAVE_IPV6
    if (family == AF_INET6) {
        default_bitlen = 128;
	if (prefix == NULL) {
            prefix = (prefix_t *) New (prefix6_t);
	    dynamic_allocated++;
	}
	memcpy (&prefix->add.sin6, dest, 16);
    }
    else
#endif /* HAVE_IPV6 */
    if (family == AF_INET) {
		if (prefix == NULL) {
#ifndef NT
            prefix = (prefix_t *) New (prefix4_t);
#else
			//for some reason, compiler is getting
			//prefix4_t size incorrect on NT
			prefix = (prefix_t *) New (prefix_t); 
#endif /* NT */
		
			dynamic_allocated++;
		}
		memcpy (&prefix->add.sin, dest, 4);
    }
    else {
        return (NULL);
    }

    prefix->bitlen = (bitlen >= 0)? bitlen: default_bitlen;
    prefix->family = family;
    prefix->ref_count = 0;
    if (dynamic_allocated) {
        pthread_mutex_init (&prefix->mutex_lock, NULL);
        prefix->ref_count++;
        num_active_prefixes++;
   }
/* fprintf(stderr, "[C %s, %d]\n", prefix_toa (prefix), prefix->ref_count); */
    return (prefix);
}


prefix_t *
New_Prefix (int family, void *dest, int bitlen)
{
    return (New_Prefix2 (family, dest, bitlen, NULL));
}

/* name_toprefix() takes a hostname and returns a prefix with the 
 * appropriate address information.  This function uses gethostbyname_r,
 * so it should be thread-safe.
 */
prefix_t *
name_toprefix(char *name, trace_t *caller_trace)
{
    struct hostent *hostinfo;
    prefix_t *prefix;

#ifdef HAVE_GETHOSTBYNAME_R
    struct hostent result;
    int h_errno_r;
    char buf[1024];

    hostinfo = gethostbyname_r(name, &result, buf, 1024, &h_errno_r);
#else
    hostinfo = gethostbyname(name);
#endif

    if (hostinfo == NULL) {
#ifdef HAVE_GETHOSTBYNAME_R
      switch (h_errno) {
#else
      switch (errno) {
#endif 
            case HOST_NOT_FOUND:
                trace(NORM, caller_trace, " ** Host %s not found **\n", name);
		break;
        
            case NO_DATA:
            /* case NO_ADDRESS: */
                trace(NORM, caller_trace, 
                    " ** No address data is available for host %s ** \n",
                    name);
		break;

	    case TRY_AGAIN:
		trace(NORM, caller_trace,
		    " ** DNS lookup failure for host %s; try again later **\n",
		    name);
		break;

	    case NO_RECOVERY:
		trace(NORM, caller_trace,
		    "** Unable to get IP address from server for host %s **\n",
		    name);
		break;

	    default:
		trace(NORM, caller_trace, 
		    "** Unknown error while looking up IP address for %s **\n",
		    name);
		break;
	}
	return NULL;
    }

    prefix = New_Prefix (hostinfo->h_addrtype, hostinfo->h_addr, 
		8*hostinfo->h_length);

    if (!prefix)
	trace(NORM, caller_trace, 
	" ** Cannot allocate memory for prefix for host %s! \n", name);

    return prefix;
}


/* string_toprefix autodetects whether "name" is a hostname or an IP
 * address, and calls the appropriate prefix functions from the mrt 
 * library to create a prefix from it.  It returns the new prefix, or NULL
 * if an error occurs.
 * IPv4 and IPv6 are supported.
 * Uses the new universal socket interface extensions defined in RFC 2133.
 */

prefix_t *
string_toprefix(char *name, trace_t *caller_trace)
{
    u_char buf[16]; 	/* Buffer for address; max size = IPv6 = 16 bytes */
    prefix_t *dst;
    int status;

    if (isdigit(name[0])) {	/* Numerical address */
	if (!strchr(name, ':')) {	/* No ':' means IPv4 address */
	    if ((status = inet_pton(AF_INET, name, buf)) == 0) {
                trace(NORM, caller_trace, " ** Malformed IP address %s\n",
                    name);
                return NULL;
            } else if (status < 0) { /* Some other error */
		trace(NORM, caller_trace, " **** %s: %s ****\n", 
		    name, strerror(errno));
		return NULL;
	    }
            dst = New_Prefix(AF_INET, buf, 32);
            if (!dst) {
		trace(NORM, caller_trace, 
		    " ** Cannot allocate memory for prefix for host %s! \n",
		    name);
                return NULL;
	    } else
		return dst;
        } else {	/* IPv6 address */
#ifdef HAVE_IPV6
	    if ((status = inet_pton(AF_INET6, name, buf)) == 0) {
                trace(NORM, caller_trace, " ** Malformed IPv6 address %s\n",
                    name);
                return NULL;
            } else if (status < 0) {
                trace(NORM, caller_trace, " **** %s: %s ****\n", 
                    name, strerror(errno));
                return NULL;
            }
	    dst = New_Prefix(AF_INET6, buf, 128);
            if (!dst) {
                trace(NORM, caller_trace, 
                   " ** Cannot allocate memory for prefix for host %s! \n",
                   name);
                return NULL;
            }
#else
	    trace(NORM, caller_trace, "IPv6 not supported.\n");
	    return NULL;
#endif /* HAVE_IPV6 */
	}
    } else {	/* Host name */
	dst = name_toprefix(name, caller_trace);
    }

    return dst;
}


/* prefix_toname takes a prefix and returns a pointer to a character
 * string containing the host's name.
 * It uses gethostbyaddr_r so it should be reentrent.
 * The function dynamically allocates space for the string it retuns,
 * so the calling function should be careful to free this pointer before
 * changing it.
 *
 * We strdup "invalid name" and "prefix_toa" so we don't later deallocate
 * static or unallocated memory!
 */
char *
prefix_toname (prefix_t *prefix)
{
    struct hostent *hostinfo;
    char *name;
#ifdef HAVE_GETHOSTBYADDR_R
    struct hostent result;
    int h_errno_r;
    char hostbuf[1024];
#endif /* GETHOSTBYADDR_R */

    if (prefix == NULL) return (strdup ("invalid name"));

#ifdef GETHOSTBYADDR_R
    hostinfo = gethostbyaddr_r((char *) prefix_tochar(prefix),
		(prefix->bitlen)/8, prefix->family, &result,
		hostbuf, sizeof hostbuf, &h_errno_r);
#else
    hostinfo = gethostbyaddr((char *) prefix_tochar(prefix),
		    prefix_getlen(prefix), prefix_getfamily(prefix));
#endif /* GETHOSTBYADDR_R */

    if (!hostinfo)
	return (strdup (prefix_toa (prefix)));

    name = NewArray (char, strlen(hostinfo->h_name) + 1);
    strcpy(name, hostinfo->h_name);

    return name;
}


/* basically, prefix must not change since it's shared with threads.
   locking is provided only for handling the reference counter */
prefix_t *
Change_Prefix (int family, void *dest, int bitlen, prefix_t * prefix)
{
    /* since the strage of prefix_t varies, so family can't change.
       argument family will be eliminated in the future. */
    if (prefix->ref_count > 0)
        pthread_mutex_lock (&prefix->mutex_lock);
    assert (prefix);
    assert (prefix->family == family);
    prefix->bitlen = bitlen;
    prefix->family = family;

    if (family == AF_INET) {
	memcpy (&prefix->add.sin, dest, 4);
    }
#ifdef HAVE_IPV6
    else if (family == AF_INET6) {
	memcpy (&prefix->add.sin6, dest, 16);
    }
#endif /* HAVE_IPV6 */
    else {
	prefix = NULL;
    }
    if (prefix->ref_count > 0)
        pthread_mutex_unlock (&prefix->mutex_lock);
    return (prefix);
}


prefix_t *
Ref_Prefix (prefix_t * prefix)
{
    if (prefix == NULL)
	return (NULL);
    if (prefix->ref_count == 0) {
	/* make a copy in case of a static prefix */
        return (New_Prefix2 (prefix->family, &prefix->add, prefix->bitlen, NULL));
    }
    pthread_mutex_lock (&prefix->mutex_lock);
    prefix->ref_count++;
/* fprintf(stderr, "[A %s, %d]\n", prefix_toa (prefix), prefix->ref_count); */
    pthread_mutex_unlock (&prefix->mutex_lock);
    return (prefix);
}


void 
Deref_Prefix (prefix_t * prefix)
{
    if (prefix == NULL)
	return;
    /* for secure programming, raise an assert. no static prefix can call this */
    assert (prefix->ref_count > 0);
    pthread_mutex_lock (&prefix->mutex_lock);

/*
if (1) {
int c = prefix->ref_count;
prefix->ref_count = 1;
fprintf(stderr, "[D %s, %d]\n", prefix_toa (prefix), c-1);
prefix->ref_count = c;
} */
    prefix->ref_count--;
    assert (prefix->ref_count >= 0);
    if (prefix->ref_count <= 0) {
        pthread_mutex_destroy (&prefix->mutex_lock);
	Delete (prefix);
        num_active_prefixes--;
	return;
    }
    pthread_mutex_unlock (&prefix->mutex_lock);
}


/* copy_prefix
 */
prefix_t *
copy_prefix (prefix_t * prefix)
{
    if (prefix == NULL)
	return (NULL);
    return (New_Prefix (prefix->family, &prefix->add, prefix->bitlen));
}


/* ascii2prefix
 */
prefix_t *
ascii2prefix (int family, char *string)
{
    u_long bitlen, maxbitlen = 0;
    char *cp;
    struct in_addr sin;
#ifdef HAVE_IPV6
    struct in6_addr sin6;
#endif /* HAVE_IPV6 */
    int result;
    char save[MAXLINE];

    if (string == NULL)
		return (NULL);

    /* easy way to handle both families */
    if (family == 0) {
       family = AF_INET;
#ifdef HAVE_IPV6
       if (strchr (string, ':')) family = AF_INET6;
#endif /* HAVE_IPV6 */
    }

    if (family == AF_INET) {
		maxbitlen = 32;
    }
#ifdef HAVE_IPV6
    else if (family == AF_INET6) {
		maxbitlen = 128;
    }
#endif /* HAVE_IPV6 */

    if ((cp = strchr (string, '/')) != NULL) {
		bitlen = atol (cp + 1);
		/* *cp = '\0'; */
		/* copy the string to save. Avoid destroying the string */
		assert (cp - string < MAXLINE);
		memcpy (save, string, cp - string);
		save[cp - string] = '\0';
		string = save;
		if (bitlen < 0 || bitlen > maxbitlen)
			bitlen = maxbitlen;
		}
		else {
			bitlen = maxbitlen;
		}

		if (family == AF_INET) {
			if ((result = my_inet_pton (AF_INET, string, &sin)) <= 0)
				return (NULL);
			return (New_Prefix (AF_INET, &sin, bitlen));
		}

#ifdef HAVE_IPV6
		else if (family == AF_INET6) {
// Get rid of this with next IPv6 upgrade
#if defined(NT) && !defined(HAVE_INET_NTOP)
			inet6_addr(string, &sin6);
			return (New_Prefix (AF_INET6, &sin6, bitlen));
#else
			if ((result = inet_pton (AF_INET6, string, &sin6)) <= 0)
				return (NULL);
#endif /* NT */
			return (New_Prefix (AF_INET6, &sin6, bitlen));
		}
#endif /* HAVE_IPV6 */
		else
			return (NULL);
}


void 
Delete_Prefix (prefix_t * prefix)
{
    if (prefix == NULL)
	return;
    assert (prefix->ref_count >= 0);
    Delete (prefix);
}


/* 
 * print_prefix_list
 */
void 
print_prefix_list (LINKED_LIST * ll_prefixes)
{
    prefix_t *prefix;

    if (ll_prefixes == NULL)
	return;

    LL_Iterate (ll_prefixes, prefix) {
	printf ("  %-15s\n", prefix_toax (prefix));
    }
}


/*
 * print_pref_prefix_list
 */
void 
print_pref_prefix_list (LINKED_LIST * ll_prefixes, u_short *pref)
{
    prefix_t *prefix;
    int i = 0;

    if ((ll_prefixes == NULL) || (pref == NULL))
	return;

    LL_Iterate (ll_prefixes, prefix) {
	printf ("  %-15s %d\n", prefix_toax (prefix), pref[i++]);
    }
}


void 
print_prefix_list_buffer (LINKED_LIST * ll_prefixes, buffer_t * buffer)
{
    prefix_t *prefix;

    if (ll_prefixes == NULL)
	return;

    LL_Iterate (ll_prefixes, prefix) {
	buffer_printf (buffer, "  %-15p\n", prefix);
    }
}


/*
 * print_pref_prefix_list
 */
void 
print_pref_prefix_list_buffer (LINKED_LIST * ll_prefixes, u_short *pref, 
			       buffer_t * buffer)
{
    prefix_t *prefix;
    int i = 0;

    if ((ll_prefixes == NULL) || (pref == NULL))
	return;

    LL_Iterate (ll_prefixes, prefix) {
	buffer_printf (buffer, "  %-15p %d\n", prefix, pref[i++]);
    }
}


/*
 * returns 1 if the both prefixes are equal
 *    both prefix length are equal
 *    both addresses up to the length are equal
 * otherwise, returns 0
 */
int 
prefix_equal (prefix_t * p1, prefix_t * p2)
{
    assert (p1);
    assert (p2);
    assert (p1->ref_count >= 0);
    assert (p2->ref_count >= 0);
    if (p1->family != p2->family) {
	/* we can not compare in this case */
	return (FALSE);
    }
    return ((p1->bitlen == p2->bitlen) &&
	    (p1->bitlen == 0 || comp_with_mask (
		      prefix_tochar (p1), prefix_tochar (p2), p1->bitlen)));
}


/*
 * returns 1 if the both prefixes are equal
 *    both prefix length are equal
 *    both addresses up to the length are equal
 * otherwise, returns 0
 */
int 
prefix_compare (prefix_t * p1, prefix_t * p2)
{
    return (prefix_equal (p1, p2));
}


/*
 * compare addresses only
 *   both addresses must be totally equal regardless of their length
 * returns 0 if equal, otherwise the difference
 */
int
prefix_compare_wolen (prefix_t *p, prefix_t *q)
{
    int bytes = 4, i, difference;
    u_char *up = prefix_touchar (p);
    u_char *uq = prefix_touchar (q);

    if ((difference = (p->family - q->family)) != 0) {
	/* we can not compare in this case */
	return (difference);
    }
#ifdef HAVE_IPV6
    if (p->family == AF_INET6)
        bytes = 16;
#endif /* HAVE_IPV6 */
    for (i = 0; i < bytes; i++) {
	if ((difference = (up[i] - uq[i])) != 0)
	    return (difference);
    }
    return (0);
}


int
address_equal (prefix_t *p, prefix_t *q)
{
    return (prefix_compare_wolen (p, q) == 0);
}


/*
 * compare addresses and then bitlen
 *   both addresses must be totally equal regardless of their length
 * returns 0 if equal, otherwise the difference
 */
int
prefix_compare_wlen (prefix_t *p, prefix_t *q)
{
    int r;

    if ((r = prefix_compare_wolen (p, q)) != 0)
	return (r);
    if ((r = (p->bitlen - q->bitlen)) != 0)
	return (r);
    return (0);
}


int
prefix_compare2 (prefix_t *p, prefix_t *q)
{
    return (prefix_compare_wlen (p, q));
}


/*
 * returns 1 if prefix a includes prefix b
 * returns 0 otherwise
 */
int 
a_include_b (prefix_t * a, prefix_t * b)
{
    assert (a);
    assert (b);
    assert (a->ref_count >= 0);
    assert (b->ref_count >= 0);

    if (a->bitlen > b->bitlen)
	return (0);

    return (comp_with_mask (prefix_tochar (a), prefix_tochar (b), a->bitlen));
}


/* prefix_toa
 */
char *
prefix_toa (prefix_t * prefix)
{
    return (prefix_toa2 (prefix, (char *) NULL));
}

/* prefix_toa2
 * convert prefix information to ascii string
 */
char *
prefix_toa2 (prefix_t *prefix, char *buff)
{
    return (prefix_toa2x (prefix, buff, 0));
}

/* 
 * convert prefix information to ascii string with length
 * thread safe and (almost) re-entrant implementation
 */
char *
prefix_toa2x (prefix_t *prefix, char *buff, int with_len)
{
    if (prefix == NULL)
	return ("(Null)");
    assert (prefix->ref_count >= 0);
    if (buff == NULL) {

        struct buffer {
            char buffs[16][48+5];
            u_int i;
        } *buffp;

	THREAD_SPECIFIC_DATA (struct buffer, buffp, 1);
	if (buffp == NULL) {
	    /* XXX should we report an error? */
	    return (NULL);
	}

	buff = buffp->buffs[buffp->i++%16];
    }
    if (prefix->family == AF_INET) {
	u_char *a;
	assert (prefix->bitlen <= 32);
	a = prefix_touchar (prefix);
	if (with_len) {
	    sprintf (buff, "%d.%d.%d.%d/%d", a[0], a[1], a[2], a[3],
		     prefix->bitlen);
	}
	else {
	    sprintf (buff, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
	}
	return (buff);
    }
#ifdef HAVE_IPV6
    else if (prefix->family == AF_INET6) {
	char *r;
	r = (char *) inet_ntop (AF_INET6, &prefix->add.sin6, buff, 48 /* a guess value */ );
	if (r && with_len) {
	    assert (prefix->bitlen <= 128);
	    sprintf (buff + strlen (buff), "/%d", prefix->bitlen);
	}
	return (buff);
    }
#endif /* HAVE_IPV6 */
    else
	return (NULL);
}


/*
 * prefix_toa with /length
 */
char *
prefix_toax (prefix_t *prefix)
{
    return (prefix_toa2x (prefix, (char *) NULL, 1));
}

#ifdef notdef
/* prefix_tolong
 * convert prefix information to long
 */
long 
prefix_tolong (prefix_t * prefix)
{
    int l;
    if (prefix == NULL)
	return (0);
    return (prefix->add.sin.s_addr);
}


/* prefix_tochar
 * convert prefix information to bytes
 */
u_char *
prefix_tochar (prefix_t * prefix)
{
    if (prefix == NULL)
	return (NULL);

    return ((u_char *) & prefix->add.sin);
}
#endif

/* prefix_tosockaddr 
 * Takes a prefix and returns a struct sockaddr * with the appropriate
 * address and family type filled in.
 */
struct sockaddr *
prefix_tosockaddr(prefix_t *prefix)
{
    struct sockaddr_in *sockaddr;
#ifdef HAVE_IPV6
    struct sockaddr_in6 *sockaddr6;
#endif

    if (prefix == NULL)
	return (NULL);

    /* If this is an AF_INET prefix (IPv4), return a struct sockaddr_in. */
    if (prefix->family == AF_INET) {

	sockaddr = New(struct sockaddr_in);
	if (!sockaddr)
	    return NULL;

	memset(sockaddr, 0, sizeof(struct sockaddr_in));
	sockaddr->sin_family = AF_INET;
	memcpy(&(sockaddr->sin_addr), &(prefix->add.sin),
		sizeof(sockaddr->sin_addr));
	return ((struct sockaddr *) sockaddr);
    }
#ifdef HAVE_IPV6
    else if (prefix->family == AF_INET6) {

	sockaddr6 = New(struct sockaddr_in6);
	if (!sockaddr6)
	    return NULL;

	memset(sockaddr6, 0, sizeof(struct sockaddr_in6));
	sockaddr6->sin6_family = AF_INET6;
	memcpy(&(prefix->add.sin6), &(sockaddr6->sin6_addr), 
		sizeof(prefix->add.sin6));
	return ((struct sockaddr *) sockaddr6);
    }
#endif
    else
	return NULL;
}

prefix_t *
sockaddr_toprefix (struct sockaddr *sa)
{
    int family;
    prefix_t *prefix = NULL;

    assert (sa);
    if ((family = sa->sa_family) == AF_INET) {
	struct sockaddr_in *sin = (struct sockaddr_in *) sa;
	prefix = New_Prefix (AF_INET, &sin->sin_addr, 32);
    }
#ifdef HAVE_IPV6
    else if (family == AF_INET6) {
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
	if (IN6_IS_ADDR_V4MAPPED (&sin6->sin6_addr))
	    prefix = New_Prefix (AF_INET, ((char *) &sin6->sin6_addr) + 12, 
				 32);
	else
	    prefix = New_Prefix (AF_INET6, &sin6->sin6_addr, 128);
    }
#endif /* HAVE_IPV6 */
    return (prefix);
}

/* prefix_getsockaddrsize
 * Returns the size of the corresponding sockaddr structure.
 * Returns -1 in case of error (unsupported protocol family).
 */
int
prefix_getsockaddrsize (prefix_t *prefix)
{
    if (prefix == NULL)
	return (0);

    if (prefix->family == AF_INET)
	return sizeof(struct sockaddr_in);
#ifdef HAVE_IPV6
    else if (prefix->family == AF_INET6)
	return sizeof(struct sockaddr_in6);
#endif
    else
	return -1;
}

void 
trace_prefix_list (char *msg, trace_t * ltrace, LINKED_LIST * ll_prefix)
{
    char buff[4][MAXLINE];
    prefix_t *prefix = NULL;
    int n = 0;

    if (ll_prefix == NULL)
	return;

    LL_Iterate (ll_prefix, prefix) {
	n++;
	if (n == 4) {
	    sprintf (buff[n - 1], "%s/%d", prefix_toa (prefix),
		prefix->bitlen);
	    trace (TR_PACKET, ltrace, "%s %s %s %s %s\n",
		   msg, buff[0], buff[1], buff[2], buff[3]);
	    n = 0;
	    memset (buff[0], 0, MAXLINE);
	    memset (buff[1], 0, MAXLINE);
	    memset (buff[2], 0, MAXLINE);
	    memset (buff[3], 0, MAXLINE);
	}
	else {
	    sprintf (buff[n - 1], "%s/%d", prefix_toa (prefix),
		prefix->bitlen);
	}
    }

    if (n == 3)
	trace (TR_PACKET, ltrace, "%s %s %s %s\n",
	       msg, buff[0], buff[1], buff[2]);
    else if (n == 2)
	trace (TR_PACKET, ltrace, "%s %s %s\n",
	       msg, buff[0], buff[1]);
    else if (n == 1)
	trace (TR_PACKET, ltrace, "%s %s\n",
	       msg, buff[0]);
}


int
prefix_is_unspecified (prefix_t *prefix)
{
    if (prefix->family == AF_INET)
	return (prefix_tolong (prefix) == INADDR_ANY);
#ifdef HAVE_IPV6
    if (prefix->family == AF_INET6)
	return (IN6_IS_ADDR_UNSPECIFIED (prefix_toaddr6 (prefix)));
#endif /* HAVE_IPV6 */
    assert (0);
    return (0);
}


int
prefix_is_loopback (prefix_t *prefix)
{
    if (prefix->family == AF_INET)
	return (prefix_tolong (prefix) == htonl (0x7f000001));
#ifdef HAVE_IPV6
    if (prefix->family == AF_INET6)
	return (IN6_IS_ADDR_LOOPBACK (prefix_toaddr6 (prefix)));
#endif /* HAVE_IPV6 */
    assert (0);
    return (0);
}


int
prefix_is_v4compat (prefix_t *prefix)
{
#ifdef HAVE_IPV6
    if (prefix->family == AF_INET6)
	return (IN6_IS_ADDR_V4COMPAT (prefix_toaddr6 (prefix)));
#endif /* HAVE_IPV6 */
    return (0);
}


int
prefix_is_v4mapped (prefix_t *prefix)
{
#ifdef HAVE_IPV6
    if (prefix->family == AF_INET6)
	return (IN6_IS_ADDR_V4MAPPED (prefix_toaddr6 (prefix)));
#endif /* HAVE_IPV6 */
    return (0);
}


/* unicast linklocal or multicast linklocal */
int
prefix_is_linklocal (prefix_t *prefix)
{
#ifdef HAVE_IPV6
    if (prefix->family == AF_INET6)
	return (IN6_IS_ADDR_LINKLOCAL (prefix_toaddr6 (prefix)) ||
	        IN6_IS_ADDR_MC_LINKLOCAL (prefix_toaddr6 (prefix)));
#endif /* HAVE_IPV6 */
    return (0);
}


int
prefix_is_sitelocal (prefix_t *prefix)
{
#ifdef HAVE_IPV6
    if (prefix->family == AF_INET6)
	return (IN6_IS_ADDR_SITELOCAL (prefix_toaddr6 (prefix)) ||
	        IN6_IS_ADDR_MC_SITELOCAL (prefix_toaddr6 (prefix)));
#endif /* HAVE_IPV6 */
    return (0);
}


int
prefix_is_multicast (prefix_t *prefix)
{
    if (prefix->family == AF_INET)
        return (IN_MULTICAST (ntohl (prefix_tolong (prefix))));
#ifdef HAVE_IPV6
    if (prefix->family == AF_INET6)
        return (IN6_IS_ADDR_MULTICAST (prefix_toaddr6 (prefix)));
#endif /* HAVE_IPV6 */
    assert (0);
    return (0);
}


int
prefix_is_global (prefix_t *prefix)
{
    return (!prefix_is_unspecified (prefix) &&
	    !prefix_is_loopback (prefix) &&
	    !prefix_is_v4compat (prefix) &&
	    !prefix_is_v4mapped (prefix) &&
	    !prefix_is_sitelocal (prefix) &&
	    !prefix_is_linklocal (prefix));
}


/* unicast sitelocal or multicast sitelocal */

#ifdef HAVE_IPV6

int 
ipv6_global_unicast_addr (struct in6_addr *sin6)
{
    assert (sin6);

    return ((sin6->s6_addr[0] & 0xe0) == 0x04 ||
	    (sin6->s6_addr[0] & 0xe0) == 0x08);
}

int 
ipv6_multicast_addr (struct in6_addr *sin6)
{

    struct in6_addr zero;
    assert (sin6);

    zero.s6_addr[0] = 0xff;
    return (comp_with_mask ((char *) &zero, (char *) sin6, 8));
}

int 
ipv6_link_local_addr (struct in6_addr *sin6)
{

    struct in6_addr zero;

    assert (sin6);
    zero.s6_addr[0] = 0xfe;
    zero.s6_addr[1] = 0x80;

    return (comp_with_mask ((char *) &zero, (char *) sin6, 10));
}

int 
ipv6_ipv4_addr (struct in6_addr *sin6)
{

    struct in6_addr zero;

    assert (sin6);
    memset (&zero, 0, 12);
    zero.s6_addr[10] = 0xff;
    zero.s6_addr[11] = 0xff;
    return (comp_with_mask ((char *) &zero, (char *) sin6, 96));
}

int 
ipv6_compat_addr (struct in6_addr *sin6)
{

    struct in6_addr zero;

    assert (sin6);
    memset (&zero, 0, 12);
    return (comp_with_mask ((char *) &zero, (char *) sin6, 96));
}

int 
ipv6_any_addr (struct in6_addr *sin6)
{

    struct in6_addr zero;

    assert (sin6);
    memset (&zero, 0, 16);
    return (comp_with_mask ((char *) &zero, (char *) sin6, 128));
}

#endif /* HAVE_IPV6 */

u_char *
netmasking (int family, void *vaddr, u_int bitlen)
{
    u_char *addr = vaddr;

    if (family == AF_INET) {
	assert (0 <= bitlen && bitlen <= 32);
	if (bitlen == 32)
	    return (addr);
	memset (addr + (bitlen + 7) / 8, 0, 4 - (bitlen + 7) / 8);
	addr[bitlen / 8] &= (0xff00 >> (bitlen % 8));
    }
#ifdef HAVE_IPV6
    else if (family == AF_INET6) {
	assert (0 <= bitlen && bitlen <= 128);
	if (bitlen == 128)
	    return (addr);
	memset (addr + (bitlen + 7) / 8, 0, 16 - (bitlen + 7) / 8);
	addr[bitlen / 8] &= (0xff00 >> (bitlen % 8));
    }
#endif /* HAVE_IPV6 */
    else
	assert (0);
    return (addr);
}


int 
comp_with_mask (void *addr, void *dest, u_int mask)
{

    if ( /* mask/8 == 0 || */ memcmp (addr, dest, mask / 8) == 0) {
	int n = mask / 8;
	int m = ((-1) << (8 - (mask % 8)));

	if (mask % 8 == 0 || (((u_char *)addr)[n] & m) == (((u_char *)dest)[n] & m))
	    return (1);
    }
    return (0);
}


int 
byte_compare (void *addr, void *dest, int bits, void *wildcard)
{
    int bytelen = bits / 8;
    int bitlen = bits % 8;
    int i, m;
    static u_char zeros[16];

    if (wildcard == NULL)
	wildcard = zeros;

    for (i = 0; i < bytelen; i++) {
        if ((((u_char *)addr)[i] | ((u_char *)wildcard)[i]) !=
            (((u_char *)dest)[i] | ((u_char *)wildcard)[i]))
	    return (0);
    }

    if (bitlen == 0)
	return (1);

    m = (~0 << (8 - bitlen));
    if (((((u_char *)addr)[i] | ((u_char *)wildcard)[i]) & m) !=
        ((((u_char *)dest)[i] | ((u_char *)wildcard)[i]) & m))
            return (0);

    return (1);
}


#if !defined(HAVE_INET_NTOP) 
#if defined(HAVE_ADDR2ASCII)
/* 
 * mrt uses inet_ntop() defined in RFC 2133.  * At least, BIND 4.9.5 has
 * the expected version of inet_ntop() in its library (libresolv.a).
 * If these are not available, the following wrappers call existing address
 * conversion routines.
 */

const char *
inet_ntop (int af, const void *src, char *dst, size_t size)
{
    return (addr2ascii (af, src, (af == AF_INET) ? 4 : 16, dst));
}

int 
inet_pton (int af, const char *src, void *dst)
{
    return (ascii2addr (af, src, dst));
}
#else	/* don't have ADDR2ASCII */
/* inet_ntop substitute implementation
 * uses inet_ntoa to convert IPv4 address to string; can't support IPv6.
 * If the dst buffer is too small to hold the result, the answer is
 * truncated and a NULL is returned with errno set to ENOSPC.
 * The man page reports that inet_ntoa uses thread-local static storage
 * for the returned string, so this function should be thread safe.
 */
const char *
inet_ntop (int af, const void *src, char *dst, size_t size)
{
    char *buf;
    struct in_addr in;
    int len;

    /* We can only support IPv4 packets */
    if (af == AF_INET) {
		memcpy (&in, src,4);
		buf = inet_ntoa(in);

		/* Check length of returned answer and truncate if necessary */
		len = strlen(buf) + 1;
		memcpy(dst, buf, (size < len) ? size : len);

		/* Null terminate dst buffer if necessary */
		if (size < len) {
			dst[size-1] = 0;
			errno = ENOSPC;
			return NULL;
		} else
			return dst;
	}

#ifdef NT 
#ifdef HAVE_IPV6
	else if (af == AF_INET6) {
		struct in6_addr Address;	
		memcpy (&Address, src, sizeof (Address));
		buf = inet6_ntoa (&Address);

		/* Check length of returned answer and truncate if necessary */
		len = strlen(buf) + 1;
		memcpy(dst, buf, (size < len) ? size :len);

		/* Null terminate dst buffer if necessary */
		if (size < len) {
		    dst[size-1] = 0;
		    errno = ENOSPC;
		    return NULL;
		} else
			return dst;
	}
#endif /* HAVE_IPV6 */
#endif /* NT */

 
#ifndef NT
	errno = EAFNOSUPPORT;
#endif /* NT */

	return NULL;
  
}

void sdsdds () {

}

/* inet_pton substitute implementation
 * Uses inet_addr to convert an IP address in dotted decimal notation into 
 * unsigned long and copies the result to dst.
 * Only supports AF_INET.  Follows standard error return conventions of 
 * inet_pton.
 */
int
inet_pton (int af, const char *src, void *dst)
{
    u_long result;  

    if (af == AF_INET) {
	result = inet_addr(src);
	if (result == -1)
	    return 0;
	else {
			memcpy (dst, &result, 4);
	    return 1;
		}
	}
#ifdef NT
#ifdef HAVE_IPV6
	else if (af == AF_INET6) {
		struct in6_addr Address;
		return (inet6_addr(src, &Address));
	}
#endif /* HAVE_IPV6 */
#endif /* NT */
#ifndef NT
    else {

	errno = EAFNOSUPPORT;
	return -1;
    }
#endif /* NT */
}

#endif /* if defined(HAVE_ADDR2ASCII) */
#endif /* if !defined(HAVE_INET_NTOP) */


/* this allows imcomplete prefix */
int
my_inet_pton (int af, const char *src, void *dst)
{
    if (af == AF_INET) {
        int i, c, val;
        u_char xp[4] = {0, 0, 0, 0};

        for (i = 0; ; i++) {
	    c = *src++;
	    if (!isdigit (c))
		return (-1);
	    val = 0;
	    do {
		val = val * 10 + c - '0';
		if (val > 255)
		    return (0);
		c = *src++;
	    } while (c && isdigit (c));
            xp[i] = val;
	    if (c == '\0')
		break;
            if (c != '.')
                return (0);
	    if (i >= 3)
		return (0);
        }
	memcpy (dst, xp, 4);
        return (1);
#ifdef HAVE_IPV6
    } else if (af == AF_INET6) {
        return (inet_pton (af, src, dst));
#endif /* HAVE_IPV6 */
    } else {
#ifndef NT
	errno = EAFNOSUPPORT;
#endif /* NT */
	return -1;
    }
}


char *
family2string (int family)
{
#ifdef HAVE_IPV6
    if (family == AF_INET6)
        return ("inet6");
#endif /* HAVE_IPV6 */
    if (family == AF_INET)
        return ("inet");
    return ("???");
}

/*
 * returns 1 if the prefix is any address (all 0s)
 * don't care about the prefix's length
 */
int
is_any_addr (prefix_t *prefix)
{
    int bytes = 4;
    char zero[16];

#ifdef HAVE_IPV6
    if (prefix->family == AF_INET6)
	bytes = 16;
#endif /* HAVE_IPV6 */

    memset (zero, 0, bytes);
    return (memcmp (zero, prefix_tochar (prefix), bytes) == 0);
}



#ifdef notdef
/* is_prefix
 * Scan string and check if this looks like a prefix. Return 1 if prefix,
 * 0 otherwise
 */
int is_ipv4_prefix (char *string) {
  char *cp, *last, *prefix, *len, *copy;
  int octet = 0;

  copy = strdup (string);
  cp = strtok_r (copy, "/", &last);
  prefix = cp;

  if ((cp != NULL) && ((len = strtok_r (NULL, "/", &last)) != NULL)) {
    if ((atoi (len) < 0) || (atoi (len) > 32)) {
      Delete (copy);
      return (-1);
    }
  }

  cp = strtok_r (prefix, ".", &last);
  
  while (cp != NULL) {
    octet++;
    if ((atoi (cp) < 0) || (atoi (cp) > 255)) {Delete (copy); return (-1);}
    cp = strtok_r (NULL, ".", &last);
  }

  if ((octet > 4) || (octet <= 0)) {Delete (copy); return (-1);}

  Delete (copy);
  return (1);
}
#else
/*
 * it's difficult to make sure that the above code works correctly.
 * instead, I'll take an easy way as follows: -- masaki
 */
int is_ipv4_prefix (char *string) {

  u_char dst[4];
  char *p, save[MAXLINE];

  if ((p = strchr (string, '/')) != NULL) {
      strcpy (save, string);
      save [p - string] = '\0';
      string = save;
  }
  return (my_inet_pton (AF_INET, string, dst) > 0);
}
#endif


#ifdef HAVE_IPV6
/* is_prefix
 * ask inet_pton() to see if this looks like a prefix. Return 1 if prefix,
 * 0 otherwise
 */
int is_ipv6_prefix (char *string) {

  u_char dst[16];
  char *p, save[MAXLINE];

  if ((p = strchr (string, '/')) != NULL) {
      strcpy (save, string);
      save [p - string] = '\0';
      string = save;
  }
  return (inet_pton (AF_INET6, string, dst) > 0);
}
#endif /* HAVE_IPV6 */


/* long_inet_ntoa
 * just for convenience -- I often don't want to bother converting longs
 * to prefixes or sockaddrs just to print out
 */
char *long_inet_ntoa (u_long addr) {
  struct in_addr in;

  memcpy (&in, &addr, 4);
  return (inet_ntoa (in));
}

/* add2group is used by my_inet_pton6 */
#define add2group(a,b,c) a->s6_addr[c*2+1] = b & 0xff; a->s6_addr[c*2] = b >> 8;c++;

#if 0
void add2group(struct in6_addr *sin6, long group, int grpcnt) {
  sin6->s6_addr[grpcnt*2+1] = group & 0xff;
  sin6->s6_addr[grpcnt*2]   = group >> 8;
  grpcnt++;
} 
#endif

#ifdef HAVE_IPV6
/* my_inet_pton6 - converts an ipv6 string to an ipv6 address */
int my_inet_pton6(int family, const char *string, struct in6_addr *sin6) {
  int grpcnt, poscnt;
  long group;
  int done = 0, coloncount = 0, doublecolon = 0;
  int mask, i;
  const char *c, *d;
  char x = 0;
 
  memset(sin6, 0, 16);
 
/* The sequence of checking:
a.      is it a NULL? if so, stuff existing values, and return.
b.      ELSE is it a slash? If so, add group in register, and AND the
                appropriate bits, and return.
c.      ELSE is it a colon? if so, stuff the current 4-byte value into
                the current field, update the new field pointer, and inc
                the char ptr
                if the next char is a colon, test to make sure that it's
                legal (right number of fields), that there wasn't
                a previous double colon, etc. If everything's legal,
                adjust the group number by counting the number of remaining
                colons
d.      ELSE error if it's not hex
                error if it's more than the fourth number without a colon
                update the numbercount, shift the current holding
                value by 4, add in the new number
e.      goto a
 
        0123:4567::89ab:cdef
         ^      ^
	 |      +-- group 1, count 3
	 +--------- group 0, count 1
*/

  c = string;
  grpcnt = 0; poscnt = 0; group = 0;
  while (!done) { 
    if (*c == '\0') {                   /* state a */
      add2group(sin6, group, grpcnt);
      return 0;

    } else if (*c == '/') {             /* state b */
      add2group(sin6, group, grpcnt);
      mask = atof(++c); /* Note that this ignores any other garbage */
      poscnt = 8 - (mask % 8); grpcnt = mask >>3;
      for (i = grpcnt + 1; i <= 16; i++) {
	sin6->s6_addr[i] = 0;
      }
      sin6->s6_addr[grpcnt] &= ~((1 << poscnt) - 1);
      return 0;

    } else if (*c == ':') {             /* state c */
      add2group(sin6, group, grpcnt);
      group = 0;
      poscnt = 0;
      c++;

      /* check for double colon, and do zero filling, and group advancement */
      
      if (*c == ':') { /* double colon time */
	if (doublecolon++) return(-1); /* No more than one double colon! */
        c++;
	for (d = c; !(*d == 0 || *d == '/'); d++) {
          if (*d == ':') coloncount++;
        }
	if ((grpcnt + coloncount) >= 8) return(-1); /* Too many fields! */

        grpcnt = (7 - coloncount);
	/* printf("colons found %d; grpcnt now %d.\n",coloncount, grpcnt); */
      }

    } else {                            /* state d */
      switch (*c) {
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
          x = *c - '0';
          break;
        case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
          x = *c - 'A' + 10;
          break;
        case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
          x = *c - 'a' + 10;
          break;
        default:
          return(-1); /* ERROR! */      /* stage d1 */
      } /* switch */

      if (poscnt++ > 3) {               /* state d2 */
        return (-1); /* Whoops, too many numbers between colons. */
      }

      group <<= 4;                      /* state d3 */
      group |= x;
      c++;                              /* and now, the cycle starts again */
    }
  } /* !done */
  
  /* NOTREACHED */
  return 0;
}
#endif /* HAVE_IPV6 */
 

int
gen_hash_fn (prefix_t * prefix, int size)
{
#ifdef HAVE_IPV6
    if (prefix->family == AF_INET6) {
	u_int val, buff[4];
	memcpy (buff, prefix_toaddr6 (prefix), 16);
	netmasking (prefix->family, (char *) buff, prefix->bitlen);
	/* Pedro's suggestion */
	val = buff[0] ^ buff[1] ^ buff[2] ^ buff[3];
	val ^= (val >> 16);
	val = val % size;
	return (val);
    }
    else
#endif /* HAVE_IPV6 */
    if (prefix->family == AF_INET) {
	u_int val;
	u_char dest[4];
	memcpy (dest, prefix_tochar (prefix), 4);
	netmasking (prefix->family, dest, prefix->bitlen);
	val = dest[0] + dest[1] + dest[2] + dest[3];
	val = val % size;
	return (val);
    }
    else {
	assert (0);
    }
    /* NEVER REACHES */
    return (0);
}


int
gen_lookup_fn (prefix_t * a, prefix_t * b)
{
    return (prefix_compare (a, b));
}


#ifdef NT
/* convert address to text */
inet_ntop (int af, const void *src, char *dst, size_t size) {
	struct in6_addr *addr6;
	struct in_addr *addr4;
	struct sockaddr_in6 sin6;
	struct sockaddr_in sin4;

	if (af == AF_INET6) {
		addr6 = (struct in6_addr *) src;
		memset(&sin6, 0, sizeof(struct sockaddr_in6));
		memcpy (&sin6.sin6_addr, addr6, sizeof (struct in6_addr));
		sin6.sin6_family = AF_INET6;
	
		memset (dst, 0, size);
		getnameinfo((struct sockaddr *)&sin6, sizeof (struct sockaddr_in6),
			dst, size, NULL, 0, NI_NUMERICHOST);

		return (dst);
	}
	else {
		addr4 = (struct in_addr *) src;
		memset(&sin4, 0, sizeof(struct sockaddr_in));
		memcpy (&sin4.sin_addr, addr4, sizeof (addr4));
		sin4.sin_family = AF_INET;
	
		getnameinfo ((struct sockaddr *)&sin4, sizeof (struct sockaddr_in),
			dst, size, NULL, 0, NI_NUMERICHOST);

		return (dst);
	}
}



/* convert text to address */
int inet_pton (int af, char *src, void *dst) {
	int error;
	struct addrinfo hints;
	struct addrinfo *res;
	struct sockaddr_in6 *sin6;
	struct sockaddr_in  *sin4;	

	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = af;
	hints.ai_flags = AI_NUMERICHOST;
	res = NULL;
	error = getaddrinfo(src, NULL, &hints, &res);

	if (error != 0)
		return (-1);

	if (af == AF_INET6) {
		//return (my_inet_pton6(af, src, (struct in6_addr *) dst));
		sin6 = (struct sockaddr_in6 *) res->ai_addr;
		memcpy (dst, &sin6->sin6_addr, sizeof (struct in6_addr));
		freeaddrinfo (res);
	}
	else {
		sin4 = (struct sockaddr_in *) res->ai_addr;
		memcpy (dst, &sin4->sin_addr, sizeof (struct in_addr));	
	}

	return (1);
}


#endif /* NT */
