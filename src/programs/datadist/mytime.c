/* some systems (e.g. Solaris 2.5, and, I believe, glibc 1) have mktime 
   implementations that are not thread-safe. this alternative (adapted from
	NetBSD's libc) should be. */

#if defined(_REENTRANT)
#include "mytime.h"

#define P(x) x

#ifndef TRUE
	#define TRUE 1
#endif

#ifndef FALSE
	#define FALSE 0
#endif

/*
   Extracted and adapated from libc/time/localtime.c in the NetBSD 
	source tree.
   (quichem) 
*/

/*
** This file is in the public domain, so clarified as of
** June 5, 1996 by Arthur David Olson (arthur_david_olson@nih.gov).
*/
/*
** Leap second handling from Bradley White (bww@k.gp.cs.cmu.edu).
** POSIX-style TZ environment variable handling from Guy Harris
** (guy@auspex.com).
*/

#include "fcntl.h"

struct ttinfo {                         /* time type information */
        long            tt_gmtoff;      /* GMT offset in seconds */
        int             tt_isdst;       /* used to set tm_isdst */
        int             tt_abbrind;     /* abbreviation list index */
        int             tt_ttisstd;     /* TRUE if transition is std time */
        int             tt_ttisgmt;     /* TRUE if transition is GMT */
};

struct lsinfo {                         /* leap second information */
        time_t          ls_trans;       /* transition time */
        long            ls_corr;        /* correction to apply */
};

#define BIGGEST(a, b)   (((a) > (b)) ? (a) : (b))

struct state {
        int             leapcnt;
        int             timecnt;
        int             typecnt;
        int             charcnt;
        time_t          ats[TZ_MAX_TIMES];
        unsigned char   types[TZ_MAX_TIMES];
        struct ttinfo   ttis[TZ_MAX_TYPES];
        struct lsinfo   lsis[TZ_MAX_LEAPS];
};


/*
** Prototypes for static functions.
*/

static void             localsub P((const time_t * timep, long offset,
                                struct tm * tmp));
static int              increment_overflow P((int * number, int delta));
static int              normalize_overflow P((int * tensptr, int * unitsptr,
                                int base));
static time_t           time1 P((struct tm * tmp,
                                void(*funcp) P((const time_t *,
                                long, struct tm *)),
                                long offset));
static time_t           time2 P((struct tm *tmp,
                                void(*funcp) P((const time_t *,
                                long, struct tm*)),
                                long offset, int * okayp));
static int              tmcomp P((const struct tm * atmp,
                                const struct tm * btmp));

#ifdef ALL_STATE
static struct state *   lclptr;
static struct state *   gmtptr;
#endif /* defined ALL_STATE */

#ifndef ALL_STATE
static struct state     lclmem;
static struct state     gmtmem;
#define lclptr          (&lclmem)
#define gmtptr          (&gmtmem)
#endif /* State Farm */

static const int        mon_lengths[2][MONSPERYEAR] = {
        { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 },
        { 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
};

static const int        year_lengths[2] = {
        DAYSPERNYEAR, DAYSPERLYEAR
};

/*
** The easy way to behave "as if no library function calls" localtime
** is to not call it--so we drop its guts into "localsub", which can be
** freely called.  (And no, the PANS doesn't require the above behavior--
** but it *is* desirable.)
**
** The unused offset argument is for the benefit of mktime variants.
*/


void localsub(const time_t * const timep, const long offset, struct tm *
const tmp) {
	localtime_r(timep, tmp);
}

/*
** Adapted from code provided by Robert Elz, who writes:
**      The "best" way to do mktime I think is based on an idea of Bob
**      Kridle's (so its said...) from a long time ago.
**      [kridle@xinet.com as of 1996-01-16.]
**      It does a binary search of the time_t space.  Since time_t's are
**      just 32 bits, its a max of 32 iterations (even at 64 bits it
**      would still be very reasonable).
*/

#ifndef WRONG
#define WRONG   (-1)
#endif /* !defined WRONG */

/*
** Simplified normalize logic courtesy Paul Eggert (eggert@twinsun.com).
*/

static int
increment_overflow(number, delta)
int *   number;
int     delta;
{
        int     number0;

        number0 = *number;
        *number += delta;
        return (*number < number0) != (delta < 0);
}

static int
normalize_overflow(tensptr, unitsptr, base)
int * const     tensptr;
int * const     unitsptr;
const int       base;
{
        register int    tensdelta;

        tensdelta = (*unitsptr >= 0) ?
                (*unitsptr / base) :
                (-1 - (-1 - *unitsptr) / base);
        *unitsptr -= tensdelta * base;
        return increment_overflow(tensptr, tensdelta);
}

static int
tmcomp(atmp, btmp)
register const struct tm * const atmp;
register const struct tm * const btmp;
{
        register int    result;

        if ((result = (atmp->tm_year - btmp->tm_year)) == 0 &&
                (result = (atmp->tm_mon - btmp->tm_mon)) == 0 &&
                (result = (atmp->tm_mday - btmp->tm_mday)) == 0 &&
                (result = (atmp->tm_hour - btmp->tm_hour)) == 0 &&
                (result = (atmp->tm_min - btmp->tm_min)) == 0)
                        result = atmp->tm_sec - btmp->tm_sec;
        return result;
}

#define CHAR_BIT (sizeof(char)*8)
#define TYPE_BIT(type)	(sizeof (type) * CHAR_BIT)
#define TYPE_SIGNED(type) (((type) -1) < 0)

static time_t
time2(tmp, funcp, offset, okayp)
struct tm * const       tmp;
void (* const           funcp) P((const time_t*, long, struct tm*));
const long              offset;
int * const             okayp;
{
        register const struct state *   sp;
        register int                    dir;
        register int                    bits;
        register int                    i, j ;
        register int                    saved_seconds;
        time_t                          newt;
        time_t                          t;
        struct tm                       yourtm, mytm;

        *okayp = FALSE;
        yourtm = *tmp;
        if (normalize_overflow(&yourtm.tm_hour, &yourtm.tm_min, MINSPERHOUR))
                return WRONG;
        if (normalize_overflow(&yourtm.tm_mday, &yourtm.tm_hour, HOURSPERDAY))
                return WRONG;
        if (normalize_overflow(&yourtm.tm_year, &yourtm.tm_mon, MONSPERYEAR))
                return WRONG;
        /*
        ** Turn yourtm.tm_year into an actual year number for now.
        ** It is converted back to an offset from TM_YEAR_BASE later.
        */
        if (increment_overflow(&yourtm.tm_year, TM_YEAR_BASE))
                return WRONG;
        while (yourtm.tm_mday <= 0) {
                if (increment_overflow(&yourtm.tm_year, -1))
                        return WRONG;
                i = yourtm.tm_year + (1 < yourtm.tm_mon);
                yourtm.tm_mday += year_lengths[isleap(i)];
        }
        while (yourtm.tm_mday > DAYSPERLYEAR) {
                i = yourtm.tm_year + (1 < yourtm.tm_mon);
                yourtm.tm_mday -= year_lengths[isleap(i)];
                if (increment_overflow(&yourtm.tm_year, 1))
                        return WRONG;
        }
        for ( ; ; ) {
                i = mon_lengths[isleap(yourtm.tm_year)][yourtm.tm_mon];
                if (yourtm.tm_mday <= i)
                        break;
                yourtm.tm_mday -= i;
                if (++yourtm.tm_mon >= MONSPERYEAR) {
                        yourtm.tm_mon = 0;
                        if (increment_overflow(&yourtm.tm_year, 1))
                                return WRONG;
                }
        }
        if (increment_overflow(&yourtm.tm_year, -TM_YEAR_BASE))
                return WRONG;
        if (yourtm.tm_year + TM_YEAR_BASE < EPOCH_YEAR) {
                /*
                ** We can't set tm_sec to 0, because that might push the
                ** time below the minimum representable time.
                ** Set tm_sec to 59 instead.
                ** This assumes that the minimum representable time is
                ** not in the same minute that a leap second was deleted from,
                ** which is a safer assumption than using 58 would be.
                */
                if (increment_overflow(&yourtm.tm_sec, 1 - SECSPERMIN))
                        return WRONG;
                saved_seconds = yourtm.tm_sec;
                yourtm.tm_sec = SECSPERMIN - 1;
        } else {
                saved_seconds = yourtm.tm_sec;
                yourtm.tm_sec = 0;
        }
        /*
        ** Divide the search space in half
        ** (this works whether time_t is signed or unsigned).
        */
        bits = TYPE_BIT(time_t) - 1;
        /*
        ** If time_t is signed, then 0 is just above the median,
        ** assuming two's complement arithmetic.
        ** If time_t is unsigned, then (1 << bits) is just above the median.
        */
        t = TYPE_SIGNED(time_t) ? 0 : (((time_t) 1) << bits);
        for ( ; ; ) {
                (*funcp)(&t, offset, &mytm);
                dir = tmcomp(&mytm, &yourtm);
                if (dir != 0) {
                        if (bits-- < 0)
                                return WRONG;
                        if (bits < 0)
                                --t; /* may be needed if new t is minimal */
                        else if (dir > 0)
                                t -= ((time_t) 1) << bits;
                        else    t += ((time_t) 1) << bits;
                        continue;
                }
                if (yourtm.tm_isdst < 0 || mytm.tm_isdst == yourtm.tm_isdst)
                        break;
                /*
                ** Right time, wrong type.
                ** Hunt for right time, right type.
                ** It's okay to guess wrong since the guess
                ** gets checked.
                */
                /*
                ** The (void *) casts are the benefit of SunOS 3.3 on Sun 2's.
                */
                sp = (const struct state *)
                        (((void *) funcp == (void *) localsub) ?
                        lclptr : gmtptr);
#ifdef ALL_STATE
                if (sp == NULL)
                        return WRONG;
#endif /* defined ALL_STATE */
                for (i = sp->typecnt - 1; i >= 0; --i) {
                        if (sp->ttis[i].tt_isdst != yourtm.tm_isdst)
                                continue;
                        for (j = sp->typecnt - 1; j >= 0; --j) {
                                if (sp->ttis[j].tt_isdst == yourtm.tm_isdst)
                                        continue;
                                newt = t + sp->ttis[j].tt_gmtoff -
                                        sp->ttis[i].tt_gmtoff;
                                (*funcp)(&newt, offset, &mytm);
                                if (tmcomp(&mytm, &yourtm) != 0)
                                        continue;
                                if (mytm.tm_isdst != yourtm.tm_isdst)
                                        continue;
                                /*
                                ** We have a match.
                                */
                                t = newt;
                                goto label;
                        }
                }
                return WRONG;
        }
label:
        newt = t + saved_seconds;
        if ((newt < t) != (saved_seconds < 0))
                return WRONG;
        t = newt;
        (*funcp)(&t, offset, tmp);
        *okayp = TRUE;
        return t;
}

static time_t
time1(tmp, funcp, offset)
struct tm * const       tmp;
void (* const           funcp) P((const time_t *, long, struct tm *));
const long              offset;
{
        register time_t                 t;
        register const struct state *   sp;
        register int                    samei, otheri;
        int                             okay;

        if (tmp->tm_isdst > 1)
                tmp->tm_isdst = 1;
        t = time2(tmp, funcp, offset, &okay);
#ifdef PCTS
        /*
        ** PCTS code courtesy Grant Sullivan (grant@osf.org).
        */
        if (okay)
                return t;
        if (tmp->tm_isdst < 0)
                tmp->tm_isdst = 0;      /* reset to std and try again */
#endif /* defined PCTS */
#ifndef PCTS
        if (okay || tmp->tm_isdst < 0)
                return t;
#endif /* !defined PCTS */
        /*
        ** We're supposed to assume that somebody took a time of one type
        ** and did some math on it that yielded a "struct tm" that's bad.
        ** We try to divine the type they started from and adjust to the
        ** type they need.
        */
        /*
        ** The (void *) casts are the benefit of SunOS 3.3 on Sun 2's.
        */
        sp = (const struct state *) (((void *) funcp == (void *) localsub) ?
                lclptr : gmtptr);
#ifdef ALL_STATE
        if (sp == NULL)
                return WRONG;
#endif /* defined ALL_STATE */
        for (samei = sp->typecnt - 1; samei >= 0; --samei) {
                if (sp->ttis[samei].tt_isdst != tmp->tm_isdst)
                        continue;
                for (otheri = sp->typecnt - 1; otheri >= 0; --otheri) {
                        if (sp->ttis[otheri].tt_isdst == tmp->tm_isdst)
                                continue;
                        tmp->tm_sec += sp->ttis[otheri].tt_gmtoff -
                                        sp->ttis[samei].tt_gmtoff;
                        tmp->tm_isdst = !tmp->tm_isdst;
                        t = time2(tmp, funcp, offset, &okay);
                        if (okay)
                                return t;
                        tmp->tm_sec -= sp->ttis[otheri].tt_gmtoff -
                                        sp->ttis[samei].tt_gmtoff;
                        tmp->tm_isdst = !tmp->tm_isdst;
                }
        }
        return WRONG;
}

time_t
mktime_r(tmp)
struct tm * const       tmp;
{
        return time1(tmp, localsub, 0L);
}
#endif	/* _REENTRANT */
