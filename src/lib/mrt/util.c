/*
 * $Id: util.c,v 1.1.1.1 2000/08/14 18:46:12 labovit Exp $
 */

#include <mrt.h>


/* r_inet_ntoa
 * A thread safe (and IPNG) version of inet_ntoa
 * takes allocated buffer and buffer size
 */
char *r_inet_ntoa (char *buf, int n, u_char *l, int len)
{
  memset (buf, 0, n);

  /*ASSERT ( (len >= 0) && (len < 255));*/

   if (len > 24)
      sprintf(buf, "%d.%d.%d.%d/%d", l[0], l[1], l[2], l[3], len);
   else if (len > 16)
      sprintf(buf, "%d.%d.%d/%d", l[0], l[1], l[2], len);
   else if (len > 8)
      sprintf(buf, "%d.%d/%d", l[0], l[1], len);
   else 
      sprintf(buf, "%d/%d", l[0], len);

   return (buf);
}

/* 
 * A thread safe (and IPNG) version of inet_ntoa
 * takes allocated buffer and buffer size
 * this doesn't append /length
 */
char *r_inet_ntoa2 (char *buf, int n, u_char *l)
{
   sprintf(buf, "%d.%d.%d.%d", l[0], l[1], l[2], l[3]);
   return (buf);
}

/* r_inet_ntoa
 * A thread safe (and IPNG) version of inet_ntoa
 * takes allocated buffer and buffer size
 */
char *rinet_ntoa (char *buf, int n, prefix_t *prefix)
{
  int len = prefix->bitlen;
  u_char *l = (u_char *) prefix_tochar (prefix);
  memset (buf, 0, n);

  /*ASSERT ( (len >= 0) && (len < 255));*/

   if (len > 24)
      sprintf(buf, "%d.%d.%d.%d/%d", l[0], l[1], l[2], l[3], len);
   else if (len > 16)
      sprintf(buf, "%d.%d.%d/%d", l[0], l[1], l[2], len);
   else if (len > 8)
      sprintf(buf, "%d.%d/%d", l[0], l[1], len);
   else 
      sprintf(buf, "%d/%d", l[0], len);

   return (buf);
}

char *my_inet_ntoa_simple (u_char *l, int len)
{
   static char tmp[100];
   memset (tmp, 0, 100);

   /*   ASSERT ( (len >= 0) && (len < 255));*/

   if (len > 24)
      sprintf(tmp, "%d.%d.%d.%d", l[0], l[1], l[2], l[3]);
   else if (len > 16)
      sprintf(tmp, "%d.%d.%d", l[0], l[1], l[2]);
   else if (len > 8)
      sprintf(tmp, "%d.%d", l[0], l[1]);
   else 
      sprintf(tmp, "%d", l[0]);

   return (tmp);
}


/*-----------------------------------------------------------
 *  Name: 	my_atoi
 *  Created:	Wed Oct 26 00:04:36 1994
 *  Author: 	Laurent Joncheray <lpj@merit.edu>
 *  DESCR:  	
 */

int my_atoi(str, i)
        char *str;
        int *i;
{
        for(*i = 0; *str; str++) {
                if (!isdigit(*str))
                        return(0);
                *i = *i * 10 + ((int)*str - 0x30);
        }
	if ( (*i < 0) || (*i > 255))
	   return (0);
        return(1);
}



/*-----------------------------------------------------------
 *  Name: 	atox
 *  Created:	Tue Nov 26 20:32:23 EST 1996
 *  Author: 	Masaki Hirabaru <masaki@merit.edu>
 *  DESCR:  	Hex string into binary
 */

int atox(str)
        char *str;
{
	int x = 0;

        for(; *str; str++) {
		int c = toupper (*str);

                if (isdigit(c)) {
			x = x * 16 + c - '0';
		}
		else if (c >= 'A' && c <= 'F') {
			x = x * 16 + c - 'A' + 10;
		}
		else {
                        return(x);
		}
        }
        return(x);
}



  
/*-----------------------------------------------------------
 *  Name: 	my_strftime
 *  Created:	Mon Dec 19 14:15:42 1994
 *  Author: 	Craig Labovitz   <labovit@snoopy.merit.net>
 *  DESCR:  	Given a time long and format, return string. 
 *		If time <=0, use current time of day
 */

char *my_strftime(long in_time, char *fmt)
{
   char *tmp = NewArray (char, MAXLINE);
   long t;
   struct tm *tm;

   if (in_time <= 0)
      t = time (NULL);
   else
      t = in_time;

   tm = localtime(&t);

   strftime (tmp, MAXLINE, fmt, tm);
   return (tmp);
}


/*
 * returns pointer to a token
 * line, a pointer of pointer to the string will be updated to the next position
 * word is a strage for the token
 * if word == NULL, it will be dynamically allocated by malloc
 */

char *
uii_parse_line2 (char **line, char *word)
{
    char *cp = *line, *start;
    int len;

    /* skip spaces */
    while (*cp && isspace (*cp))
	cp++;

    start = cp;
    while (!isspace (*cp) && (*cp != '\0') && (*cp != '\n'))
	cp++;

    if ((len = cp - start) > 0) {
	if (word == NULL) {
	    word = NewArray (char, len + 1);
	    assert (word);
	}
	memcpy (word, start, len);
	word[len] = '\0';
	*line = cp;
	return (word);
    }

    return (NULL);
}


char *
time2date (int elapsed, char *date)
{
    if (elapsed < 0) {
	    sprintf (date, "--:--:--");
    }
    else {
	if (elapsed / 3600 > 99)
	    sprintf (date, "%02ddy%02dhr", 
			   elapsed / (3600 * 24), 
			   (elapsed % (3600 * 24)) / 3600);
	else
	    sprintf (date, "%02d:%02d:%02d", 
			   elapsed / 3600, (elapsed / 60) % 60, elapsed % 60);
    }
    return (date);
}


char *
safestrncpy (char *dest, const char *src, size_t n)
{
    strncpy (dest, src, n);
    dest[n - 1] = '\0';
    return (dest);
}


char * 
etime2ascii (time_t elapsed, char *date)
{
    if (elapsed < 0)
        sprintf (date, "--:--:--");
    if (elapsed/3600 > 99)  
        sprintf (date, "%02lddy%02ldhr",
                 elapsed/(3600*24), (elapsed%(3600*24))/3600);
    else
        sprintf (date, "%02ld:%02ld:%02ld",
                 elapsed/3600, (elapsed/60)%60, elapsed%60);
    return (date);
}   


u_long
strtoul10 (char *nptr, char **endptr)
{
    u_long value = 0;

    while (isdigit (*nptr))
	value = value * 10 + *nptr++ - '0';
    if (*nptr == ':') {
	u_long value2 = 0;
	nptr++;
        while (isdigit (*nptr))
	    value2 = value2 * 10 + *nptr++ - '0';
	value = (value << 16) + value2;
    }
    if (endptr)
	*endptr = nptr;
    return (value);
}
