/*
 * $Id: compat.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <sys/types.h>
#ifndef NT
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#endif /* NT */
#include <config.h>

#ifndef HAVE_MEMMOVE
char *
memmove (char *dest, const char *src, size_t n)
{

    if (n <= 0 || dest == src)
	return (dest);
    if (dest > src && dest < src + n) {
	/* copy from backward */
	while (n--)
	    ((char *)dest)[n] = ((char *)src)[n];
    }
    else {
	register int i;
	for (i = 0; i < n; i++)
	    ((char *)dest)[i] = ((char *)src)[i];
    }
    return (dest);
}
#endif /* HAVE_MEMMOVE */



#ifdef NO_GETOPT

/*
 * getopt - get option letter from argv
 */

#include <stdio.h>

char	*optarg;	/* Global argument pointer. */
int	optind = 0;	/* Global argv index. */

static char	*scan = NULL;	/* Private scan pointer. */

 

int
getopt(argc, argv, optstring)
int argc;
char *argv[];
char *optstring;
{
	register char c;
	register char *place;

	optarg = NULL;

	if (scan == NULL || *scan == '\0') {
		if (optind == 0)
			optind++;
	
		if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0')
			return(EOF);
		if (strcmp(argv[optind], "--")==0) {
			optind++;
			return(EOF);
		}
	
		scan = argv[optind]+1;
		optind++;
	}

	c = *scan++;
	place = strchr (optstring, c);

	if (place == NULL || c == ':') {
		fprintf(stderr, "%s: unknown option -%c\n", argv[0], c);
		return('?');
	}

	place++;
	if (*place == ':') {
		if (*scan != '\0') {
			optarg = scan;
			scan = NULL;
		} else if (optind < argc) {
			optarg = argv[optind];
			optind++;
		} else {
			fprintf(stderr, "%s: -%c argument missing\n", argv[0], c);
			return('?');
		}
	}

	return(c);
}


#endif /* NO_GETOPT */