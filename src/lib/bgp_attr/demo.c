/*
 * $Id: demo.c,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#include <mrt.h>
#include <aspath.h>

void
main (int argc, char **argv)
{
#if 1
    char buff[MAXLINE];
    as_regexp_code_t *code;
    aspath_t *aspath;
    int pos;

    while (gets (buff) != NULL) {
        if ((code = as_regexp_comp (buff, &pos)) == NULL) {
            printf ("%s\n", buff);
            printf ("%*c\n", pos, '^');
            continue;
        }
        printf ("\n");

        if (gets (buff) == NULL)
            break;
        aspath = aspth_from_string (buff);
        if (aspath) {
            printf ("aspath: %s\n", aspath_toa (aspath));
            as_regexp_exec (code, aspath);
        }
        Delete (code);
    }

#endif

#if 0
    aspath_t *aspath1, *aspath2;
    aspath1 = aspth_from_string ("[101 20] 1 2 3 [201 301]");
    aspath2 = aspth_from_string ("[101 20] 1 3 5 202 [302]");
    fprintf(stderr, "aspath1 = %s\n", aspath_toa (aspath1));
    fprintf(stderr, "aspath2 = %s\n", aspath_toa (aspath2));
    fprintf(stderr, "result = %s\n", aspath_toa (
			aspath_merge (aspath1, aspath2, NULL)));
#endif
    exit(0);
}
