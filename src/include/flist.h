/*
 * $Id: flist.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef FLIST_H
#define FLIST_H

#include <linked_list.h>

#define MAX_AS_ALIST 100
int add_as_access_list (int num, char *expr, int permit);
int remove_as_access_list (int num, char *expr, int permit);
int apply_as_access_list (int num, LINKED_LIST * aspath);
char *as_access_list_toa (int num);
int count_as_access_list (int num);

typedef struct _as_regexp_code_t {
    int type;
    int value;
    int next1;
    int next2;
} as_regexp_code_t;

as_regexp_code_t *as_regexp_comp (char *expr, int *pos);
int as_regexp_exec (as_regexp_code_t * code, LINKED_LIST * aspath);
void as_regexp_code_print (as_regexp_code_t * code);
int as_regexp_code_same (as_regexp_code_t * a, as_regexp_code_t * b);

#endif /* FLIST_H */
