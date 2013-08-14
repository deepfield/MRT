/*
 * $Id: alist.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef _ALIST_H
#define _ALIST_H

#define MAX_ALIST 100
typedef struct _condition_t {
    int permit; /* just a flag */
    prefix_t *prefix; /* all in case of null */
    prefix_t *wildcard; /* may be null */
    int exact; /* just a flag */
    int refine; /* just a flag */
} condition_t;

int add_access_list (int num, int permit, prefix_t *prefix, prefix_t *wildcard,
                     int exact, int refine);
int remove_access_list (int num, int permit, prefix_t *prefix, 
			prefix_t *wildcard, int exact, int refine);
int del_access_list (int num);
int apply_condition (condition_t *condition, prefix_t *prefix);
int apply_access_list (int num, prefix_t *prefix);
char *access_list_toa (void);
char *access_list_toa2 (int num);
void access_list_out (int num, void_fn_t fn);

#endif /* _ALIST_H */
