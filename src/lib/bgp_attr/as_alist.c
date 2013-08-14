/*
 * $Id: as_alist.c,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#include <mrt.h>
#include <bgp.h>
#include <aspath.h>
#include <flist.h>

static LINKED_LIST *as_access_list[MAX_AS_ALIST];

typedef struct _as_condition_t {
    int permit;
    char *expr;
    as_regexp_code_t *code;
} as_condition_t;


int
add_as_access_list (int num, char *expr, int permit)
{

    as_condition_t *condition;
    as_regexp_code_t *code;

    if (num >= MAX_AS_ALIST)
	return (-1);
    if ((code = as_regexp_comp (expr, NULL)) == NULL)
	return (-1);
    if (as_access_list[num] == NULL) {
	as_access_list[num] = LL_Create (0);
    }
    condition = New (as_condition_t);
    condition->permit = permit;
    condition->code = code;
    condition->expr = strdup (expr);
    LL_Add (as_access_list[num], condition);
    return (1);
}

int
remove_as_access_list (int num, char *expr, int permit)
{
    as_condition_t *condition;
    as_regexp_code_t *code;

    if (num >= MAX_AS_ALIST)
	return (-1);
    if (as_access_list[num] == NULL)
	return (-1);
    if ((code = as_regexp_comp (expr, NULL)) == NULL)
	return (-1);

    LL_Iterate (as_access_list[num], condition)
	if (as_regexp_code_same (code, condition->code) &&
	    (permit == condition->permit)) {
	Delete (condition->expr);
	Delete (condition->code);
	LL_Remove (as_access_list[num], condition);
	return (1);
    }
    return (-1);
}


int
del_as_access_list (int num)
{

    if (num >= MAX_AS_ALIST)
	return (-1);
    if (as_access_list[num] == NULL) {
	return (-1);
    }
    Delete (as_access_list[num]);
    as_access_list[num] = NULL;
    return (1);
}


int
count_as_access_list (int num)
{
    if (num >= MAX_AS_ALIST)
	return (-1);
    if (as_access_list[num] == NULL) {
	return (0);
    }
    return (LL_GetCount (as_access_list[num]));
}


/*
 * return 1 if permit, 0 otherwise
 */
int 
apply_as_access_list (int num, aspath_t * aspath)
{

    as_condition_t *condition;

    if (num >= MAX_AS_ALIST)
	return (0);
    if (num == 0)
	return (1);		/* cisco feature */
    if (as_access_list[num] == NULL) {
	/* I'm not sure how cisco works for undefined aspath access lists */
	return (0);		/* assuming deny for now */
    }

    LL_Iterate (as_access_list[num], condition) {

	if (condition->code == NULL)	/* all */
	    return (condition->permit);

	if (as_regexp_exec (condition->code, aspath) > 0)
	    return (condition->permit);
    }
    return (0);
}



char *
as_access_list_toa (int num)
{
    as_condition_t *condition;
    char line[MAXLINE], *tmpx = line;
    int len = 0;

    assert (num < MAX_AS_ALIST);

    if (as_access_list[num] == NULL || LL_GetCount (as_access_list[num]) <= 0)
	return (NULL);

    /* estimate a strage size required */
    LL_Iterate (as_access_list[num], condition) {
	len += sprintf (tmpx, "as-path access-list %d %s %s\n", num,
			(condition->permit) ? "permit" : "deny",
			condition->expr);
    }

    tmpx = NewArray (char, len + 1);
    /* now printing */
    len = 0;
    LL_Iterate (as_access_list[num], condition) {
	len += sprintf (tmpx + len, "as-path access-list %d %s %s\n", num,
			(condition->permit) ? "permit" : "deny",
			condition->expr);
    }

    return (tmpx);
}
