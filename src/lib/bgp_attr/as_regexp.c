/*
 * $Id: as_regexp.c,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#include <mrt.h>
#include <flist.h>

#undef REGEXP_DEBUG

static void
REGEXP_PRINT (char *fmt, ...)
{
#ifdef REGEXP_DEBUG
    va_list ap;

    va_start (ap, fmt);
    vprintf (fmt, ap);
    va_end (ap);
#endif /* REGEXP_DEBUG */
}

#include <mrt.h>
#include <aspath.h>
#include <linked_list.h>

typedef struct _as_regexp_env {
    char *cp;
    int type;
    int value;
    as_regexp_code_t *code;
    int state;
} as_regexp_env;

/*
 * returns
 *     error : -1
 *     EOS:     0
 *     token:   > 0
 */
int static
as_regexp_scan (as_regexp_env *env)
{
    int c, value;

    while (isspace (*env->cp))
	env->cp++;

    switch (c = *env->cp++) {
	case '^':
	case '$':
	case '.':
	case '*':
	case '+':
	case '?':
	case '(':
	case '|':
	case ')':
	case '\0':
	    env->type = c;
	    break;
	case '_': /* cisco's way */
	    if (isdigit (*env->cp)) {
		c = *env->cp++;
		goto number;
	    }
	    else {
		env->type = -1;
		break;
	    }
	case 'a': case 'A':
	    if (env->cp[0] && 
	       (env->cp[0] == 's' || env->cp[0] == 'S') && 
		env->cp[1] && isdigit (env->cp[1])) {
		env->cp++;
		c = *env->cp++;
		/* FALL THROUGH */
	    }
	    else {
		env->type = -1;
		break;
	    }
	case '0': case '1': case '2': case '3':
	case '4': case '5': case '6': case '7':
	case '8': case '9': 
number:	    value = c - '0';
	    while ((c = *env->cp), isdigit (c)) {
		value = value*10 + (c - '0');
		env->cp++;
	    }
	    env->value = value;
	    env->type = 'x';
	    if (*env->cp == '_') /* cisco's way */
		env->cp++;
	    break;
        default:
	    env->type = -1;
	    break;
    }
    return (env->type);
}


void static
as_regexp_poke (as_regexp_env *env,
	  int state, int type, int value, int next1, int next2)
{
    if (env->code) {
        env->code[state].type = type;
        env->code[state].value = value;
        env->code[state].next1 = next1;
        env->code[state].next2 = next2;
    }
}

int static as_regexp_expression (as_regexp_env *env);

/*
 * Error                               ==> -1
 * OK but possible to be null like .*  ==>  0
 * OK and must be something like 1     ==>  1
 */

int static
as_regexp_factor (as_regexp_env *env)
{
    int t1;
    int r = 1; /* not nullable */

    /* put a no-operation here for later change */
    /* I know it's a somewhat redundant way */
    t1 = env->state;
    as_regexp_poke (env, t1, ' ', 0, t1 + 1, t1 + 1);
    env->state++;

    if (env->type == '(') {
        if (as_regexp_scan (env) <= 0) /* doesn't allow EOF */
	    return (-1);
	if ((r = as_regexp_expression (env)) < 0)
	    return (-1);
	if (env->type != ')')
	    return (-1);
        if (as_regexp_scan (env) < 0) /* could be EOF */
	    return (-1);
    }
    else if (env->type == 'x' ||
             env->type == '.') {
	as_regexp_poke (env, env->state, env->type, env->value, 
				 env->state + 1, env->state + 1);
	env->state++;
        if (as_regexp_scan (env) < 0) /* could be EOF */
	    return (-1);
    }
    else {
	return (-1);
    }

    if (env->type == '*' ||
        env->type == '+' ||
        env->type == '?') {

	/* error */
	if (env->type == '*' && r == 0)
	    return (-1);

	if (env->type == '*') {
    	    as_regexp_poke (env, t1, ' ', 0, env->state, env->state);
	    as_regexp_poke (env, env->state, ' ', 0, env->state + 1, t1 + 1);
	    env->state++;
	    r = 0;
	}
	else if (env->type == '+') {
	    as_regexp_poke (env, env->state, ' ', 0, env->state + 1, t1 + 1);
	    env->state++;
	}
	else if (env->type == '?') {
    	    as_regexp_poke (env, t1, ' ', 0, t1 + 1, env->state);
	    /* putting a noop here is safer ? */
	    r = 0;
	}
	if (as_regexp_scan (env) < 0) /* could be EOF */
	    return (-1);
    }
    return (r);
}


int static
as_regexp_term (as_regexp_env *env)
{
    int r;

    if ((r = as_regexp_factor (env)) < 0)
	return (-1);
    if (env->type == '(' || env->type == '.' || env->type == 'x') {
	int r2;
	r2 = as_regexp_term (env);
	if (r2 < 0)
	    return (-1);
	r = (r | r2);
    }
    return (r);
}


int static
as_regexp_expression (as_regexp_env *env)
{
    int t1, r;

    /* put a no-operation here for later change */
    /* I know it's a somewhat redundant way */
    t1 = env->state;
    as_regexp_poke (env, t1, ' ', 0, t1 + 1, t1 + 1);
    env->state++;

    if ((r = as_regexp_term (env)) < 0)
	return (-1);

    if (env->type == '|') {
	int t2, t3, r2;

        if (as_regexp_scan (env) <= 0)
	    return (-1);
	t2 = env->state;
	env->state++;
	t3 = env->state;
	if ((r2 = as_regexp_expression (env)) < 0)
	    return (-1);
	as_regexp_poke (env, t1, ' ', 0, t1 + 1, t3);
	as_regexp_poke (env, t2, ' ', 0, env->state, env->state);
	r = (r & r2);
    }

    return (r);
}


int static
as_regexp_parse_start (as_regexp_env *env)
{
    int r = 0;

    if (as_regexp_scan (env) < 0)
	return (-1);

    /* we don't want state 0 appears except for the end */
    as_regexp_poke (env, env->state, ' ', 0, env->state + 1, env->state + 1);
    env->state++;

    if (env->type == '^') {
        if (as_regexp_scan (env) < 0)
	    return (-1);
    }
    else {
	/* put .* at the beginning */
        as_regexp_poke (env, env->state, ' ', 0, 
					env->state + 1, env->state + 2);
	env->state++;
	as_regexp_poke (env, env->state, '.', 0, env->state + 1, env->state);
	env->state++;
    }

    if (env->type != '$' && env->type != '\0') {
        if ((r = as_regexp_expression (env)) < 0)
	    return (-1);
    }

    if (env->type == '$') {
        if (as_regexp_scan (env) < 0)
	    return (-1);
    }
    else {
	/* put .* at the end */
	as_regexp_poke (env, env->state, ' ', 0, env->state + 1, 
						  env->state + 2);
	env->state++;
	as_regexp_poke (env, env->state, '.', 0, env->state + 1, env->state);
	env->state++;
    }

    if (env->type != '\0') {
	return (-1);
    }
    as_regexp_poke (env, env->state, ' ', 0, 0, 0);
    env->state++;
    return (r);
}


/*
 * expr: regular expression
 * pos will have a position where an error occurs if pos is suppried
 * returns code
 */
as_regexp_code_t *
as_regexp_comp (char *expr, int *pos)
{
    as_regexp_env *env;
    as_regexp_code_t *code;

    assert (expr);
    REGEXP_PRINT ("RE: %s\n", expr);

    env = New (as_regexp_env);
    env->cp = expr;
    env->state = 0;
    env->code = NULL;
    /* estimate the length of code area */
    if (as_regexp_parse_start (env) < 0) {
        if (pos)
	    *pos = env->cp - expr;
        Delete (env);
        return (NULL);
    }

    assert (env->state > 0);
    code = NewArray (as_regexp_code_t, env->state);
    env->cp = expr;
    env->state = 0;
    env->code = code;
    if (as_regexp_parse_start (env) < 0) {
	/* should not happen */
	assert (0);
    }
    Delete (env);
#ifdef REGEXP_DEBUG
    as_regexp_code_print (code);
#endif /* REGEXP_DEBUG */
    return (code);
}

/*
 * Match ==>  1
 * NO    ==> -1
 */

int
as_regexp_exec (as_regexp_code_t *code, LINKED_LIST *aspath)
{
    aspath_segment_t *as_seg;
    int nowi;

    int scan; /* a mark to dintinguish states */
    int state = 0; /* current state */

    int *deque; /* queue and stack */
    int bottom = 0;
    int top = 0;

    u_char *dups; /* duplicate check */

    as_regexp_code_t *ip;
    int len;

    assert (code);

    /* calculate the code length to estimate working spaces */
    for (ip = code; ; ip++) {
	if (ip->next1 == 0 && ip->next2 == 0) {
	    ip++; /* to be subtracted later */
	    break;
	}
    }
    len = ip - code;

    REGEXP_PRINT ("code len = %d\n", len);
    if (len <= 0)
        return (0);

    scan = len; /* special scan code which doesn't appear as an index */

    /* scan can be on the stack so that the one more space is required */
    len++;

    dups = NewArray (u_char, len);
    memset (dups, 0, len);
    deque = NewArray (int, len);

    /*
     * At least, there is one scan code on the stack
     */
    if (bottom <= 0)
        bottom = len;
    deque[--bottom] = scan;

    if (aspath == NULL)
	as_seg = NULL;
    else
        as_seg = LL_GetHead (aspath);
    while (as_seg && as_seg->len <= 0)
         as_seg = LL_GetNext (aspath, as_seg);
    nowi = 0;

    for (;;) {

	if (state == scan) {

	    REGEXP_PRINT ("state = #\n");

	    if (bottom == top) {
	        REGEXP_PRINT ("*** NO OTHER CHOISE #1\n");
    		Delete (dups);
    		Delete (deque);
		return (-1);
	    }

	    if (as_seg == NULL) {
	        REGEXP_PRINT ("*** AS END\n");
    		Delete (dups);
    		Delete (deque);
	        return (-1);
	    }

	    if (as_seg->type == PA_PATH_SET || ++nowi >= as_seg->len) {
		do {
		    as_seg = LL_GetNext (aspath, as_seg);
		} while (as_seg && as_seg->len <= 0);
		nowi = 0;
	    }
	    if (as_seg) {
		if (as_seg->type == PA_PATH_SET) {
		    int i;
		    REGEXP_PRINT ("next as is [");
		    for (i = 0 ; i < as_seg->len; i++)
			REGEXP_PRINT ("%d ", as_seg->as[i]);
		    REGEXP_PRINT ("]\n");
		}
		else {
		    REGEXP_PRINT ("next as is %d\n", as_seg->as[nowi]);
		}
	    }
	    else {
		REGEXP_PRINT ("next as is END\n");
	    }
	    if (bottom <= 0)
		bottom = len;
    	    deque[--bottom] = scan;
	    REGEXP_PRINT ("put #\n");
	}
	else {

	    int type, value, next1, next2;

	    type = code[state].type;
	    value = code[state].value;
	    next1 = code[state].next1;
	    next2 = code[state].next2;
	    REGEXP_PRINT (
		"state = %d type = [%c] value = %d next1 = %d next2 = %d\n", 
		 state, type, value, next1, next2);

	    if (next1 == 0 && next2 == 0 && as_seg == NULL) {
    	        REGEXP_PRINT ("*** PATTERN END #1\n");
    		Delete (dups);
    		Delete (deque);
	        return (1);
	    }

	    if ((type == 'x' || type == '.') && as_seg) {

	        if (type == 'x')
	            REGEXP_PRINT ("check %d with ", value);
		else
	            REGEXP_PRINT ("check any with ");

		if (as_seg->type == PA_PATH_SEQ) {
	            REGEXP_PRINT ("AS %d\n",
			  	  as_seg->as[nowi]);
		}
		else {
		    int i;

		    REGEXP_PRINT ("AS [");
		    for (i = 0 ; i < as_seg->len; i++)
			REGEXP_PRINT ("%d ", as_seg->as[i]);
		    REGEXP_PRINT ("]\n");
		}

	        if ((type == 'x' && ((as_seg->type == PA_PATH_SEQ && 
			              value == as_seg->as[nowi]) ||
				     (as_seg->type == PA_PATH_SET &&
				      bgp_check_aspath_in (as_seg, value)))) ||
		     type == '.') {
		    if (dups[next1] == 0) {
			if (bottom <= 0)
			    bottom = len;
    	                deque[--bottom] = next1;
			dups[next1]++;
		        REGEXP_PRINT ("put %d\n", next1);
		    }
		    else {
		        REGEXP_PRINT ("put %d (dup)\n", next1);
		    }
	            if (next1 != next2) {
		        if (dups[next2] == 0) {
			    if (bottom <= 0)
			        bottom = len;
    	                    deque[--bottom] = next2;
			    dups[next2]++;
		            REGEXP_PRINT ("put %d\n", next2);
			}
			else {
		            REGEXP_PRINT ("put %d (dup)\n", next2);
			}
	            }
	        }
	    }
	    else if (type == ' ') {
		if (dups[next1] == 0) {
	            deque[top++] = next1;
		    if (top >= len)
		        top = 0;
		    dups[next1]++;
	            REGEXP_PRINT ("push %d\n", next1);
		}
		else {
	            REGEXP_PRINT ("push %d (dup)\n", next1);
		}
	        if (next1 != next2) {
		    if (dups[next2] == 0) {
	                deque[top++] = next2;
		        if (top >= len)
		            top = 0;
		        dups[next2]++;
	                REGEXP_PRINT ("push %d\n", next2);
		    }
		    else {
	                REGEXP_PRINT ("push %d (dup)\n", next2);
		    }
	        }
	    }
	}
    {
	int i;

        for (i = bottom; i != top;) {
            if (deque[i] != scan) REGEXP_PRINT("%5d ", deque[i]);
            else REGEXP_PRINT("%5c ", '#');
	    if (++i >= len)
		i = 0;
	}
        REGEXP_PRINT ("\n");
    }
	assert (bottom != top);
	if (top <= 0)
	    top = len;
	state = deque[--top];
	dups[state] = 0;
	while (state == 0) {
	    REGEXP_PRINT ("REACH PATTERN END\n");
	    if (as_seg == NULL) {
	        REGEXP_PRINT ("*** BOTH END\n");
    		Delete (dups);
    		Delete (deque);
		return (1);
	    }
	    if (bottom == top) {
	        REGEXP_PRINT ("NO OTHER CHOISE #2\n");
		break;
	    }
	    if (top <= 0)
	        top = len;
	    state = deque[--top];
	    dups[state] = 0;
	    REGEXP_PRINT ("ANOTHER TRIAL\n");
	}

    }
    /* NOT REACHED */
}


/*
 * retuens 1 if the both are same
 * retuens 0 if not
 */
int
as_regexp_code_same (as_regexp_code_t *a, as_regexp_code_t *b)
{
    int i;

    if (a == b) /* both null */
	return (1);

    if (a && b) {
        for (i = 0; ; i++) {
	    if (a[i].type != b[i].type ||
	        a[i].value != b[i].value ||
	        a[i].next1 != b[i].next1 ||
	        a[i].next2 != b[i].next2)
	        return (0);
            if (a[i].next1 == 0 && b[i].next2 == 0)
                break;
        }
    }
    else {
	return (0);
    }
    return (1);
}


void
as_regexp_code_print (as_regexp_code_t *code)
{
    int i;

    for (i = 0; ; i++) {
        printf ("%5d", i);
        if (code[i].type == 'x')
            printf (" %5d", code[i].value);
        else
            printf (" %5c", code[i].type);
        printf (" %5d", code[i].next1);
        printf (" %5d", code[i].next2);
        printf ("\n");
        if (code[i].next1 == 0 && code[i].next2 == 0)
            break;
    }
}

