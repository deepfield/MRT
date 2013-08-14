/*
 * $Id: error.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

/*
 * Code taken from Richard Stevens, "Unix Network Programming"
 * Prentice Hall Software, New Jersey, 1990
 * [Code is publicly avaliable via annonymous ftp]
 *
 */


int VERBOSE_ERROR_FLAG = 0;

#include	<stdio.h>
#include <stdarg.h>
/*#include <varargs.h>*/
#include	 <syslog.h>

char	*pname = NULL;
char    emesgstr[255] = {0};    /* used by all server routines */

/*
 * Fatal error.  Print a message and terminate.
 * Don't print the system's errno value.
 *
 *	err_quit(str, arg1, arg2, ...)
 *
 * The string "str" must specify the conversion specification for any args.
 */

/*VARARGS1*/
err_quit(char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	fmt = va_arg(args, char *);
	vsprintf(emesgstr, fmt, args);
	va_end(args);

	syslog(LOG_ERR, emesgstr);
	if (VERBOSE_ERROR_FLAG)
	   fprintf(stderr,emesgstr); 
	exit(1);
}

/*
 * Fatal error related to a system call.  Print a message and terminate.
 * Don't dump core, but do print the system's errno value and its
 * associated message.
 *
 *	err_sys(str, arg1, arg2, ...)
 *
 * The string "str" must specify the conversion specification for any args.
 */

/*VARARGS1*/
err_sys(char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	fmt = va_arg(args, char *);
	vsprintf(emesgstr, fmt, args);
	va_end(args);

	my_perror();
	syslog(LOG_ERR, emesgstr);
	if (VERBOSE_ERROR_FLAG)
	   fprintf(stderr,emesgstr); 
	exit(1);
}

/*
 * Recoverable error.  Print a message, and return to caller.
 *
 *	err_ret(str, arg1, arg2, ...)
 *
 * The string "str" must specify the conversion specification for any args.
 */

/*VARARGS1*/
err_ret(char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	fmt = va_arg(args, char *);
	vsprintf(emesgstr, fmt, args);
	va_end(args);

	my_perror();
	syslog(LOG_ERR, emesgstr);
	if (VERBOSE_ERROR_FLAG)
	   fprintf(stderr,emesgstr); 
	return;
}

/*
 * Fatal error.  Print a message, dump core (for debugging) and terminate.
 *
 *	err_dump(str, arg1, arg2, ...)
 *
 * The string "str" must specify the conversion specification for any args.
 */

/*VARARGS1*/
err_dump(char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	fmt = va_arg(args, char *);
	vsprintf(emesgstr, fmt, args);
	va_end(args);

	my_perror();
	syslog(LOG_ERR, emesgstr);
	if (VERBOSE_ERROR_FLAG)
	   fprintf(stderr,emesgstr); 
	abort();		/* dump core and terminate */
	exit(1);		/* shouldn't get here */
}

/*
 * Print the UNIX errno value.
 * We just append it to the end of the emesgstr[] array.
 */

my_perror()
{
	register int	len;
	char		*sys_err_str();

	len = strlen(emesgstr);
	sprintf(emesgstr + len, " %s", sys_err_str());
}


			/* remainder is for both CLIENT and SERVER */
extern int	errno;		/* Unix error number */
extern int	sys_nerr;	/* # of error message strings in sys table */
/*extern char	*sys_errlist[];	 the system error message table */
extern const char *const sys_errlist[];

#ifdef	SYS5
int	t_errno;	/* in case caller is using TLI, these are "tentative
			   definitions"; else they're "definitions" */
int	t_nerr;
char	*t_errlist[1];
#endif


/*
 * Return a string containing some additional operating-system
 * dependent information.
 * Note that different versions of UNIX assign different meanings
 * to the same value of "errno" (compare errno's starting with 35
p * between System V and BSD, for example).  This means that if an error
 * condition is being sent to another UNIX system, we must interpret
 * the errno value on the system that generated the error, and not
 * just send the decimal value of errno to the other system.
 */

char *
sys_err_str()
{
	static char	msgstr[200];

	if (errno != 0) {
		if (errno > 0 && errno < sys_nerr)
			sprintf(msgstr, "(%s)", sys_errlist[errno]);
		else
			sprintf(msgstr, "(errno = %d)", errno);
	} else {
		msgstr[0] = '\0';
	}

#ifdef	SYS5
	if (t_errno != 0) {
		char	tmsgstr[100];

		if (t_errno > 0 && t_errno < sys_nerr)
			sprintf(tmsgstr, " (%s)", t_errlist[t_errno]);
		else
			sprintf(tmsgstr, ", (t_errno = %d)", t_errno);

		strcat(msgstr, tmsgstr);	/* catenate strings */
	}
#endif

	return(msgstr);
}
