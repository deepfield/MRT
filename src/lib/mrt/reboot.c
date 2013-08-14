/* 
 * $Id: reboot.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <mrt.h>
#ifdef NT
#include <ntconfig.h>
#include <direct.h>
#endif /* NT */

int init_mrt_reboot (int argc, char *argv[]) {
  char tmp[MAXLINE];

  getcwd (tmp, MAXLINE);
  MRT->cwd = strdup (tmp);
  MRT->argc = argc;
  MRT->argv = argv;

  return (1);
}

void 
mrt_reboot (void)
{

#ifndef NT
  char tmp[MAXLINE], *cp;
  int i = 0;

  /* signals ? */
  alarm (0);

  if (MRT->daemon_mode == 0) {
    for (; i < 3; i++)
      fcntl (i, F_SETFD, 0); /* keep open */
  }

  for (; i < getdtablesize (); i++)
    fcntl (i, F_SETFD, 1); /* close */

  cp = tmp;
  for (i = 0; MRT->argv[i]; i++) {
    if (i > 0) *cp++ = ' ';
    sprintf (cp, "%s", MRT->argv[i]);
    cp += strlen (cp);
  }
  trace (TR_WARN, MRT->trace, "MRT rebooting %s\n", tmp);
  execvp (MRT->argv[0], MRT->argv);
  trace (TR_ERROR, MRT->trace, "MRT ERROR rebooting %s\n", tmp);
  exit (1);

#endif /* NT */
}
