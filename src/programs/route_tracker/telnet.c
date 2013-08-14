
/*
 * $Id: telnet.c,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
 */


/* Most of this code was taken from the MRT user.c library. I'm not sure what
 * all -- shrug, even most -- of the code does. Ask Masaki. Seems to work.
 */

#include <stdio.h>
#include <string.h>
#include <mrt.h>
#include <select.h>
#include <trace.h>
#include <interface.h>
#include <time.h>
#include <sys/time.h>
#include <bgp.h>
#include <signal.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include <stdarg.h>
#include <config_file.h>
#include <sys/types.h>
#include "rtracker.h"
#include <fcntl.h>
#ifndef SETPGRP_VOID
#include <sys/termios.h>
#endif
#include <config_file.h>

extern int IPV4;
extern trace_t *default_trace;
extern radix_tree_t *RADIX;

extern rtracker_t RTR;

static int control = 0;

static void irr_bs (int fd, int n);
static void irr_bell (int fd);
static int irr_read_command (irr_connection_t * irr);
void Delete_RTR_File (rtr_data_file_t *file);
int irr_send_data (irr_connection_t * irr,...);
int buffered_write (int fd, char *buffer, int len, int usec);

static void *start_irr_connection (irr_connection_t * irr_connection)
{
  fd_set          read_fds;
  struct timeval  tv;
  int		  ret;
  sigset_t set;

  sigemptyset (&set);
  sigaddset (&set, SIGALRM);
  sigaddset (&set, SIGHUP);
  pthread_sigmask (SIG_BLOCK, &set, NULL);

  /* look for SENT IAC SB NAWS 0 133 (133) 0 58 (58)
   * to learn screen size
   */

  /* TIMEOUT of three minutes */
  tv.tv_sec = 60*3;
  tv.tv_usec = 0;

  /*  memset (irr_connection->buffer, 0, MAXLINE); */
  irr_connection->cp = irr_connection->buffer;
  irr_connection->end = irr_connection->buffer;
  irr_connection->end[0] = '\0';

  irr_connection->end_window = time (NULL);
  irr_connection->start_window = time (NULL) - 60*60;
  irr_connection->database = LL_GetHead (RTR.ll_database);

#ifndef HAVE_LIBPTHREAD    
    select_add_fd (irr_connection->sockfd, SELECT_READ,
		   (void *) irr_read_command, irr_connection);
#endif /* HAVE_LIBPTHREAD */

#ifdef HAVE_LIBPTHREAD
    FD_ZERO(&read_fds);
    FD_SET(irr_connection->sockfd, &read_fds);

    while (1) {
      /*schedule_wait_for_event (irr_connection->schedule);*/
      ret = select (irr_connection->sockfd + 1, &read_fds, 0, 0, &tv);
      if (ret <= 0) {
	trace (NORM, default_trace,
	       "ERROR on RTR select (before read). Closing connection (%s)\n",
	       strerror (errno));
	irr_send_data (irr_connection, "Connect closed -- timeout or error\r\n");
	irr_destroy_connection (irr_connection);
	return NULL;
      }
      irr_read_command (irr_connection);
    }
#else
    return NULL;
#endif /* HAVE_LIBPTHREAD */

}


static int irr_accept_connection (void) {
    int sockfd;
    int len, port, family;
    prefix_t *prefix;
    struct sockaddr_in addr;
    irr_connection_t *irr_connection;
    u_int one = 1;
    char tmp[MAXLINE];

    len = sizeof (addr);
    memset ((struct sockaddr *) &addr, 0, len);

    if ((sockfd =
	 accept (RTR.sockfd, (struct sockaddr *) &addr, &len)) < 0) {
	trace (ERROR, default_trace, "ERROR -- RTR Accept failed (%s)\n",
	       strerror (errno));
	select_enable_fd (RTR.sockfd);
	return (-1);
    }


    select_enable_fd (RTR.sockfd);

    if (setsockopt (sockfd, IPPROTO_TCP, TCP_NODELAY, (char *) &one,
		    sizeof (one)) < 0) {
      trace (NORM | INFO, default_trace, "RTR setsockoptfailed\n");
      return (-1);
    }

    if ((family = addr.sin_family) == AF_INET) {
      struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
      port = ntohs (sin->sin_port);
      prefix = New_Prefix (AF_INET, &sin->sin_addr, 32);
    }  
    else {
      trace (ERROR, default_trace, "RTR ERROR unknown connection family = %d\n",
             family);
      close (sockfd);
      return (-1);
    }  

    /* check load */
    if (RTR.connections > RTR.max_connections) {
      trace (INFO, default_trace, "Too many connections -- REJECTING %s\n",
	     prefix_toa (prefix));
      Deref_Prefix (prefix);
      close (sockfd);
      return (-1);
    }

    trace (INFO, default_trace, "RTR accepting connection from %s\n",
	   prefix_toa (prefix));

    /* Apply access list (if one exists) */
    if (RTR.access_list > 0) {
      if (!apply_access_list (RTR.access_list, prefix)) {
	trace (NORM | INFO, default_trace, "RTR DENIED to %s\n",
	       prefix_toa (prefix));
	Deref_Prefix (prefix);
	close (sockfd);
	return (-1);
      }
    }

    RTR.connections++;

    irr_connection = New (irr_connection_t);
    irr_connection->schedule = New_Schedule ("irr_connection", default_trace);
    irr_connection->sockfd = sockfd;
    irr_connection->cmdcp = irr_connection->cmdend = 0;
    irr_connection->from = prefix;
    irr_connection->ll_peer = LL_Create (LL_DestroyFunction, Delete_Peer, 0);
    irr_connection->database = LL_GetHead (RTR.ll_database);
    
    sprintf (tmp, "RTR %s", prefix_toa (prefix));
    mrt_thread_create (tmp, irr_connection->schedule,
		       (thread_fn_t) start_irr_connection, irr_connection);
    return (1);
}


/*
 * begin listening for connections on a well known port
 */
int 
listen_telnet (void) {
    struct sockaddr *sa;
    struct servent *service;
    int len, optval = 1;
    u_short port;
    int fd;
    char *portname = NULL;

    struct sockaddr_in serv_addr;
    memset (&serv_addr, 0, sizeof (serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    if (portname == NULL) {
	port = htons (RTR.rtr_port);
    }
    else {
        /* search /etc/services for port */
      if ((service = getservbyname (portname, NULL)) == NULL) {
	    int i = atoi (portname);	/* in case of number */
	    port = (i > 0) ? htons (i) : htons (RTR.rtr_port);
        }
        else
	  port = service->s_port;
    }

    serv_addr.sin_port = port;
    sa = (struct sockaddr *) &serv_addr;
    len = sizeof (serv_addr);
    if ((fd = socket (sa->sa_family, SOCK_STREAM, 0)) < 0) {
	    trace (ERROR, default_trace, 
	           "RTR ERROR -- Could not get socket (%s)\n",
		    strerror (errno));
	    return (-1);
    }
    RTR.sockfd = fd;

    if (setsockopt (RTR.sockfd, SOL_SOCKET, SO_REUSEADDR,
		    (const char *) &optval, sizeof (optval)) < 0) {
	trace (ERROR, default_trace, "RTR ERROR -- Could setsocket (%s)\n",
	       strerror (errno));
    }

    if (bind (RTR.sockfd, sa, len) < 0) {
	trace (ERROR, default_trace, 
	       "RTR ERROR -- Could not bind to port %d (%s)\n",
	       ntohs (port), strerror (errno));
	return (-1);
    }

    listen (RTR.sockfd, 5);

    trace (NORM, default_trace,
	   "RTR listening for connections on port %d (socket %d)\n",
	   ntohs (port), RTR.sockfd);

    select_add_fd (RTR.sockfd, 1, (void_fn_t) irr_accept_connection, NULL);

    return (1);
}



/* irr_send_data
 * send formatted data out a socket
 */
int 
irr_send_data (irr_connection_t * irr,...)
{
    va_list ap;
    char *format;
    char line[MAXLINE];
    short size;
    fd_set fdvar_write;
    int total;
    int nn;
    int fd;

    char *cp = line;

    if (irr == NULL) {
	return (-1);
    }
    fd = irr->sockfd;

    va_start (ap, irr);

    memset (line, 0, MAXLINE);

    format = va_arg (ap, char *);

    vsprintf (cp, format, ap);

    size = strlen (cp);
    /*UTIL_PUT_SHORT (size, psize); */

    FD_ZERO (&fdvar_write);
    FD_SET (fd, &fdvar_write);

    total = 0;
    cp = line;

    while (total < size) {
	if (select (FD_SETSIZE, NULL, &fdvar_write, NULL, NULL) < 0) {
	  return (-1);
	}

	if ((nn = write (fd, cp, size - total)) < 0) {
	    return (-1);
	}

	total += nn;
	cp += nn;

    }

    return (1);
}




static int irr_read_command (irr_connection_t * irr) {
    int n;
    char *cp;

    /* memset (irr->tmp, 0, MAXLINE); */

    if ((n = read (irr->sockfd, irr->tmp, MAXLINE - 1)) <= 0) {
      trace (NORM, default_trace, "RTR read failed\n",
	     strerror (errno));
      irr_destroy_connection (irr);
      return (-1);
    }
    irr->tmp[n] = '\0';

    cp = irr->tmp;
    while (n--) {
	if (control == 1) {
	    if (*cp == '[') {
		control = 2;
		cp++;
	    }
	    else {
		control = 0;
		cp++;
	    }
	}
	else if (control == 2) {
	    control = 0;

	    /* up \020 */
	    if (*cp == 'A') {
	      up:
		if (--irr->cmdcp < 0)
		    irr->cmdcp = MAXHIST - 1;
		if (irr->cmds[irr->cmdcp][0] == '\0') {
		    irr_bell (irr->sockfd);
		    if (++irr->cmdcp >= MAXHIST)
			irr->cmdcp = 0;
		}
		else {
		    int len, i, m;

		  replace:
		    if (irr->cp - irr->buffer > 0)
			irr_bs (irr->sockfd, irr->cp - irr->buffer);
		    strcpy (irr->buffer, irr->cmds[irr->cmdcp]);
		    len = strlen (irr->buffer);
		    write (irr->sockfd, irr->buffer, len);
		    if ((m = irr->end - irr->buffer - len) > 0) {
			for (i = 0; i < m; i++)
			    write (irr->sockfd, " ", 1);
			irr_bs (irr->sockfd, m);
		    }
		    irr->cp = irr->end = irr->buffer + len;
		}
	    }
	    /* down \016 */
	    else if (*cp == 'B') {
	      down:
		if (++irr->cmdcp >= MAXHIST)
		    irr->cmdcp = 0;
		if (irr->cmds[irr->cmdcp][0] == '\0') {
		    irr_bell (irr->sockfd);
		    if (--irr->cmdcp < 0)
			irr->cmdcp = MAXHIST - 1;
		}
		else {
		    goto replace;
		}
	    }
	    /* left */
	    else if (*cp == 'D') {
	      left:
		if (irr->cp <= irr->buffer) {
		    irr_bell (irr->sockfd);
		}
		else {
		    irr->cp--;
		    irr_bs (irr->sockfd, 1);
		}
	    }
	    /* right */
	    else if (*cp == 'C') {
	      right:
		if (irr->cp >= irr->end) {
		    irr_bell (irr->sockfd);
		}
		else {
		    write (irr->sockfd, irr->cp, 1);
		    irr->cp++;
		}
	    }
	    cp++;
	}
	/* ^B */
	else if (*cp == 'B' - '@') {
	    goto left;
	}
	/* ^F */
	else if (*cp == 'F' - '@') {
	    goto right;
	}
	/* ^N */
	else if (*cp == 'N' - '@') {
	    goto down;
	}
	/* ^P */
	else if (*cp == 'P' - '@') {
	    goto up;
	}
	/* ^K */
	else if (*cp == 'K' - '@') {
	    int i, m;

	    if ((m = irr->end - irr->cp) > 0) {
		for (i = 0; i < m; i++)
		    write (irr->sockfd, " ", 1);
		irr_bs (irr->sockfd, m);
		irr->end = irr->cp;
		irr->end[0] = '\0';
	    }
	}
	/* ^U */
	else if (*cp == 'U' - '@') {
	    int i, m;

	    if ((m = irr->end - irr->buffer) > 0) {
		irr_bs (irr->sockfd, irr->cp - irr->buffer);
		for (i = 0; i < m; i++)
		    write (irr->sockfd, " ", 1);
		irr_bs (irr->sockfd, m);
		irr->cp = irr->end = irr->buffer;
		irr->end[0] = '\0';
	    }
	}
	/* ^D */
	else if (*cp == 'D' - '@') {

	    if (irr->cp >= irr->end) {
		irr_bell (irr->sockfd);
	    }
	    else {
		memmove (irr->cp, irr->cp + 1, irr->end - irr->cp + 1);
		irr->end--;
		write (irr->sockfd, irr->cp, irr->end - irr->cp);
		write (irr->sockfd, " ", 1);
		irr_bs (irr->sockfd, irr->end - irr->cp + 1);
	    }
	}
	/* go to beginning of line */
	else if (*cp == 'A' - '@') {
	  irr_bs (irr->sockfd, irr->cp - irr->buffer);
	  irr->cp = irr->buffer;
	}
	/* goto end of line */
	else if (*cp == '\005') {
	  while (irr->cp < irr->end) {
	    write (irr->sockfd, irr->cp, 1);
	    irr->cp++;
	  }
	}
	else if (*cp == '\b' || *cp == '\177') {

	    /* no more to delete -- send bell */
	    if (irr->cp <= irr->buffer) {
		irr_bell (irr->sockfd);
	    }
	    else {
		irr_bs (irr->sockfd, 1);
		memmove (irr->cp - 1, irr->cp, irr->end - irr->cp);
		irr->cp--;
		irr->end--;
		write (irr->sockfd, irr->cp, irr->end - irr->cp);
		write (irr->sockfd, " ", 1);
		irr_bs (irr->sockfd, irr->end - irr->cp + 1);
	    }
	}
	/* control character (escape followed by 2 bytes */
	else if (*cp == '\033') {
	    control = 1;
	    cp++;
	}
	/* ^C */
	else if (*cp == 'C' - '@') {
	    irr->cp = irr->end = irr->buffer;
	    irr->end[0] = '\0';
	    goto xxxx;
	}
	else if (*cp == '\n') {
	    irr->end[0] = '\0';

	    /* remove tailing spaces */
	    cp = irr->buffer + strlen (irr->buffer) - 1;
	    while (cp >= irr->buffer && isspace (*cp)) {
	      *cp = '\0';
	      cp--;
	    }

	    /* remove heading spaces */
	    cp = irr->buffer;
	    while (*cp && isspace (*cp)) {
		cp++;
	    }
	    if (irr->buffer != cp)
		strcpy (irr->buffer, cp);

	    irr->cp = irr->buffer;
	  xxxx:
	    if (irr->buffer[0] != '\0') {
		strcpy (irr->cmds[irr->cmdend], irr->buffer);
		if (++irr->cmdend >= MAXHIST)
		    irr->cmdend = 0;
		irr->cmdcp = irr->cmdend;
	    }
	    if (rtr_proccess_command (irr) == 2) {
	      /* user has quit or we've unexpetdly terminated */
	      /* delete irr memory here -- or maybe not. I think it is already deleted */
	      return (1);
	    }

	    irr->cp = irr->buffer;
	    irr->end = irr->buffer;
	    irr->end[0] = '\0';

#ifndef HAVE_LIBPTHREAD
	    select_enable_fd (irr->sockfd);
#endif /* HAVE_LIBPTHREAD */
	    /*irr_send_data (irr, "[%2d] ", pthread_self ());*/
	    /*irr_send_data (irr, RTR.prompts[irr->state]);*/
	    return (1);
	}
	else if (*(u_char *)cp == 0xff) {
	    /*printf ("telnet sequences\n"); */
	    cp += 3;
	    n -= 2;
	}
	else {
	    if ((*cp > 31) && (*cp < 127)) {
	      if (irr->end > irr->cp) {
		write (irr->sockfd, irr->cp, irr->end - irr->cp);
		irr_bs (irr->sockfd, irr->end - irr->cp);
		memmove (irr->cp + 1, irr->cp, irr->end - irr->cp);
	      }
	      *(irr->cp)++ = *cp;
	      irr->end++;
	    }
	    cp++;
	}
    }

#ifndef HAVE_LIBPTHREAD
    select_enable_fd (irr->sockfd);
#endif /* HAVE_LIBPTHREAD */

    return (1);
}



int irr_destroy_connection (irr_connection_t * connection) {
  trace (NORM, default_trace, "RTR Closing a connection from %s\n", 
	 prefix_toa (connection->from));
	 
#ifndef HAVE_LIBPTHREAD
    select_delete_fd2 (connection->sockfd);
#endif /* HAVE_LIBPTHREAD */

   close (connection->sockfd);

   if (connection->ll_peer) {
     LL_Destroy (connection->ll_peer);
     trace (NORM, default_trace, "Cleaned up memory...\n");
   }

   Deref_Prefix (connection->from);
   delete_schedule (connection->schedule);
   Delete (connection);
   RTR.connections--;

   mrt_thread_exit ();
   return (1);
}



static void irr_bs (int fd, int n) {
    char bs = 0x08;
    while (n--) {
	write (fd, &bs, 1);
    }
}

static void irr_bell (int fd) {
    char bell = 0x07;
    write (fd, &bell, 1);
}



int irr_add_answer (irr_connection_t *irr, char *format, ...) {
  va_list args;
  int len;

  if (irr->answer == NULL) {
    irr->answer = malloc (RTR_OUTPUT_BUFFER_SIZE);
    irr->cp = irr->answer;
    irr->answer_len = 0;
  }

  if (irr->answer_len > (RTR_OUTPUT_BUFFER_SIZE - 200)) {
    return (-1);
  }

  va_start (args, format);
  vsprintf (irr->cp, format, args);  

  /*sprintf (irr->cp, "%s", s);*/
  len = strlen (irr->cp);
  irr->cp += len;
  irr->answer_len += len;

  return (1);
}



/* irr_send_bulk_data
 * A "more"  -- when we need to send pages of information (i.e. BGP table dumps)
 * out to the irr socket.
 *
 * When we get around to it, we should figure out how to
 *  1) get termcap string to clear screen
 *  2) and learn how big the screen is (how many lines). I think this comes during
 *     the telnet setup negotiations?
 *
 */
void irr_send_answer (irr_connection_t * irr) {
  char *cp, tmp[20];
  int n, no_eol = 0;

  cp = irr->answer;
  if (cp == NULL) {
    sprintf (tmp, "D\r\n");
    n = write (irr->sockfd, tmp, strlen (tmp));
    return;
  }

  if (irr->answer[irr->answer_len -1] != '\n') {
    no_eol = 1;
  }

  /* add two bytes for terminating carrige return */
  sprintf (tmp, "A%d\n", irr->answer_len + no_eol); 
  if (((n = buffered_write (irr->sockfd, tmp, strlen (tmp), 30)) <= 0) ||
      ((n = buffered_write (irr->sockfd, irr->answer, 
			    irr->answer_len, 30)) <= 0)) {
    irr_destroy_connection (irr);
    return;
  }
  

  if (no_eol) {
    sprintf (tmp, "\n");
    n = write (irr->sockfd, tmp, strlen (tmp));
  }

  sprintf (tmp, "C\n");
  n = write (irr->sockfd, tmp, strlen (tmp));

  Delete (irr->answer);
  irr->answer = NULL;
  return;
}



void irr_send_okay (irr_connection_t * irr) {
  char tmp[20];
  sprintf (tmp, "C\r\n");
  write (irr->sockfd, tmp, strlen (tmp));
}


void irr_send_error (irr_connection_t * irr) {
  char tmp[20];
  sprintf (tmp, "D\r\n");
  write (irr->sockfd, tmp, strlen (tmp));
}



/* buffered_write
 */
int buffered_write (int fd, char *buffer, int len, int usec) {
  fd_set fdvar_write;
  struct timeval tv;
  char *cp;
  int w, n = 0;

  tv.tv_sec = 0; /* XXX */
  tv.tv_usec = usec;

  cp = buffer;

  if (fd < 0) {return 0;}

  FD_ZERO (&fdvar_write);
  FD_SET(fd, &fdvar_write);

  while (n < len) {
    FD_ZERO (&fdvar_write);
    FD_SET(fd, &fdvar_write);

    if (select (FD_SETSIZE, NULL, &fdvar_write, NULL, &tv) <= 0)
      return (0);

    /* server isn't ready for us -- we have timed out */
    if (!FD_ISSET (fd, &fdvar_write)) return (0);

    w = write (fd, cp, len - n);
    if (w <= 0) return (-1);
    n += w;
  }
  return (1);
}
