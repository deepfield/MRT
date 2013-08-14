/*
 * $Id: sample_select.c,v 1.1.1.1 2000/08/14 18:46:16 labovit Exp $
 */


/*-----------------------------------------------------------
 *  Program: 	sample_trace.c
 *  Created:	Thu Mar 30 17:52:42 1995
 *  Author: 	Craig Labovitz   <labovit@snoopy.merit.net>
 *  DESCR:  	A trivial demonstration of the MRT trace library
 */


#include <stdio.h>
#include <mrt.h>
#include <select.h>

#define MAXBUFF 100

void call_me () {
  char buf[MAXBUFF];
  int r;
  
  while ((r = read (0, buf, MAXBUFF)) != MAXBUFF) {
    buf[r] = '\0';
    printf ("Read %d bytes: %s", r, buf);
  }

  select_enable_fd (0);
}

main () {

#ifdef SOLARIS
  thr_setconcurrency (20);
#endif 

  init_select ();

  select_add_fd (0, 1, call_me, NULL);
  while (1);
}


