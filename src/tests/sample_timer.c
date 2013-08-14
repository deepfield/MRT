/*
 * $Id: sample_timer.c,v 1.1.1.1 2000/08/14 18:46:16 labovit Exp $
 */


/*-----------------------------------------------------------
 *  Program: 	sample_timer.c
 *  Created:	Thu Mar 30 17:52:42 1995
 *  Author: 	Craig Labovitz   <labovit@snoopy.merit.net>
 *  DESCR:  	A trivial demonstration of the MRT timer library
 */


#include <stdio.h>
#include <timer.h>  
#include <version.h>


void my_timer_fire(Timer *timer) {  
   printf("%s I have fired %d\n", timer->name, time (NULL)); 

#ifdef SOLARIS
   thr_exit (0);
#endif /* SOLARIS */
}



main () {
   Timer *timer1, *timer2;
   int ret;

#ifdef SOLARIS
   thr_setconcurrency (10);
#endif

   init_timer_master();

   timer1 = New_Timer (my_timer_fire, 2, "timer2", NULL);   
   timer2 = New_Timer (my_timer_fire, 4, "timer4", NULL);

   Timer_Turn_ON (timer1);   
   Timer_Turn_ON (timer2);
  
   /* loop forever */   while (1); 
}
