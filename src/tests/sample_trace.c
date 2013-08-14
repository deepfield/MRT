/*
 * $Id: sample_trace.c,v 1.1.1.1 2000/08/14 18:46:16 labovit Exp $
 */


/*-----------------------------------------------------------
 *  Program: 	sample_trace.c
 *  Created:	Thu Mar 30 17:52:42 1995
 *  Author: 	Craig Labovitz   <labovit@snoopy.merit.net>
 *  DESCR:  	A trivial demonstration of the MRT trace library
 */


#include <stdio.h>
#include <trace.h>
#include <version.h>


main () {
   Trace_Struct *protocol_trace;

   protocol_trace = New_Trace_Struct (TRACE_LOGFILE, "/tmp/my_logfile", 
				      TRACE_FLAGS, NORM, 
				      NULL);
   
   trace (NORM, protocol_trace, "This is a trace message");
   trace (TR_POLICY, protocol_trace, "This will not show up");

   Set_Trace_Struct (protocol_trace, 
		     TRACE_FLAGS, TR_ALL, 
		     TRACE_LOGFILE, "stdout",
		     NULL);

   trace (TR_POLICY, protocol_trace, "This will show up on the console");

   trace (FATAL, protocol_trace, "Now I will die... (this shows up in syslog)");

}
