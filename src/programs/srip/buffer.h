/*
 * $Id: buffer.h,v 1.1.1.1 2000/08/14 18:46:15 labovit Exp $
 */

#ifndef _BUFFER_H
#define _BUFFER_H


#define DEFAULT_MAXBUFFERSIZE 1024

typdef struct _Buffer_Struct {
   int 			maxsize;
   u_char               *buffer;
   u_char 		*read_ptr;      /* current ptr of read in buffer */
   u_char 		*start_ptr;     /* current ptr of start of packet */
   int			room_in_buffer; /* bytes left in buffer */


} Buffer_Struct;




#endif /* _BUFFER_H */


