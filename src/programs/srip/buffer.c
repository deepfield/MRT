/* 
 * $I$
 */

#include <stdio.h>
#include <New.h>
#include "buffer.h"



/*-----------------------------------------------------------
 *  Name: 	New_Buffer
 *  Created:	Sun Apr 23 20:36:51 1995
 *  Author: 	Craig Labovitz   <labovit@snoopy.merit.net>
 *  DESCR:  	
 

Buffer_Struct *New_Buffer (int maxsize) {
   Buffer_Struct *tmp;

   tmp = New (Buffer_Struct);

   tmp->maxsize = maxsize;

   tmp->buffer = NewArray (maxsize);

}*/




/*-----------------------------------------------------------
 *  Name: 	buffer_read_socket
 *  Created:	Sun Apr 23 20:37:05 1995
 *  Author: 	Craig Labovitz   <labovit@snoopy.merit.net>
 *  DESCR:  	
 */

u_char *util_read_socket (char *ptr, int sockfd, int nbytes,
			  int block_flag)
{
   int total, n;
   fd_set fdvar_read;
   char *cp;
   
   if (ptr == NULL)
      ptr = NewArray (char, nbytes);

   total = 0;
   cp = ptr;

   FD_ZERO (&fdvar_read);
   FD_SET(sockfd, &fdvar_read);

   while (total < nbytes) {
      if (select (FD_SETSIZE, &fdvar_read, NULL, NULL, NULL) < 0) {
	 perror ("\nselect failed");
	 while (1);
      }
      if ((n = read (sockfd, cp, nbytes - total)) == 0) {
	 /*printf("\nError - 0 bytes (%d)", len - total);
	 perror ("\nread failed");*/
	 return (NULL);
      }
      cp += n;
      total += n;
      /*if (total < len)
	 printf ("\nmising %d out of %d, got %d", len - total, len, total);*/
   }
   /*printf ("\n%d %d bytes", len, total);*/
   return (ptr);
}

