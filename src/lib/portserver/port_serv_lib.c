/*
 * $Id: port_serv_lib.c,v 1.1.1.1 2000/08/14 18:46:13 labovit Exp $
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <netdb.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <mrt.h>
#include <timer.h>
#include <port_serv_lib.h>



int register_with_port_server (char *process, int port, long ip_address) {
   int sockfd;
   struct sockaddr sockname;
   u_char buffer[1024];
   fd_set fdvar_read;
   char *cp = buffer;

   sockfd= socket (AF_UNIX, SOCK_STREAM, 0);
   sockname.sa_family = AF_UNIX;
   strcpy (sockname.sa_data, DEFAULT_SERVICE_NAME);

   if (connect (sockfd, &sockname, strlen (DEFAULT_SERVICE_NAME) + 2) == -1) {
      perror ("BAD Connection");
      return (-1);
   }

   UTIL_PUT_LONG (port, cp);
   UTIL_PUT_LONG (ip_address, cp);

   printf ("\nPORT = %d", port);

   write (sockfd, buffer, 8);
   
   bzero (buffer, 100);

   FD_ZERO(&fdvar_read);
   FD_SET (sockfd, &fdvar_read);

   select (FD_SETSIZE, &fdvar_read, NULL, NULL, NULL);
   read (sockfd, buffer, 2);

   if (buffer[0] == 0) {
      errno = buffer[1];
      return (-1);
   }

   return (sockfd);
}

























/*-----------------------------------------------------------
 *  Name: 	sendfile
 *  Created:	Tue Dec 20 16:13:56 1994
 *  Author: 	Code taken from Stevens, Unix Network Programming
 *  DESCR:  	
 */

int sendfile (int sockfd, int fd)
{

   struct iovec		iov[1];
   struct msghdr	msg;
   extern int		errno;

   iov[0].iov_base = (char *) 0;
   iov[0].iov_len  = 0;
   msg.msg_iov	= iov;
   msg.msg_iovlen = 1;
   msg.msg_name = (caddr_t) 0;
   msg.msg_accrights = (caddr_t) &fd;  
   msg.msg_accrightslen = sizeof (fd);

   if (sendmsg (sockfd, &msg, 0) < 0)
      return ((errno <0) ? errno : 255);

   return (0);
}

/*-----------------------------------------------------------
 *  Name: 	recvfile
 *  Created:	Tue Dec 20 16:13:56 1994
 *  Author: 	Code taken from Stevens, Unix Network Programming
 *  DESCR:  	
 */
int recvfile (int sockfd)
{
   int fd;
   struct iovec iov[1];
   struct msghdr msg;

   iov[0].iov_base = (char *) 0;
   iov[0].iov_len  = 0;
   msg.msg_iov	= iov;
   msg.msg_iovlen = 1;
   msg.msg_name = (caddr_t) 0;
   msg.msg_accrights = (caddr_t) &fd;
   msg.msg_accrightslen = sizeof (fd);

   if (recvmsg (sockfd, &msg, 0) < 0)
      return (-1);

   return (fd);
}




