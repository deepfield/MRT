#define DEFAULT_SERVICE_NAME 		"/tmp/port_server"


int register_with_port_server (char *process, int port, long ip_address);
int recvfile (int sockfd);
int sendfile (int sockfd, int fd);
