/* 
 * $Id: io.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

/* TODO:
 *    - provide multiple inputs/outputs per process or per thread?
 *        right now each process has only one input and one output stream.
 */


#include <mrt.h>
#ifndef NT
#include <sys/ipc.h>
#include <sys/msg.h>
#endif /* NT */

static int io_setup (enum IO_ATTR attr, io_t * IO, void *arg);
static int close_input (io_t * io);
static int close_output (io_t * io);
static int add_myq (char *client);
static int del_myq (int mqid, char *client);
static int get_destq (char *client);
static mrt_msg_t *io_file_read (io_t * io);
static mrt_msg_t *io_msgq_read (int mqid);


io_t *MASTER_IO;

/* public */
char *S_MRT_MSG_TYPES[] =
{
    "MSG_NULL", /* 0 */
    "START",	/* 1 */
    "DIE",	/* 2 */
    "I_AM_DEAD",	/* 3 */
    "PEER_DOWN",	/* 4 */
    "BGP",	/* 5 */
    "RIP",	/* 6 */
    "IDRP",	  /* 7 */
    "RIPNG",	  /* 8 */
    "BGP4+",	  /* 9 */
    "BGP4+(1)",	  /* 10 */
    "OSPF",	  /* 11 */
    "TABLE_DUMP", /* 12 */
    "? (13)",	/* 13 */
    "? (14)",	/* 14 */
    "? (15)",	/* 15 */
    "BGP4MP",	/* 16 */
    NULL,
};


char *S_MRT_MSG_BGP_TYPES[] =
{
    "NULL",	/* 0 */
    "UPDATE",	/* 1 */
    "PREF_UPDATE",	/* 2 */
    "STATE_CHANGE",	/* 3 */
    "SYNC",	/* 4 */
    "OPEN",	/* 5 */
    "NOTIFY",	/* 6 */
    "KEEPALIVE",	/* 7 */
    NULL,
};


char *S_MRT_MSG_BGP4MP_TYPES[] =
{
    "STATE_CHANGE",	/* 0 */
    "MESSAGE",	/* 1 */
    "ENTRY",	/* 2 */
    "SNAPSHOT",	/* 3 */
    "MESSAGE_OLD",	/* 4 */
    NULL,
};

char *S_MRT_MSG_OSPF_TYPES[] = 
{
  "STATE_CHANGE",	/* 0 */
  "LSA_UPDATE",		/* 1 */
  NULL,
};

char *S_MRT_MSG_TABLE_DUMP[] = 
{
  "UNKNOWN",
  "INET",	/* 1 */
  "INET6",	/* 2 */
  NULL,
};

char **S_MRT_MSG_SUBTYPES[] =
{
    NULL, /* MSG_NULL */
    NULL, /* START */
    NULL, /* DIE */
    NULL, /* I_AM_DEAD */
    NULL, /* PEER_DOWN */
    S_MRT_MSG_BGP_TYPES, /* BGP */
    NULL, /* RIP */
    NULL, /* IDRP */
    NULL, /* RIPNG */
    S_MRT_MSG_BGP_TYPES, /* BGP4+ */
    S_MRT_MSG_BGP_TYPES, /* BGP4+(1) */
    NULL, /* 11 */
    S_MRT_MSG_TABLE_DUMP, /* TABLE_DUMP */
    NULL, /* 13 */
    NULL, /* 14 */
    NULL, /* 15 */
    S_MRT_MSG_BGP4MP_TYPES, /* 16 */
    NULL,
};


#ifdef HAVE_LIBPTHREAD
static void
io_recv_mesg (io_t * io)
{
    mrt_msg_t *msg;

    while (1) {
	msg = io_read (io);

	if (msg == NULL)
	    return;

	if (io->call_fn)
	    io->call_fn (msg);
	else
	    Delete (msg);
    }

    /* NOT REACHED */
}

static void
_io_start (io_t * io)
{
    init_mrt_thread_signals ();
    select_add_fd (io->in.fd, 1, io_recv_mesg, io);

    trace (TR_THREAD, io->trace, "THREAD starting for IO\n");
    while (1)
	schedule_wait_for_event (io->schedule);
    /* NOT REACHED */
}
#endif /* HAVE_LIBPTHREAD */


/* io_start
 * Start async IO on its own thread. Responsibility of
 * called func to delete mesg
 */
int
io_start (io_t * io)
{
#ifdef HAVE_LIBPTHREAD
    pthread_t thread;

    if (pthread_create (&thread, NULL, (thread_fn_t) _io_start, io) < 0) {
        trace (ERROR, io->trace, "THREAD pthread_create failed for IO\n");
	return (-1);
    }
#endif /* HAVE_LIBPTHREAD */
    return (1);
}


static int
io_file_write (io_t * io, u_long tstamp, u_short type, u_short subtype,
	       u_long length, void *value)
{
    u_int l = length;

    pthread_mutex_lock (&io->mutex_lock);

    tstamp = htonl (tstamp);
    type = htons (type);
    subtype = htons (subtype);
    length = htonl (length);

    if ((write (io->out.fd, &tstamp, 4) != 4) ||
	(write (io->out.fd, &type, 2) != 2) ||
	(write (io->out.fd, &subtype, 2) != 2) ||
	(write (io->out.fd, &length, 4) != 4) ||
	(write (io->out.fd, value, l) == -1)) {
	pthread_mutex_unlock (&io->mutex_lock);

	return (-1);
    }

    pthread_mutex_unlock (&io->mutex_lock);

    return (0);
}


static int
io_msgq_write (io_t * io, u_long tstamp, u_short type, u_short subtype,
	       u_long length, void *value)
{
    mrt_msg_t msg;

    msg.priority = 1;
    msg.tstamp = tstamp;
    msg.type = type;
    msg.subtype = subtype;
    msg.length = length;
    memcpy (msg.value, value, MAX_MSG_SIZE);

#ifndef NT
    fprintf (stderr, "io_msgq_write: sending msg (len %ld) to mqid %d\n",
	     length, io->out.mq.mqid);

    if (msgsnd (io->out.mq.mqid, (struct msgbuf *) &msg, sizeof (mrt_msg_t), 0) < 0)
	return -1;
    else
#endif /* NT */
	return 0;
}


/* this can be used even for an pipe */
static int
piperead (int fd, void *bufp, int len)
{
    int n, m;

    n = 0;
    do {
        m = read (fd, ((char *) bufp) + n, len - n);
	if (m == 0)
	    return (n);
	if (m < 0) {
	    return (-1);
	}
	n += m;
    } while (n < len);

    return (n);
}


/* do I need to buffer? probaly */
static mrt_msg_t *
io_file_read (io_t * io)
{
    mrt_msg_t *tmp;

    if ((tmp = New (mrt_msg_t)) == NULL)
	return NULL;

    if ((piperead (io->in.fd, &(tmp->tstamp), 4) != 4) ||
	(piperead (io->in.fd, &(tmp->type), 2) != 2) ||
	(piperead (io->in.fd, &tmp->subtype, 2) != 2) ||
	(piperead (io->in.fd, &tmp->length, 4) != 4)) {
	Delete (tmp);
	/* maybe EOF. can't determine. need to change XXX */
	/* trace (TR_ERROR, io->trace, "unexpected EOF (%m)\n");
	   io->error = -1; */
	return NULL;
    }

    tmp->tstamp = ntohl (tmp->tstamp);
    tmp->type = ntohs (tmp->type);
    tmp->subtype = ntohs (tmp->subtype);
    tmp->length = ntohl (tmp->length);

    /* sanity checks */
    if ((tmp->length < 0) || (tmp->length > MAX_MSG_SIZE)) {
	Delete (tmp);
	trace (TR_ERROR, io->trace, "Wrong message length (%d)\n", tmp->length);
	io->error = -1;
	return NULL;
    }

    if (piperead (io->in.fd, tmp->value, tmp->length) != tmp->length) {
        Delete (tmp);
	trace (TR_ERROR, io->trace, "Can't read %d bytes (%m)\n", tmp->length);
	io->error = -1;
        return NULL;
    }

    trace (TR_TRACE, io->trace, "Read %d bytes type %d subtype %d\n", 
	   tmp->length, tmp->type, tmp->subtype);
    return (tmp);
}


static mrt_msg_t *
io_msgq_read (int mqid)
{
    mrt_msg_t *msg;

    fprintf (stderr, "io_msgq_read: invoked with mqid=%d\n", mqid);

    if ((msg = New (mrt_msg_t)) == NULL)
	return NULL;
#ifndef NT
    if (msgrcv (mqid, (struct msgbuf *) msg, sizeof (mrt_msg_t), 0, 0) < 0) {
	Delete (msg);
	return NULL;
    }
#endif /* NT */

    return msg;
}


static int
io_setup (enum IO_ATTR attr, io_t * IO, void *arg)
{
    char *name;

    switch (attr) {
    case IO_INNONE:
	if (close_input (IO) != 0)
	    return -1;
	break;

    case IO_OUTNONE:
	if (close_output (IO) != 0)
	    return -1;
	break;

    case IO_OUTFILE:
	name = (char *) arg;
	if (close_output (IO) != 0)
	    return -1;
	if (strcasecmp (name, "stdout") == 0) {
	    IO->out.fd = 1;
	}
	else {
	    if ((IO->out.fd =
		 open (name, (O_CREAT | O_TRUNC | O_WRONLY), 0666)) < 0)
		return -1;
	}
	IO->io_output_type = IO_FILE;
	IO->out_bytes = 0;
	if (IO->io_out_name)
	    Delete (IO->io_out_name);
	IO->io_out_name = strdup (name);
	IO->out_open_time = time (0);
	break;

    case IO_OUTAPPEND:
	name = (char *) arg;
	if (close_output (IO) != 0)
	    return -1;
	if ((IO->out.fd = open (name, (O_APPEND | O_CREAT | O_WRONLY), 0666)) < 0)
	    return -1;
	lseek (IO->out.fd, 0, SEEK_END);
	IO->io_output_type = IO_FILE;
	IO->out_bytes = 0;
	if (IO->io_out_name)
	    Delete (IO->io_out_name);
	IO->io_out_name = strdup (name);
	IO->out_open_time = time (0);
	break;

    case IO_INFILE:
	name = (char *) arg;
	if (close_input (IO) != 0)
	    return -1;
	if (strcasecmp (name, "stdin") == 0) {
	    IO->in.fd = 0;
	}
	else {
	    if ((IO->in.fd = open (name, O_RDONLY, 0)) < 0)
		return -1;
	}
	IO->io_input_type = IO_FILE;
	IO->in_bytes = 0;
	if (IO->io_in_name)
	    Delete (IO->io_in_name);
	IO->io_in_name = strdup (name);
	IO->in_open_time = time (0);
	break;

#ifndef NT
    case IO_INMSGQ:
	name = (char *) arg;
	if (close_input (IO) != 0)
	    return -1;
	if ((IO->in.mq.mqid = add_myq (name)) < 0)
	    return -1;
	safestrncpy (IO->in.mq.clientid, name, CLIENTLEN);
	IO->io_input_type = IO_MSGQ;
	IO->in_bytes = 0;
	if (IO->io_in_name)
	    Delete (IO->io_in_name);
	IO->io_in_name = strdup (name);
	IO->in_open_time = time (0);
	break;

    case IO_OUTMSGQ:
	name = (char *) arg;
	if (close_output (IO) != 0)
	    return -1;
	if ((IO->out.mq.mqid = get_destq (name)) < 0)
	    return -1;
	safestrncpy (IO->out.mq.clientid, name, CLIENTLEN);
	IO->io_output_type = IO_MSGQ;
	IO->out_bytes = 0;
	if (IO->io_out_name)
	    Delete (IO->io_out_name);
	IO->io_out_name = strdup (name);
	IO->out_open_time = time (0);
	break;
#endif /* NT */ 

    case IO_RECV_CALL_FN:
	IO->call_fn = (void_fn_t) arg;
	break;

    default:
	return -1;
    }

    return 0;
}



void Delete_IO (io_t *IO) {
  if (IO->io_out_name) 
    Delete (IO->io_out_name);
  if (IO->io_in_name) 
    Delete (IO->io_in_name);
  Delete (IO);
}

/* New_IO
 * Create a New IO object and initialize
 */
io_t *
New_IO (trace_t * tr)
{

    io_t *tmp = New (io_t);

    pthread_mutex_init (&tmp->mutex_lock, NULL);

    tmp->io_input_type = IO_NONE;
    tmp->io_output_type = IO_NONE;
    tmp->trace = tr;

    return (tmp);
}


/* io_set
 * Attach the input and output streams.
 */
int
io_set (io_t * io, int first,...)
{
    va_list ap;
    enum IO_ATTR attr;

    /* Process the Arguments */
    va_start (ap, first);
    for (attr = (enum IO_ATTR) first; attr != IO_NULL;
	 attr = va_arg (ap, enum IO_ATTR)) {
	if (io_setup (attr, io, va_arg (ap, char *)) != 0)
	      return -1;
    }
    va_end (ap);

    return 0;
}


/* Close input stream. */
static int
close_input (io_t * IO)
{
    int ret = 0;

    switch (IO->io_input_type) {
    case IO_NONE:
	break;

    case IO_FILE:
	if (IO->in.fd > 2) /* XXX */
	    ret = close (IO->in.fd);
	break;

#ifndef NT
    case IO_MSGQ:
	printf ("close_input: removing qid %d, clientid %s\n",
		IO->in.mq.mqid, IO->in.mq.clientid);
	ret = del_myq (IO->in.mq.mqid, IO->in.mq.clientid);
	break;
#endif /* NT */

    default:
	ret = -1;
	break;
    }

    IO->io_input_type = IO_NONE;
    return (ret);
}


/* Close output stream. */
static int
close_output (io_t * IO)
{
    int ret = 0;

    switch (IO->io_output_type) {
    case IO_NONE:
	break;

    case IO_FILE:
	if (IO->out.fd > 2)
	    ret = close (IO->out.fd);
	break;

    case IO_MSGQ:
	break;

    default:
	ret = -1;
	break;
    }

    IO->io_output_type = IO_NONE;
    return (ret);
}


/* Create and register a message queue with the key registry.  Returns
   the MQID for our message queue, or -1 on error. */
static int
add_myq (char *client)
{
#ifndef NT
    int mqid;
    int server_qid;
    ARB_MSG_Struct msg;

    /* create queue */
    /*if((mqid = msgget(GETKEY(), (IPC_CREAT | IPC_EXCL | 0622))) < 0) */
    if ((mqid = msgget (GETKEY (), (IPC_CREAT | IPC_EXCL | 0666))) < 0)
	return -1;

    /* get server's qid */
    if ((server_qid = msgget (MSGSERVER_KEY, 0222)) < 0)
	return -1;

    /* build message */
    msg.priority = 1;
    msg.type = MSG_SETMBOX;
    msg.sender = GETKEY ();
    safestrncpy (msg.mqinfo.client, client, CLIENTLEN);
    msg.mqinfo.key = GETKEY ();

    /* register */
    if (msgsnd (server_qid, (struct msgbuf *) &msg, sizeof (ARB_MSG_Struct), 0) < 0)
	return -1;

    return mqid;
#endif /* NT */
}


/* De-allocate our message queue, and unregister from the client-ID
   registry. */
static int
del_myq (int mqid, char *client)
{
#ifndef NT
    int server_qid;
    ARB_MSG_Struct msg;

    /* get the server's qid */
    if ((server_qid = msgget (MSGSERVER_KEY, 0222)) < 0)
	return -1;

    /* assemble the query */
    msg.priority = 1;
    msg.type = MSG_CLRMBOX;
    msg.sender = GETKEY ();
    safestrncpy (msg.mqinfo.client, client, CLIENTLEN);
    msg.mqinfo.key = GETKEY ();

    /* send query */
    if (msgsnd (server_qid, (struct msgbuf *) &msg, sizeof (ARB_MSG_Struct), 0) < 0)
	return -1;

    /* if that worked, remove our message queue */
    if (msgctl (mqid, IPC_RMID, (struct msqid_ds *) NULL) < 0)
	return -1;

#endif /* NT */
    return 0;
}

/* Query the message queue key registry for the specified client ID,
   and open a message queue on the returned key.  Returns the open
   MQID, or -1 on error. */
static int
get_destq (char *client)
{
#ifndef NT
    int mqid;
    int server_qid;
    int need_rm = 1;
    ARB_MSG_Struct msg;
    extern int errno;

    /* Get a mailbox endpoint to receive the message from the server.
       Try to create one first; if it already exists, assume we made it
       and use it. */
    if ((mqid = msgget (GETKEY (), (IPC_CREAT | IPC_EXCL | 0666))) < 0) {
	if (errno == EEXIST) {
	    /*if((mqid = msgget(GETKEY(), 0622)) < 0) { */
	    if ((mqid = msgget (GETKEY (), 0666)) < 0) {
		return -1;
	    }
	    else {
		need_rm = 0;
	    }
	}
	else {
	    return -1;
	}
    }

    /* get the server's mailbox */
    if ((server_qid = msgget (MSGSERVER_KEY, 0222)) < 0)
	return -1;

    /* assemble the query */
    msg.priority = 1;
    msg.type = MSG_GETMBOX;
    msg.sender = GETKEY ();
    safestrncpy (msg.mqinfo.client, client, CLIENTLEN);
    msg.mqinfo.key = 0;

    /* send query */
    if (msgsnd (server_qid, (struct msgbuf *) &msg, sizeof (ARB_MSG_Struct), 0) < 0)
	return -1;

    /* read reply */
    if (msgrcv (mqid, (struct msgbuf *) &msg, sizeof (ARB_MSG_Struct), 0, 0) < 0)
	return -1;

    /* clean up if necessary */
    if (need_rm)
	msgctl (mqid, IPC_RMID, (struct msqid_ds *) NULL);

    /* finally, open the message queue with the client key */
    if ((mqid = msgget (msg.mqinfo.key, 0222)) < 0)
	return -1;

    return mqid;
#endif /* NT */
}


/* io_set_notify
 */
int 
io_set_notify (io_t * io, int method, void (*call_fn) ())
{

    if (method == 1) {
	select_add_fd (io->in.fd, 1, call_fn, NULL);
	return (1);
    }
    else
	return (-1);

}


/* 
 * Read and return the next message packet.
 */
mrt_msg_t *
io_read (io_t * io)
{
    mrt_msg_t *msg;

    switch (io->io_input_type) {
    case IO_NONE:
	return (NULL);
	break;
    case IO_FILE:
	if ((msg = io_file_read (io)) != NULL)
	    io->in_bytes += (msg->length + 12);
	return (msg);
	break;
#ifndef NT
    case IO_MSGQ:
	if ((msg = io_msgq_read (io->in.mq.mqid)) != NULL)
	    io->in_bytes += (msg->length + 12);
	return (msg);
	break;
#endif /* NT */
    default:
	/* XXX printf should be removed in production code */
	printf ("\nUnknown io type %d", MASTER_IO->io_input_type);
	return NULL;
    }
}


/*
 * Place the given information into a message packet and
 * send it.
 */
int
io_write (io_t * io,
   time_t tstamp, u_short type, u_short subtype, u_long length, void *value)
{
    int ret;

    if (tstamp <= 0)
	tstamp = time (NULL);

    switch (io->io_output_type) {
    case IO_NONE:
	return (0);
	break;
    case IO_FILE:
	ret = io_file_write (io, tstamp, type, subtype, length, value);
	if (ret >= 0)
	    io->out_bytes += (length + 12);
	return (ret);
	break;
    case IO_MSGQ:
	ret = io_msgq_write (io, tstamp, type, subtype, length, value);
	if (ret >= 0)
	    io->out_bytes += (length + 12);
	return (ret);
	break;
    default:
	/* XXX printf should be removed in production code */
	printf ("\nUnknown io type");
	return -1;
    }
}
