/*
 * $Id: io.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef _IO_H
#define _IO_H


#ifndef NT
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#endif /* NT */

#include <mrt.h>
#include <timer.h>
#include <schedule.h>


/* All programs use BASE_KEY as the base for their message-queue key.
   BASE_KEY has been chosen arbitrarily and will hopefully not
   conflict with other applications running on the same machine.  The
   message server uses the special value BASE_KEY | 1 for its message
   queue.  All others use GETKEY(), which bases the key on PID.  (This
   could be augmented with thread-ID, if it becomes necessary.)  */
#define BASE_KEY	(0x50 << 16)
#define MSGSERVER_KEY	(BASE_KEY | 1)
#define GETKEY()	(BASE_KEY | getpid())

/* maximum length of a client ID */
#define CLIENTLEN 80

/* this is misleading, since it has nothing to do with the message-queue
   I/O functions. */
#define MAX_MSG_SIZE             8192

union IO_Handle {
   int fd;
#ifndef NT
   struct {
      int mqid;
      char clientid[CLIENTLEN];
   } mq;
#endif /* NT */
};



#ifndef NT

typedef struct _MQINFO_Struct {
   char client[CLIENTLEN];
   key_t key;
} MQINFO_Struct;

#endif /* NT */

/* I/O types -- used for io_input_type and io_output_type */
enum IO_TYPES {
   IO_NONE,
   IO_FILE,
   IO_MSGQ
};

/* I/O attributes -- used as key in set_io arglist */
enum IO_ATTR {
   IO_NULL = 0,
   IO_INNONE,			/* no input */
   IO_OUTNONE,			/* no output */
   IO_OUTFILE,			/* output to file (truncate) */
   IO_OUTAPPEND,		/* output to file (append) */
   IO_INFILE,			/* input from file */
   IO_INMSGQ,			/* input from message queue */
   IO_OUTMSGQ,			/* output to message queue */
   IO_RECV_CALL_FN		/* async func to call on new input */
};

typedef struct _io_t {
   pthread_mutex_t   	mutex_lock;
   schedule_t		*schedule;	/* event processing */
   trace_t		*trace;
   time_t		last;
   enum IO_TYPES io_input_type;
   enum IO_TYPES io_output_type;
   char *io_in_name;
   char *io_out_name;
   void_fn_t call_fn;
   union IO_Handle in;
   union IO_Handle out;
   u_long in_bytes;
   u_long out_bytes;
   time_t in_open_time;
   time_t out_open_time;
   int error;
} io_t;


/* message types for an ARB_MSG_Struct */
enum ARB_MSG_TYPES {
   MSG_SETMBOX,			/* set a client/mailbox association */
   MSG_GETMBOX,			/* get a client/mailbox association */
   MSG_CLRMBOX,			/* remove a client/mailbox association */
   MSG_DUMP,			/* dump hash table on stderr */
   MSG_SHUTDOWN			/* shut down */
};


enum MRT_MSG_TYPES {
   MSG_NULL,
   MSG_START,			/* sender is starting up */
   MSG_DIE,			/* receiver should shut down */
   MSG_I_AM_DEAD,		/* sender is shutting down */
   MSG_PEER_DOWN,		/* sender's peer is down */
   MSG_PROTOCOL_BGP,		/* msg is a BGP packet */
   MSG_PROTOCOL_RIP,		/* msg is a RIP packet */
   MSG_PROTOCOL_IDRP,		/* msg is an IDRP packet */
   MSG_PROTOCOL_RIPNG,		/* msg is a RIPNG packet */
   MSG_PROTOCOL_BGP4PLUS,	/* msg is a BGP4+ packet */
   MSG_PROTOCOL_BGP4PLUS_01,	/* msg is a BGP4+ (draft 01) packet */
   MSG_PROTOCOL_OSPF,		/* msg is an OSPF packet */
   MSG_TABLE_DUMP		/* routing table dump */
};


enum MRT_MSG_BGP_TYPES {
   MSG_BGP_NULL,
   MSG_BGP_UPDATE,	/* raw update packet (contains both with and ann) */
   MSG_BGP_PREF_UPDATE, /* tlv preferences followed by raw update */
   MSG_BGP_STATE_CHANGE,/* state change */
   MSG_BGP_SYNC,	/* sync point with dump */
   MSG_BGP_OPEN,
   MSG_BGP_NOTIFY,
   MSG_BGP_KEEPALIVE
};

/* new BGP4MP dump format */
/* type value */
#define MSG_PROTOCOL_BGP4MP 16
/* subtype value */
#define BGP4MP_STATE_CHANGE 0
#define BGP4MP_MESSAGE 1
#define BGP4MP_ENTRY 2
#define BGP4MP_SNAPSHOT 3
#define BGP4MP_MESSAGE_OLD 4	/* previous BGP4MP packet format */

enum MRT_MSG_OSPF_TYPES {
  MSG_OSPF_STATE_CHANGE,
  MSG_OSPF_LSA_UPDATE
};

#ifndef NT
typedef struct _ARB_MSG_Struct {
   u_long priority;		/* required by msgget/msgrcv */
   enum ARB_MSG_TYPES type;	/* message type */
   key_t sender;		/* sender key (for replies) */
   MQINFO_Struct mqinfo;	/* message queue info */
} ARB_MSG_Struct;
#endif /* NT */

typedef struct _mrt_msg_t {
   u_long priority;		/* required by msgget/msgrcv */
   time_t tstamp;		/* timestamp */
   u_short type;		/* msg type, one of MRT_MSG_TYPES */
   u_short subtype;		/* msg subtype, protocol-specific */
   u_long length;		/* length of data */
   u_char value[MAX_MSG_SIZE];	/* data */
} mrt_msg_t;


/* Public functions */
int io_start (io_t *io);
io_t *New_IO (trace_t *tr);
int io_set (io_t *io, int first, ...);
mrt_msg_t *io_read (io_t *io);
int io_write (io_t *io, time_t tstamp, u_short type, u_short subtype, 
	      u_long length, void *value);
int io_set_notify (io_t * io, int method, void (*call_fn) ());
void Delete_IO (io_t *IO);

extern io_t *MASTER_IO;
extern char *S_MRT_MSG_TYPES[];
extern char *S_MRT_MSG_BGP_TYPES[];
extern char *S_MRT_MSG_OSPF_TYPES[];
extern char **S_MRT_MSG_SUBTYPES[];

#endif /* _IO_H */
