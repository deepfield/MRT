/*
 * $Id: qif.c,v 1.1.1.1 2000/08/14 18:46:14 labovit Exp $
 */

#include "ricd.h"

#ifdef HAVE_RIC
#include <net/route_qos.h>
#include <net/rtqos.h> 
#include <netinet/ip_qroute.h>

static int initialized = 0;
static int seq = 0;
static int qos_rtsock = -1;


static int
qif_sendmsg (struct rt_msghdr *rtm)
{
    int ret;

    if (qos_rtsock < 0)
	return (-1);
    rtm->rtm_version = RTM_VERSION;
    rtm->rtm_seq = ++seq;
    if ((ret = write (qos_rtsock, rtm, rtm->rtm_msglen)) < 0) {
	trace (TR_ERROR, MRT->trace, 
		"QIF write on qos routing socket %d (%m)\n",
	       qos_rtsock);
    }
    return (ret);
}


typedef union _qos_rtflow_t {
    struct rtflow fa;
    struct rtflow_in fin;
#ifdef HAVE_RIC6
    struct rtflow_in6 fin6;
#endif /* HAVE_RIC6 */
} qos_rtflow_t;


static void
qif_rtmsg_rcv (int sockfd)
{   
    int n, family;
    u_char msgbuf[4096]; /* I don't know how much is enough */
    struct rt_msghdr *rtm = (struct rt_msghdr *) msgbuf;
    struct qos_msghdr *qosm = (struct qos_msghdr *) (rtm + 1);
    qos_rtflow_t *qosr = (qos_rtflow_t *) (qosm + 1);
    prefix_t sdestin, ssender;
    srsvp_flow_t sflow;
    u_char *saddr, *daddr;
    srsvp_t *srsvp;
    
    assert (sockfd == qos_rtsock);
    if ((n = read (sockfd, msgbuf, sizeof (msgbuf))) > 0) {
        if (rtm->rtm_seq != 0 || (rtm->rtm_type != RTM_POLICY_SEND &&
	    rtm->rtm_type != RTM_QOS_RECV && rtm->rtm_type != RTM_QOS_SEND)) {
	    select_enable_fd (sockfd);
	    return;
	}

	memset (&sflow, 0, sizeof (sflow));
	sflow.destin = &sdestin;
	sflow.sender = &ssender;
	sflow.req_qos = (req_qos_t *)&qosm->qos;

	family = qosr->fa.family;
#ifdef HAVE_IPV6
	if (family == AF_INET6) {
	    saddr = (u_char *)&qosr->fin6.src;
	    daddr = (u_char *)&qosr->fin6.dest;
	    sflow.sport = ntohs (qosr->fin6.sport);
	    sflow.dport = ntohs (qosr->fin6.dport);
	    sflow.proto = qosr->fin6.proto;
	    srsvp = RICD6->srsvp;
	}
	else
#endif /* HAVE_IPV6 */
	{
	    saddr = (u_char *)&qosr->fin.src;
	    daddr = (u_char *)&qosr->fin.dest;
	    sflow.sport = ntohs (qosr->fin.sport);
	    sflow.dport = ntohs (qosr->fin.dport);
	    sflow.proto = qosr->fin.proto;
    	    srsvp = RICD->srsvp;
	}
	New_Prefix2 (family, saddr, -1, &ssender);
	New_Prefix2 (family, daddr, -1, &sdestin);

	switch (rtm->rtm_type) {
	    case RTM_POLICY_SEND:
	    case RTM_QOS_SEND:
    		trace (TR_TRACE, MRT->trace, "QIF QOS_SEND received "
			"for %a port %d\n", sflow.destin, sflow.dport);
/*
    		schedule_event2 ("srsvp_flow_request_by_app",
                     		 srsvp->schedule,
                     		 (event_fn_t) srsvp_flow_request_by_app,
                     		 3, srsvp, &sflow, 'S');
*/
                srsvp_flow_request_by_app (srsvp, &sflow, 'S');
		break;
	case RTM_QOS_RECV:
    		trace (TR_TRACE, MRT->trace, "QIF QOS_RECV received "
			"for %a port %d\n", sflow.destin, sflow.dport);
                srsvp_flow_request_by_app (srsvp, &sflow, 'R');
		break;
	}
    }
    else {
        trace (TR_ERROR, MRT->trace, 
		"QIF read on qos routing socket %d (%m)\n",
               sockfd);
    }
    select_enable_fd (sockfd);
}   


int
qif_init (void)
{
    int ret;
    struct rt_msghdr rtm;

    if (initialized++)
        return (0);   

    if (qos_rtsock < 0) {
	int sockfd;
        sockfd = socket_open (PF_ROUTE, SOCK_RAW, 0);
        if (sockfd < 0) {
            trace (TR_ERROR, MRT->trace, "QIF qif_init (%m)\n");
	    return (sockfd);
        }
        qos_rtsock = sockfd;
    }
    
    memset (&rtm, 0, sizeof (rtm));
    rtm.rtm_type = RTM_FLOW_INIT;
    rtm.rtm_msglen = sizeof (rtm);
    if ((ret = qif_sendmsg (&rtm)) < 0) {
        trace (TR_ERROR, MRT->trace, "QIF qif_init (%m)\n");
    }

    trace (TR_INFO, MRT->trace, "QIF initialized\n");
    select_add_fd_event ("qif_rtmsg_rcv", qos_rtsock, SELECT_READ, TRUE,
                          NULL, qif_rtmsg_rcv, 1, qos_rtsock);

    return (ret);
}


int
qif_close (void)
{
    int ret;
    struct rt_msghdr rtm;

    if (qos_rtsock < 0) {
	int sockfd;
        sockfd = socket_open (PF_ROUTE, SOCK_RAW, 0);
        if (sockfd < 0) {
            trace (TR_ERROR, MRT->trace, "QIF qif_close (%m)\n");
	    return (sockfd);
        }
        qos_rtsock = sockfd;
    }

    memset (&rtm, 0, sizeof (rtm));
    rtm.rtm_type = RTM_FLOW_CLOSE;
    rtm.rtm_msglen = sizeof (rtm);
    if ((ret = qif_sendmsg (&rtm)) < 0) {
        /* trace (TR_ERROR, MRT->trace, "QIF qif_close (%m)\n"); */
    }
    return (ret);
}


static int
qif_set_qif (srsvp_t *srsvp, srsvp_interface_t *vif, int type)
{
    u_char msgbuf[1024];
    int ret;
    struct rt_msghdr *rtm = (struct rt_msghdr *) msgbuf;
    struct qos_msghdr *qosm = (struct qos_msghdr *) (rtm + 1);
    sockunion_t *su = (sockunion_t *) (qosm + 1);
    prefix_t *gateway;

    memset (rtm, 0, sizeof (*rtm));
    memset (qosm, 0, sizeof (*qosm));

    assert (type == RTM_QIF_ADD || type == RTM_QIF_DEL);
    rtm->rtm_type = type;
    rtm->rtm_msglen = sizeof (*rtm) + sizeof (*qosm);

    qosm->qifi = vif->interface->index;
    if (type == RTM_QIF_ADD) {
        qosm->flags = QOS_QIF_MULTI;
        qosm->queue_alg = (vif->qalg)? vif->qalg: ALTQ_PRQ; /* XXX */
        qosm->qos.rdly = (vif->qlimit >= 0)? vif->qlimit: 200; /* XXX */
    }

    gateway = vif->prefix;
    assert (gateway);
#ifdef HAVE_IPV6
    if (gateway->family == AF_INET6) {
        memset (su, 0, sizeof (su->sin6));
	su->sin6.sin6_family = AF_INET6;
	su->sin6.sin6_len = sizeof (su->sin6);
	memcpy (&su->sin6.sin6_addr, prefix_tochar (gateway), 16);
    	rtm->rtm_msglen += sizeof (su->sin6);
    }
    else
#endif /* HAVE_IPV6 */
    {
        memset (su, 0, sizeof (su->sin));
        su->sin.sin_family = AF_INET;
	su->sin.sin_len = sizeof (su->sin);
	memcpy (&su->sin.sin_addr, prefix_tochar (gateway), 4);
    	rtm->rtm_msglen += sizeof (su->sin);
    }

    if ((ret = qif_sendmsg (rtm)) < 0) {
        trace (TR_ERROR, MRT->trace, "QIF qif_set_qif (%m)\n");
    }
    else {
        trace (TR_INFO, MRT->trace, "QIF %s:%d %s\n",
		    vif->interface->name, vif->interface->index,
	    (type == RTM_QIF_ADD)? "created": "removed");
    }
    return (ret);
}


int
qif_add_qif (srsvp_t *srsvp, srsvp_interface_t *vif)
{
    return (qif_set_qif (srsvp, vif, RTM_QIF_ADD));
}


int
qif_del_qif (srsvp_t *srsvp, srsvp_interface_t *vif)
{
    return (qif_set_qif (srsvp, vif, RTM_QIF_DEL));
}


static int
qif_set_flow (srsvp_t *srsvp, srsvp_flow_t *flow, srsvp_leaf_t *leaf, int type)
{
    u_char msgbuf[1024];
    int ret;
    struct rt_msghdr *rtm = (struct rt_msghdr *) msgbuf;
    struct qos_msghdr *qosm = (struct qos_msghdr *) (rtm + 1);
    qos_rtflow_t *qosr = (qos_rtflow_t *) (qosm + 1);
    sockunion_t *su;
    prefix_t *gateway;

    memset (rtm, 0, sizeof (*rtm));
    memset (qosm, 0, sizeof (*qosm));

    assert (type == RTM_FLOW_ADD || type == RTM_FLOW_DEL);
    rtm->rtm_type = type;
    rtm->rtm_msglen = sizeof (*rtm) + sizeof (*qosm);

    assert (flow); assert (leaf);
    qosm->qifi = leaf->neighbor->vif->interface->index;
    if (type == RTM_FLOW_ADD) {
        if (flow->upstream)
            qosm->parent = flow->upstream->vif->interface->index;
        else
            qosm->parent = qosm->qifi; /* XXX I'm not sure */
        memcpy (&qosm->qos, leaf->req_qos, sizeof (qosm->qos));
        qosm->flags = (QOS_FLOW_QOS | QOS_FLOW_ROUTE);
    }

    assert (flow->sender);
    assert (flow->destin);
    assert (flow->sender->family == flow->destin->family);
#ifdef HAVE_IPV6
    if (flow->upstream->prefix->family == AF_INET6) {
        memset (qosr, 0, sizeof (qosr->fin6));
	qosr->fin6.family = AF_INET6;
	qosr->fin6.len = sizeof (qosr->fin6);
	qosr->fin6.proto = flow->proto;
	memcpy (&qosr->fin6.src, prefix_tochar (flow->sender), 16);
	memcpy (&qosr->fin6.dest, prefix_tochar (leaf->destin), 16);
	qosr->fin6.sport = htons (flow->sport);
	qosr->fin6.dport = htons (flow->dport);
    	rtm->rtm_msglen += sizeof (qosr->fin6);
        su = (sockunion_t *)(((u_char *) qosr) + sizeof (qosr->fin6));
    }
    else
#endif /* HAVE_IPV6 */
    {
        memset (qosr, 0, sizeof (qosr->fin));
	qosr->fin.family = AF_INET;
	qosr->fin.len = sizeof (qosr->fin);
	qosr->fin.proto = flow->proto;
	memcpy (&qosr->fin.src, prefix_tochar (flow->sender), 4);
	memcpy (&qosr->fin.dest, prefix_tochar (flow->destin), 4);
	qosr->fin.sport = htons (flow->sport);
	qosr->fin.dport = htons (flow->dport);
    	rtm->rtm_msglen += sizeof (qosr->fin);
        su = (sockunion_t *)(((u_char *) qosr) + sizeof (qosr->fin));
    }

    gateway = leaf->neighbor->prefix;
    assert (gateway);
#ifdef HAVE_IPV6
    if (gateway->family == AF_INET6) {
        memset (su, 0, sizeof (su->sin6));
	su->sin6.sin6_family = AF_INET6;
	su->sin6.sin6_len = sizeof (su->sin6);
	memcpy (&su->sin6.sin6_addr, prefix_tochar (gateway), 16);
    	rtm->rtm_msglen += sizeof (su->sin6);
    }
    else
#endif /* HAVE_IPV6 */
    {
        memset (su, 0, sizeof (su->sin));
        su->sin.sin_family = AF_INET;
	su->sin.sin_len = sizeof (su->sin);
	memcpy (&su->sin.sin_addr, prefix_tochar (gateway), 4);
    	rtm->rtm_msglen += sizeof (su->sin);
    }
    qosm->flags |= QOS_FLOW_GATEWAY;

    if ((ret = qif_sendmsg (rtm)) < 0) {
        trace (TR_ERROR, MRT->trace, "QIF qif_set_flow (%m)\n");
    }
    else {
        trace (TR_INFO, MRT->trace, "QIF flow %a port %d index %d %s\n", 
	    flow->destin, flow->dport, qosm->qifi,
	    (type == RTM_FLOW_ADD)? "created": "removed");
    }
    return (ret);
}


int
qif_add_flow (srsvp_t *srsvp, srsvp_flow_t *flow, srsvp_leaf_t *leaf)
{
    return (qif_set_flow (srsvp, flow, leaf, RTM_FLOW_ADD));
}


int
qif_del_flow (srsvp_t *srsvp, srsvp_flow_t *flow, srsvp_leaf_t *leaf)
{
    return (qif_set_flow (srsvp, flow, leaf, RTM_FLOW_DEL));
}


int
qif_notify (srsvp_t *srsvp, srsvp_flow_t *flow, int eno)
{
    u_char msgbuf[1024];
    int ret;
    struct rt_msghdr *rtm = (struct rt_msghdr *) msgbuf;
    struct qos_msghdr *qosm = (struct qos_msghdr *) (rtm + 1);
    qos_rtflow_t *qosr = (qos_rtflow_t *) (qosm + 1);

    memset (rtm, 0, sizeof (*rtm));
    memset (qosm, 0, sizeof (*qosm));

    rtm->rtm_type = RTM_FLOW_EXCEPT;
    rtm->rtm_msglen = sizeof (*rtm) + sizeof (*qosm);

    assert (flow);
    assert (flow->sender);
    assert (flow->destin);
    assert (flow->sender->family == flow->destin->family);
#ifdef HAVE_IPV6
    if (flow->upstream->prefix->family == AF_INET6) {
        memset (qosr, 0, sizeof (qosr->fin6));
	qosr->fin6.family = AF_INET6;
	qosr->fin6.len = sizeof (qosr->fin6);
	qosr->fin6.proto = flow->proto;
	memcpy (&qosr->fin6.src, prefix_tochar (flow->sender), 16);
	memcpy (&qosr->fin6.dest, prefix_tochar (flow->destin), 16);
	qosr->fin6.sport = htons (flow->sport);
	qosr->fin6.dport = htons (flow->dport);
    	rtm->rtm_msglen += sizeof (qosr->fin6);
    }
    else
#endif /* HAVE_IPV6 */
    {
        memset (qosr, 0, sizeof (qosr->fin));
	qosr->fin.family = AF_INET;
	qosr->fin.len = sizeof (qosr->fin);
	qosr->fin.proto = flow->proto;
	memcpy (&qosr->fin.src, prefix_tochar (flow->sender), 4);
	memcpy (&qosr->fin.dest, prefix_tochar (flow->destin), 4);
	qosr->fin.sport = htons (flow->sport);
	qosr->fin.dport = htons (flow->dport);
    	rtm->rtm_msglen += sizeof (qosr->fin);
    }

    if ((ret = qif_sendmsg (rtm)) < 0) {
        trace (TR_ERROR, MRT->trace, "QIF qif_notify (%m)\n");
    }
    return (ret);
}

#else

int qif_init (void) { return (0); }
int qif_close (void) { return (0); }
int qif_add_qif (srsvp_t *srsvp, srsvp_interface_t *vif) { return (0); }
int qif_del_qif (srsvp_t *srsvp, srsvp_interface_t *vif) { return (0); }
int qif_add_flow (srsvp_t *srsvp, srsvp_flow_t *flow, srsvp_leaf_t *leaf)
    { return (0); }
int qif_del_flow (srsvp_t *srsvp, srsvp_flow_t *flow, srsvp_leaf_t *leaf)
    { return (0); }
int qif_notify (srsvp_t *srsvp, srsvp_flow_t *flow, int eno)
    { return (0); }  
#endif /* HAVE_RIC */
