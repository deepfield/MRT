/* 
 * $Id: nt.c,v 1.1.1.1 2000/08/14 18:46:11 labovit Exp $
 */

#include <config.h>
#include <stdio.h>
#include <mrt.h>
#include <winsock2.h>
#include <windef.h>
#include <stdio.h>
#include <stdlib.h>
#include <excpt.h>

#include <IPHlpApi.h>
#include <windows.h>
#include <ws2tcpip.h>

#ifdef HAVE_IPV6
#include <ntddip6.h>
#include <ws2ip6.h>
#endif /* HAVE_IPV6 */

#define RTM_ADD	1
#define RTM_DELETE 2
#define RTM_CHANGE 3

#define MAX_LINK_LEVEL_ADDRESS_LENGTH   64
HANDLE Handle;

#ifdef HAVE_IPV6
int readipv6_interfaces ();
void PrintAddress(IPV6_INFO_ADDRESS *NTE);
void ForEachAddress(IPV6_INFO_INTERFACE *IF, void (*func)(IPV6_INFO_ADDRESS *));
char *FormatIPv6Address(IPv6Addr *Address);
char *FormatDADState(uint DADState);
void krt_read_table_v6();
void add_address_to_interface ();
void ForEachAddress2();
void ipv6_nt_update_kernel_route (IPV6_INFO_ROUTE_TABLE *RTE);
void add_nt_ipv6_interface (IPV6_INFO_INTERFACE *IF, int index);
IPV6_INFO_INTERFACE *GetInterface(uint Index);
#endif /* HAVE_IPV6 */

int readipv4_interfaces ();
void krt_read_table_v4();

int
kernel_init (void)
{
	SOCKET sd;

   /* good place to open WSA socket */
	sd = WSASocket(AF_INET, SOCK_DGRAM, 0, 0, 0, 0);

    if (sd == SOCKET_ERROR) {
        printf ("Failed to get a socket.  Error %d\n", WSAGetLastError());
        return -1;
    }



	return (1);
}


sys_kernel_update_route (prefix_t * dest, prefix_t * nexthop, 
                         prefix_t * oldhop, int index, int oldindex) {

#ifdef HAVE_IPV6 
	if (dest->family == AF_INET6)
		return (sys_kernel_update_route_v6 (dest, nexthop, oldhop, index, oldindex));
#else
	if (dest->family == AF_INET)
		return (sys_kernel_update_route_v4 (dest, nexthop, oldhop, index, oldindex));
#endif /* HAVE_IPV6 */
}


int read_interfaces () {
	WSADATA WinsockData;

	
	if (WSAStartup(MAKEWORD(2, 2), &WinsockData) != 0) {
        printf ("Failed to find Winsock 2.2!\n"); 
        return -1;
    }

#ifdef HAVE_IPV6
	readipv6_interfaces	();
#else
	readipv4_interfaces ();
#endif /* IPV6 */

		return (1);
}



int
sys_kernel_read_rt_table (void)
{
#ifdef CONFIG_RTNETLINK
    if (init_netlink () >= 0) {
		return (kernel_read_rt_table_by_netlink ());
    }
#endif /* CONFIG_RTNETLINK */

#ifdef HAVE_IPV6
    krt_read_table_v6 ();
#else
    krt_read_table_v4 ();
#endif /* HAVE_IPV6 */
    return (1);
}


#ifdef HAVE_IPV6
sys_kernel_update_route_v6 (prefix_t * dest, prefix_t * nexthop, 
                         prefix_t * oldhop, int index, int oldindex) {

	IPV6_INFO_ROUTE_TABLE Route;
    uint BytesReturned;
	int command;

	memset (&Route, 0, sizeof (IPV6_INFO_ROUTE_TABLE));
    Route.ValidLifetime = 0xffffffff; /* infinite */ 
    Route.Preference = 0;
	Route.SitePrefixLength = 0;
    Route.Publish = FALSE;
    Route.Immortal = -1;

#ifdef NT
	if (nexthop) 
		printf ("nexthop %s\n", prefix_toax (nexthop));
#endif /* NT */

	Route.Query.PrefixLength = dest->bitlen;
	memcpy (&Route.Query.Prefix, &dest->add.sin6, sizeof (struct in6_addr));
    

	// add
	if (nexthop && (oldhop == NULL)){
		command = RTM_ADD;
		memcpy (&Route.Query.Neighbor.Address, &nexthop->add.sin6, sizeof (struct in6_addr));
		Route.Query.Neighbor.IF.Index = index;
    }
	// delete
    else if ((nexthop == NULL) && oldhop) {
		Route.ValidLifetime = 0;
		command = RTM_DELETE;
		if (oldhop != NULL)
			memcpy (&Route.Query.Neighbor.Address, &oldhop->add.sin6, sizeof (struct in6_addr));
		Route.Query.Neighbor.IF.Index = oldindex;	
    }
	// change
    else if (nexthop && oldhop) {
		Route.ValidLifetime = 0;
		command = RTM_CHANGE;
		if (oldhop != NULL)
			memcpy (&Route.Query.Neighbor.Address, &oldhop->add.sin6, sizeof (struct in6_addr));
		Route.Query.Neighbor.IF.Index = oldindex;
    }


	if (!DeviceIoControl(Handle, IOCTL_IPV6_UPDATE_ROUTE_TABLE,
                         &Route, sizeof Route,
                         NULL, 0, &BytesReturned, NULL)) {
        printf("route update error: %x\n", GetLastError());
        return (-1);
    }

	/* change -- and the new route */
	if (command == RTM_CHANGE) {
		memcpy (&Route.Query.Neighbor.Address, &nexthop->add.sin6, sizeof (struct in6_addr));
		Route.Query.Neighbor.IF.Index = index;

		if (!DeviceIoControl(Handle, IOCTL_IPV6_UPDATE_ROUTE_TABLE,
                         &Route, sizeof Route,
                         NULL, 0, &BytesReturned, NULL)) {
			printf("route update error: %x\n", GetLastError());
			return (-1);
		}
	}


	return (1);
}

#endif /* HAVE_IPV6 */





int readipv4_interfaces () {
	//struct sockaddr_in *pAddress, *pAddress_Mask, *pAddress_BroadCast;
	DWORD pAddress, pAddress_Mask, pAddress_BroadCast;

	INTERFACE_INFO InterfaceList[20];
	unsigned long nBytesReturned;
	int nNumInterfaces, i;
	u_long nFlags;
	interface_t *interfce;
	char name[128];
	int ret;
	MIB_IFROW IfRow;
	PMIB_IPADDRROW	prow;
	BYTE        buf[4096];
	DWORD       cbbuf = sizeof(buf);
	u_long index;
	
    PMIB_IPADDRTABLE ptable = (PMIB_IPADDRTABLE)&buf;


	ret = GetIpAddrTable(ptable, &cbbuf, TRUE);

	for (i=0; i < ptable->dwNumEntries; i++) {
		prow = &(ptable->table[i]);

		index = prow->dwIndex;
		index = index & 0x00ffff;  /* remove the top bit -- see NT Notes for more info */
	
        pAddress = prow->dwAddr;
		sprintf (name, "intf%d", index);  /* just use index number, NT doesn't really have names */



        pAddress_BroadCast = prow->dwBCastAddr;
        pAddress_Mask = prow->dwMask;

		
		IfRow.dwIndex = prow->dwIndex;
		GetIfEntry(&IfRow);
		nFlags = 0;
		if (IfRow.dwAdminStatus == MIB_IF_ADMIN_STATUS_UP)
			nFlags |= IFF_UP;

		if (prow->dwAddr == htonl (0x7f000001))
			nFlags |= IFF_LOOPBACK;
		else {	// not loopback
			nFlags |= IFF_MULTICAST; /* I have no idea how we determine this in NT */
			nFlags |= IFF_BROADCAST;
		}

		interfce = new_interface (name, nFlags, prow->dwReasmSize, index);
		add_addr_to_interface (interfce, AF_INET,
                           &pAddress,
                           mask2len (&pAddress_Mask, 4),
                           &pAddress_BroadCast);

    }

    return 0;
}


#ifdef HAVE_IPV6
int readipv6_interfaces () {
    IPV6_QUERY_INTERFACE Query, NextQuery;
    IPV6_INFO_INTERFACE *IF;
    uint InfoSize, BytesReturned;


	Handle = CreateFileW(WIN_IPV6_DEVICE_NAME,
                         0,      // access mode
                         FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL,   // security attributes
                         OPEN_EXISTING,
                         0,      // flags & attributes
                         NULL);  // template file
    assert (Handle != INVALID_HANDLE_VALUE);




    InfoSize = sizeof *IF + MAX_LINK_LEVEL_ADDRESS_LENGTH;
    IF = (IPV6_INFO_INTERFACE *) malloc(InfoSize);
    assert (IF != NULL);
    NextQuery.Index = 0;   

    for (;;) {
        Query = NextQuery;

         if (!DeviceIoControl(Handle, IOCTL_IPV6_QUERY_INTERFACE,
                              &Query, sizeof Query,
                              IF, InfoSize, &BytesReturned,
                              NULL)) {
             printf("bad index %u\n", Query.Index);
             exit(1);
         }

        NextQuery = IF->Query;

        if (Query.Index != 0) {

            if (BytesReturned != sizeof *IF + IF->LinkLevelAddressLength) {
                printf("inconsistent link-level address length\n");
                return (-1);
            }

            IF->Query = Query;
            add_nt_ipv6_interface (IF, Query.Index); 
        }

        if (NextQuery.Index == 0)
            break;
    }

    free(IF);
	return (1);
}


void add_nt_ipv6_interface (IPV6_INFO_INTERFACE *IF, int index) {
	interface_t *interfce;	
	static char buffer[128];
	int nFlags;

	// hardcode flags for now -- it looks like MSRIPv6 does not pass on this ifno
    nFlags = IFF_MULTICAST | IFF_BROADCAST;

	sprintf (buffer, "v6intf%d", index); // MSRIPv6 Interfaces don't really have names (just addresses)

	if (index == 1)
		nFlags |= IFF_LOOPBACK;

	if (IF->MediaConnected != 1)
		nFlags |= IFF_UP;

	interfce = new_interface (buffer, nFlags, IF->LinkMTU, index);
	ForEachAddress2(IF, interfce, add_address_to_interface);

}



void
ForEachAddress2(IPV6_INFO_INTERFACE *IF, interface_t *interfce,
               void (*func)(interface_t *, IPV6_INFO_ADDRESS *))
{
    IPV6_QUERY_ADDRESS Query, NextQuery;
    IPV6_INFO_ADDRESS NTE;
    uint BytesReturned;

    NextQuery.IF.Index = IF->Query.Index;
    NextQuery.Address = in6addr_any;

    for (;;) {
        Query = NextQuery;

        if (!DeviceIoControl(Handle, IOCTL_IPV6_QUERY_ADDRESS,
                             &Query, sizeof Query,
                             &NTE, sizeof NTE, &BytesReturned,
                            NULL)) {
            printf("bad address %s\n", FormatIPv6Address(&Query.Address));
            return;
        }

        NextQuery = NTE.Query;

        if (!IN6_ADDR_EQUAL(&Query.Address, &in6addr_any)) {

            NTE.Query = Query;
            (*func)(interfce, &NTE);
        }

        if (IN6_ADDR_EQUAL(&NextQuery.Address, &in6addr_any))
            break;
    }
}


void
ForEachAddress(IPV6_INFO_INTERFACE *IF,
               void (*func)(IPV6_INFO_ADDRESS *))
{
    IPV6_QUERY_ADDRESS Query, NextQuery;
    IPV6_INFO_ADDRESS NTE;
    uint BytesReturned;

    NextQuery.IF.Index = IF->Query.Index;
    NextQuery.Address = in6addr_any;

    for (;;) {
        Query = NextQuery;

        if (!DeviceIoControl(Handle, IOCTL_IPV6_QUERY_ADDRESS,
                             &Query, sizeof Query,
                             &NTE, sizeof NTE, &BytesReturned,
                            NULL)) {
            printf("bad address %s\n", FormatIPv6Address(&Query.Address));
            return (NULL); 
        }

        NextQuery = NTE.Query;

        if (!IN6_ADDR_EQUAL(&Query.Address, &in6addr_any)) {

            NTE.Query = Query;
            (*func)(&NTE);
        }

        if (IN6_ADDR_EQUAL(&NextQuery.Address, &in6addr_any))
            break;
    }
}


interface_t *NT_find_neighbor_interface (prefix_t *prefix) {
	interface_t *interfce;
	IPV6_INFO_INTERFACE *IF;

	IPV6_QUERY_NEIGHBOR_CACHE Query, NextQuery;
    IPV6_INFO_NEIGHBOR_CACHE *NCE;
    uint InfoSize, BytesReturned;

	InfoSize = sizeof *NCE + MAX_LINK_LEVEL_ADDRESS_LENGTH;

	LL_Iterate (INTERFACE_MASTER->ll_interfaces, (char *) interfce) {
		if (interfce->primary6 == NULL)
			continue;


		IF = GetInterface(interfce->index);
    
		NCE = (IPV6_INFO_NEIGHBOR_CACHE *) malloc(InfoSize);
		if (NCE == NULL) {
			printf("malloc failed\n");
			return (NULL);
		}

		NextQuery.IF.Index = IF->Query.Index;
		NextQuery.Address = in6addr_any;

		for (;;) {
			Query = NextQuery;

			if (!DeviceIoControl(Handle, IOCTL_IPV6_QUERY_NEIGHBOR_CACHE,
                             &Query, sizeof Query,
                             NCE, InfoSize, &BytesReturned,
                             NULL)) {
				printf("bad address %s\n", FormatIPv6Address(&Query.Address));
				return (NULL);
			}

			NextQuery = NCE->Query;

			if (!IN6_ADDR_EQUAL(&Query.Address, &in6addr_any)) {
				if (BytesReturned != sizeof *NCE + NCE->LinkLevelAddressLength) {
				 printf("inconsistent link-level address length\n");
					return (NULL); 
				}
				NCE->Query = Query;
				/* do something here */
				if (IN6_ADDR_EQUAL(&NextQuery.Address, &prefix->add.sin6))
					return (interfce);
			}

			if (IN6_ADDR_EQUAL(&NextQuery.Address, &in6addr_any))
			 break;
		}
		free(NCE);
	}
}


interface_t *NT_find_interface (prefix_t *prefix, int link_local) {

	IPV6_QUERY_ROUTE_TABLE Query, NextQuery;
    IPV6_INFO_ROUTE_TABLE RTE;
    uint BytesReturned;
	//char tmp[128];
	struct in6_addr addr, dst;
	int llocal = 0;
	int best = 0;
	int best_index = 0;

	NextQuery.Neighbor.IF.Index = 0;
	memcpy (&addr, prefix_toaddr6 (prefix), sizeof (addr));
#ifdef HAVE_IPV6
    if (prefix->family == AF_INET6 &&
            IN6_IS_ADDR_LINKLOCAL (&addr)) {
		llocal++;
		return (NT_find_neighbor_interface (prefix));
    }
#endif /* HAVE_IPV6 */

    for (;;) {
        Query = NextQuery;

        if (!DeviceIoControl(Handle, IOCTL_IPV6_QUERY_ROUTE_TABLE,
                             &Query, sizeof Query,
                             &RTE, sizeof RTE, &BytesReturned,
                             NULL)) {
            printf("bad index %u\n", Query.Neighbor.IF.Index);
            return (NULL); 
        }

        NextQuery = RTE.Query;

        if (Query.Neighbor.IF.Index != 0) {

            RTE.Query = Query;
			memcpy (&dst, &(RTE.Query.Prefix), sizeof (dst));

			if (comp_with_mask (&addr, &dst, (llocal) ? 128 : RTE.Query.PrefixLength)) {
				if ((link_local) && (!IN6_IS_ADDR_UNSPECIFIED (&Query.Neighbor.Address)))
					continue;
				if (RTE.Query.PrefixLength >= best) {
					best = RTE.Query.PrefixLength;
					best_index = Query.Neighbor.IF.Index;
				}
				//return (find_interface_byindex (Query.Neighbor.IF.Index));
			}
        }

        if (NextQuery.Neighbor.IF.Index == 0)
            break;
    }

	if (best > 0) 
		return (find_interface_byindex (best_index));

	return (NULL);

}


void
PrintAddress(IPV6_INFO_ADDRESS *NTE)
{
    printf("    %s address %s, ",
           FormatDADState(NTE->DADState),
           FormatIPv6Address(&NTE->Query.Address));

    if (NTE->ValidLifetime == 0xffffffff)
        printf("infinite/");
    else
        printf("%us/", NTE->ValidLifetime);

    if (NTE->PreferredLifetime == 0xffffffff)
        printf("infinite\n");
    else
        printf("%us\n", NTE->PreferredLifetime);
}


char *
FormatIPv6Address(IPv6Addr *Address)
{
    static char buffer[128];
    DWORD buflen = sizeof buffer;
    struct sockaddr_in6 sin6;
	//interface_t *interfce;
	//int nFlags;

    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = 0;
    sin6.sin6_flowinfo = 0;
    memcpy(&sin6.sin6_addr, Address, sizeof *Address);

    if (WSAAddressToString((struct sockaddr *) &sin6,
                           sizeof sin6,
                           NULL,       // LPWSAPROTOCOL_INFO
                           buffer,
                           &buflen) == SOCKET_ERROR) {
			strcpy(buffer, "<invalid>");
			printf ("WSAAdresstoString Error %d\n", WSAGetLastError());
	}
			

	//interfce = new_interface (buffer, nFlags, 512, 0);
	//add_addr_to_interface (interfce, AF_INET6,
                         //  &sin6.sin6_addr,
                          // 32,
                          // &sin6.sin6_addr);


    return buffer;
}


void add_address_to_interface (interface_t *interfce, IPV6_INFO_ADDRESS *NTE) {
	struct sockaddr_in6 sin6;

    memcpy(&sin6.sin6_addr, &NTE->Query.Address, sizeof (NTE->Query.Address));

	/* In MSRIPv6, the mask is not stored with the interface -- we'll have to check the
	 *	routing table */
	add_addr_to_interface (interfce, AF_INET6,
						 &sin6.sin6_addr, 128, NULL);

}

char *
FormatDADState(uint DADState)
{
    switch (DADState) {
    case 0:
        return "invalid";
    case 1:
        return "duplicate";
    case 2:
        return "tentative";
    case 3:
        return "deprecated";
    case 4:
        return "preferred";
    }
    return "<bad state>";
}

#endif /* HAVE_IPV6 */





#ifdef HAVE_IPV6
void
krt_read_table_v6 ()
{
	
	// ForEachRoute(PrintRouteTableEntry);
    
	IPV6_QUERY_ROUTE_TABLE Query, NextQuery;
    IPV6_INFO_ROUTE_TABLE RTE;
    uint BytesReturned;
	
    NextQuery.Neighbor.IF.Index = 0;
	
    for (;;) {
        Query = NextQuery;
		
        if (!DeviceIoControl(Handle, IOCTL_IPV6_QUERY_ROUTE_TABLE,
			&Query, sizeof Query,
			&RTE, sizeof RTE, &BytesReturned,
			NULL)) {
            printf("bad index %u\n", Query.Neighbor.IF.Index);
            return (NULL);
        }
		
        NextQuery = RTE.Query;
		
        if (Query.Neighbor.IF.Index != 0) {
			
            RTE.Query = Query;
			
	
			if (!IN6_IS_ADDR_LOOPBACK (&RTE.Query.Prefix) && 
				!IN6_IS_ADDR_MULTICAST(&RTE.Query.Prefix) &&  
				!IN6_IS_ADDR_UNSPECIFIED (&RTE.Query.Neighbor.Address)) {
					update_kernel_route ('A', AF_INET6, (void *) &RTE.Query.Prefix, 
						&RTE.Query.Neighbor.Address,
						RTE.Query.PrefixLength, 
						RTE.Query.Neighbor.IF.Index, PROTO_KERNEL);
					//ipv6_nt_update_kernel_route (&RTE);
			}
		
        if (NextQuery.Neighbor.IF.Index == 0)
            break;
		}
	}
}




IPV6_INFO_INTERFACE *
GetInterface(uint Index)
{
    IPV6_QUERY_INTERFACE Query;
    IPV6_INFO_INTERFACE *IF;
    uint InfoSize, BytesReturned;

    Query.Index = Index;

    InfoSize = sizeof *IF + MAX_LINK_LEVEL_ADDRESS_LENGTH;
    IF = (IPV6_INFO_INTERFACE *) malloc(InfoSize);
    if (IF == NULL) {
        printf("malloc failed\n");
        return (NULL);
    }
    
    if (!DeviceIoControl(Handle, IOCTL_IPV6_QUERY_INTERFACE,
                         &Query, sizeof Query,
                         IF, InfoSize, &BytesReturned,
                         NULL)) {
        printf("bad index %u\n", Query.Index);
        return (NULL);
    }

    if (BytesReturned != sizeof *IF + IF->LinkLevelAddressLength) {
        printf("inconsistent link-level address length\n");
        return (NULL);
    }

    IF->Query = Query;
    return IF;
}


#endif /* HAVE_IPV6 */







#define PAGE 4096
LPWSTR wszType[] = {L"Other", 
                    L"Invalid",
                    L"Direct",
                    L"Indirect"};

LPWSTR wszProto[] ={L"Other",                           // MIB_IPPROTO_OTHER		        1
                    L"Local",                           // MIB_IPPROTO_LOCAL		        2
                    L"SNMP",                            // MIB_IPPROTO_NETMGMT		        3
                    L"ICMP",                            // MIB_IPPROTO_ICMP			    4
                    L"Exterior Gateway Protocol",       // MIB_IPPROTO_EGP		5
                    L"GGP",                             // MIB_IPPROTO_GGP			        6
                    L"Hello",                           // MIB_IPPROTO_HELLO		        7
                    L"Routing Information Protocol",    // MIB_IPPROTO_RIP			        8
                    L"IS IS",                           // MIB_IPPROTO_IS_IS		        9
                    L"ES IS",                           // MIB_IPPROTO_ES_IS		        10
                    L"Cicso",                           // MIB_IPPROTO_CISCO		        11
                    L"BBN",                             // MIB_IPPROTO_BBN			        12
                    L"Open Shortest Path First",        // MIB_IPPROTO_OSPF			    13
                    L"Border Gateway Protocol"};        // MIB_IPPROTO_BGP			        14




void krt_read_table_v4() {

	
    BYTE        buf[PAGE];
    DWORD       cbbuf = sizeof(buf);
	DWORD		d;
	PMIB_IPFORWARDROW pRow;

    PMIB_IPFORWARDTABLE table = (PMIB_IPFORWARDTABLE)&buf;
    

	// have to check return value -- buffer might be too small
    if (GetIpForwardTable (table, &cbbuf, TRUE))
        return;

    for (d=0; d < table->dwNumEntries; ++d)
    {
		pRow = table->table+d;
		update_kernel_route ('A', AF_INET, (void *) &(pRow->dwForwardDest), 
			&(pRow->dwForwardNextHop),
			mask2len (&pRow->dwForwardMask, 4), pRow->dwForwardIfIndex, PROTO_KERNEL);
    }


}







sys_kernel_update_route_v4 (prefix_t * dest, prefix_t * nexthop, 
							 prefix_t * oldhop, int index, int oldindex) {

	MIB_IPFORWARDROW Route;	
    u_int BytesReturned;
	int command;
	int err1, err2;
	DWORD mask = 0;

	memset(&Route, 0, sizeof(MIB_IPFORWARDROW));

	if (prefix_is_loopback (dest)) 
		return;


	printf ("dest: %s", prefix_toax (dest));
	printf ("  Nexthop: %s", prefix_toa (nexthop));
	printf ("  index %d (old index %d)\n", index, oldindex);
	len2mask (dest->bitlen, &mask, 4);

    Route.dwForwardDest = prefix_tolong (dest);
    Route.dwForwardMask = mask;
    Route.dwForwardIfIndex = index;
	//Route.dwForwardIfIndex |= 0x01000000; /* hack, hack cause NT4 sets a high bit outside 256 range */
    Route.dwForwardType = MIB_IPROUTE_TYPE_DIRECT;
    Route.dwForwardProto = MIB_IPPROTO_NETMGMT;
    Route.dwForwardAge = INFINITE;
    Route.dwForwardMetric1 = 1;
    Route.dwForwardMetric2 = (DWORD)-1;
    Route.dwForwardMetric3 = (DWORD)-1;
    Route.dwForwardMetric4 = (DWORD)-1;


	// add
	if (nexthop && (oldhop == NULL)){
		command = RTM_ADD;
		Route.dwForwardNextHop = prefix_tolong (nexthop);
		if ((err1 = CreateIpForwardEntry(&Route)) != NO_ERROR) {
			err2= WSAGetLastError();
			printf ("Error %d %d %s\n", err1, err2, strerror(NULL));
		}
	}

	// delete
    else if ((nexthop == NULL) && oldhop) {
		command = RTM_DELETE;
		Route.dwForwardIfIndex = oldindex;
		//Route.dwForwardIfIndex |= 0x01000000; /* hack, hack cause NT4 sets a high bit outside 256 range */
		Route.dwForwardNextHop = prefix_tolong (oldhop);
		if ((err1 = DeleteIpForwardEntry (&Route)) != NO_ERROR) {
			err2= GetLastError ();
			printf ("Error %d %d %s\n", err1, err2, strerror(NULL));
		}
	}


	// change
    else if (nexthop && oldhop) {
		command = RTM_CHANGE;
		Route.dwForwardNextHop = prefix_tolong (nexthop);
		if ((err1 = SetIpForwardEntry(&Route)) != NO_ERROR) {
			err2= GetLastError ();
			printf ("Error %d %d %s\n", err1, err2, strerror(NULL));
		}
	}

	return (1);
}



