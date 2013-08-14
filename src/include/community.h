/*
 * $Id: community.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef COMMUNITY_H
#define COMMUNITY_H

#define MAX_CLIST 100

typedef struct _community_condition_t {
    int permit; /* boolean */
    u_long value;
} community_condition_t;

int add_community_list (int num, int permit, u_long value);
int remove_community_list (int num, int permit, u_long value);
int del_community_list (int num);
int apply_community_condition (community_condition_t *condition, 
			       community_t *community);
int apply_community_list (int num, community_t *community);
void community_list_out (int num, void_fn_t fn);

/*
 * BGP4 well-known attributes
 */
#define COMMUNITY_NO_EXPORT (0xFFFFFF01)
	 /* MUST NOT be advertised outside a BGP confederation boundary */
#define COMMUNITY_NO_ADVERTISE (0xFFFFFF02)
	 /* MUST NOT be advertised to other BGP peers */
#define COMMUNITY_NO_EXPORT_SUBCONFED (0xFFFFFF03)
	 /* MUST NOT be advertised to external BGP peers */

#define	PA_COMMUNITY_MAXLEN	255	/* maximum length */

community_t *munge_community (int plen, u_char * cp);
u_char *unmunge_community (community_t * community, u_char * cp);
char *community_toa (community_t * community);
char *community_toa2 (u_long value, char *strbuf);
community_t *community_from_string (char *cp);
community_t *New_community (int len, u_char * cp, int conversion);
community_t *community_copy (community_t * community);
void Delete_community (community_t * community);
int community_compare (community_t * a, community_t * b);
int community_test (community_t * community, u_long value);

cluster_list_t * munge_cluster_list (int plen, u_char * cp);
u_char * unmunge_cluster_list (cluster_list_t * cluster_list, u_char * cp);
cluster_list_t * New_cluster_list (int len, u_char * cp);
void Delete_cluster_list (cluster_list_t * cluster_list);
cluster_list_t * cluster_list_copy (cluster_list_t *cluster_list);
char * cluster_list_toa (cluster_list_t * cluster_list);
cluster_list_t * cluster_list_from_string (char *cp);

#endif /* COMMUNITY_H */
