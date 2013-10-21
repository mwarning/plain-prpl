
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <glib.h>
#include <assert.h>
#include <sys/time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>


/* Needed to be placed before the libpurple includes */
#define PURPLE_PLUGINS 1

#include "account.h"
#include "accountopt.h"
#include "blist.h"
#include "cmds.h"
#include "conversation.h"
#include "connection.h"
#include "debug.h"
#include "notify.h"
#include "privacy.h"
#include "prpl.h"
#include "roomlist.h"
#include "request.h"
#include "status.h"
#include "util.h"
#include "version.h"

#include "extra.h"
#include "scripts.h"

#define PLAIN_VERSION "0.1"
#define PLAIN_WEBSITE "http://foo"
#define PLAIN_AUTHOR NULL
#define LINKPRPL_ID "prpl-plain"
#define PLAIN_STATUS_ONLINE "plain_online"
#define PLAIN_STATUS_OFFLINE "plain_offline"
#define PLAIN_PING_TIME (5*60)
#define PLAIN_DEFAULT_PORT_STR "1235"
#define _(msg) msg /* dummy hook for gettext */

/* A sensible payload size for a UDP packet */
#define MAX_MESSAGE_SIZE 1490


enum {
	BUDDY_STATE_RESOLVE = 0,
	BUDDY_STATE_PING = 1,
};

/* State data attached to PurpleBuddy */
typedef struct {
	char *name;
	IP addr;
	int state;
	int state_step;
	time_t state_next;
	time_t time_recv; /* Last time a packet was received */
	time_t time_send; /* Last time a packet was send */
} plain_buddy_state;

/* State data attached to PurpleAccount */
typedef struct {
	int sockfd;
	int sockaf;
	guint receive_timer; /* Call plain_receive() in intervals */
	time_t time_next; /* Next time to try to resolve/ping buddies */
	GSList *all_buddies; /* List of all buddies of this account */
	int block_unknown; //prevent multiple unknown add buddy dialogs
} plain_plugin_state;


void free_buddy_data(plain_buddy_state *bstate)
{
	if(bstate) {
		g_free(bstate->name);
		g_free(bstate);
	}
}

void free_plugin_data(plain_plugin_state *pstate)
{
	if(pstate) {
		g_free(pstate);
	}
}

static void plainprpl_add_buddy_by_contact_request(PurpleConnection *gc, const char *addr_str, const char *message);


plain_buddy_state * add_buddy_sdata(PurpleBuddy *buddy, plain_plugin_state* pstate )
{
	plain_buddy_state *bstate;

	bstate = g_new0(plain_buddy_state, 1);
	bstate->name = g_strdup(buddy->name);
	purple_buddy_set_protocol_data(buddy, bstate);

	/* Append buddy data to plugin data list */
	pstate->all_buddies = g_slist_append(pstate->all_buddies, buddy);

	return bstate;
}

/* Receive message and identify buddy */
PurpleBuddy* receive_msg(plain_plugin_state *pstate, IP *addr_ret, char buf[], int *buf_length)
{
	char addrbuf[FULL_ADDSTRLEN+1];
	PurpleBuddy *buddy;
	plain_buddy_state *bstate;
	GSList *iter;
	socklen_t addrlen;
	IP addr;
	int n;

	addrlen = sizeof(IP);
	n = recvfrom( pstate->sockfd, buf, *buf_length, 0, (struct sockaddr *) &addr, &addrlen );
	if( n < 0 || n > *buf_length ) {
		buf[0] = '\0';
		*buf_length = 0;
		return NULL;
	} else {
		buf[n] = '\0';
		*buf_length = n;
	}

	memcpy(addr_ret, &addr, sizeof(IP));

	iter = pstate->all_buddies;
	while(iter) {
		buddy = iter->data;
		bstate = purple_buddy_get_protocol_data(buddy);
		const char *addr_str = purple_blist_node_get_string(PURPLE_BLIST_NODE(buddy), "addr_str");

		//printf("buddy: %s, addr: %s (addr_str: %s)\n", bstate->name, str_addr(&bstate->addr, addrbuf), addr_str);

		if(addr_equal(&bstate->addr, &addr )) {
			/* Found buddy by address */
			return buddy;
		}

		iter = iter->next;
	}

	/* No buddy found */
	return NULL;
}

/* Send a message to a buddy */
int send_msg( plain_plugin_state *plugin_data, plain_buddy_state *buddy_data, const char *msg_str)
{
	char addrbuf[FULL_ADDSTRLEN+1];
	int rc;
	int sockfd = plugin_data->sockfd;
	IP *addr = &buddy_data->addr;
	const int msg_len = strlen(msg_str);

	int str_len = msg_len;
	const char *str_ptr = msg_str;
	/*
		purple_debug_info("plainprpl", "Try to send %d Bytes to: %s\n", msg_len, str_addr(addr, addrbuf) );
		rc = sendto( sockfd, msg_str, msg_len, 0, (struct sockaddr *)addr, sizeof(IP) );
		printf("rc of sendto: %d\n", rc);
	*/
	purple_debug_info("plainprpl", "Try to send %d Bytes to: %s\n", msg_len, str_addr(addr, addrbuf) );
	while(str_len > 0) {
		int size = (str_len < MAX_MESSAGE_SIZE) ? str_len : MAX_MESSAGE_SIZE;

		purple_debug_info("plainprpl", "Send (%d Bytes): %.*s\n", size, size, str_ptr );
		rc = sendto( sockfd, str_ptr, size, 0, (struct sockaddr *)addr, sizeof(IP) );
		if( rc < 0 ) {
			purple_debug_info("plainprpl", "Failed to send message: %s (%d)\n", strerror(errno), rc);
			return -1;
		}
		str_len -= size;
		str_ptr += size;
	}

	return 1;
}

void on_lookup_handle(const char* line, PurpleConnection *gc, PurpleBuddy* buddy)
{
	purple_debug_info("plainprpl", "on_lookup_handle: %s\n", line);

	plain_plugin_state *pstate;
	plain_buddy_state *bstate;

	pstate = purple_connection_get_protocol_data(gc);
	bstate = purple_buddy_get_protocol_data(buddy);

	addr_parse( &bstate->addr, line, PLAIN_DEFAULT_PORT_STR, pstate->sockaf );
}

/* Ping buddies a ping every 5 minutes if there is no traffic */
void ping_buddies( PurpleConnection *gc, time_t now)
{
	char addrbuf[FULL_ADDSTRLEN+1];
	PurpleBuddy *buddy;
	PurpleAccount *account;
	plain_buddy_state *bstate;
	plain_plugin_state *pstate;
	time_t time_next;
	GSList *iter;

	account = purple_connection_get_account(gc);
	pstate = purple_connection_get_protocol_data(gc);

	if( pstate->time_next > now ) {
		return;
	}

	time_next = now + (60*5); //max time we wait for another round
	const char *on_lookup = purple_account_get_string(account, "on_lookup", NULL);

	iter = pstate->all_buddies;
	while(iter) {
		buddy = iter->data;
		bstate = purple_buddy_get_protocol_data(buddy);

		//uninitialized buddy
		if(bstate == NULL) {
			purple_debug_info("plainprpl", "Buddy %s has no state set.\n", buddy->name);
			goto next;
		}

		//printf("Do ping_buddies for %s\n", buddy->name);

		int state = bstate->state;
		int state_step = bstate->state_step;
		time_t state_next = bstate->state_next;

		if(state == BUDDY_STATE_RESOLVE) {
			const char* addr_str = purple_blist_node_get_string(PURPLE_BLIST_NODE(buddy), "addr_str");
			if(exec_process(on_lookup, addr_str, on_lookup_handle, gc, buddy) == 0) {
				/* Script was called - wait for answer some other time */
				purple_debug_info("plainprpl", "Lookup by SCRIPT succeded. Start to ping %s\n", str_addr( &bstate->addr, addrbuf));
				state = BUDDY_STATE_PING;
				state_step = 1;
				state_next = now + 1;
			} else if( addr_parse_full( &bstate->addr, addr_str, PLAIN_DEFAULT_PORT_STR, pstate->sockaf ) == 0 ) {
				purple_debug_info("plainprpl", "Lookup by DNS succeded (%s). Start to ping %s\n", addr_str, str_addr( &bstate->addr, addrbuf));
				//switch to ping state
				state = BUDDY_STATE_PING;
				state_step = 1;
				state_next = now + 1;
			} else {
				if( state_step == 0 ) {
					state_step = 4;
				} else if( state_step < (5*60) ) {
					state_step *= 2;
				}

				purple_debug_info("plainprpl", "Resolve failed. Try again in %d seconds.\n", state_step);
				state_next = now + state_step;
			}
		} else if(state == BUDDY_STATE_PING) {
			//send ping
			if(bstate->time_recv < (now - (5*60))) {
				if( state_step < (5*60) ) {
					state_step *= 2;
					state_next = now + state_step;

					send_msg( pstate, bstate, "/ping" );

					/* Set buddy status to online */
					purple_prpl_got_user_status(account, bstate->name, PLAIN_STATUS_OFFLINE, NULL);
				} else {
					state = BUDDY_STATE_RESOLVE;
					state_step = 1;
					state_next = now + 1;
				}
			} else {
				state_step = 1;
				state_next = now + (5*60);
			}
		} else {
			purple_debug_info("plainprpl", "Invalid state: %d\n", state);
		}

		bstate->state = state;
		bstate->state_step = state_step;
		bstate->state_next = state_next;

		/* Get next time we need to do something here */
		if( state_next < time_next ) {
			time_next = state_next;
		}

next:
		iter = iter->next;
	}

	pstate->time_next = time_next;
	purple_debug_info("plainprpl", "Next iteration in %d seconds.\n", (int) (time_next - now));
}

static gboolean plain_receive(gpointer data)
{
	char addrbuf[FULL_ADDSTRLEN+1];
	char msgbuf[MAX_MESSAGE_SIZE];
	int msgbuf_len;
	IP addr;
	const char *addr_str;
	const char *status;
	PurpleConnection *gc;
	PurpleAccount *account;
	PurpleBuddy *buddy;
	plain_plugin_state *pstate;
	plain_buddy_state* bstate;

	/* Get time in seconds since 1970 */
	time_t now = time(NULL);

	gc = (PurpleConnection*) data;
	account = purple_connection_get_account(gc);
	pstate = purple_connection_get_protocol_data(gc);

	/* Check if we need to ping any buddy */
	ping_buddies( gc, now );

	msgbuf_len = sizeof(msgbuf);
	buddy = receive_msg(pstate, &addr, msgbuf, &msgbuf_len);

	/* Nothing to receive or error */
	if( msgbuf_len <= 0) {
		return TRUE;
	}

	addr_str = str_addr( &addr, addrbuf );

	if(!g_utf8_validate(msgbuf, -1, NULL)) {
		purple_debug_info("plainprpl", "Received invalid UTF8 message from %s - ignore.\n", addr_str);
		return TRUE;
	}

	/* We got a message and identified the sender */
	purple_debug_info("plainprpl", "Received message from %s (%d Bytes): %s\n", addr_str, strlen(msgbuf), msgbuf);

	/* We got a message from a source we don't know */
	gboolean allow_unknown = purple_account_get_bool(account, "allow_unknown", FALSE);
	if(buddy == NULL) {
		purple_debug_info("plainprpl", "Packet from unknown buddy from address %s.\n", addr_str);

		if(allow_unknown && !pstate->block_unknown) {
			//temporary disable the setting
			pstate->block_unknown = TRUE;
			plainprpl_add_buddy_by_contact_request(gc, addr_str, msgbuf);
		}
		return TRUE;
	}

	bstate = purple_buddy_get_protocol_data(buddy);
	if(bstate == NULL) {
		purple_debug_info("plainprpl", "bstate of buddy %s is NULL.\n", buddy->name);
		return TRUE;
	}

	status = PLAIN_STATUS_ONLINE;

	if(strcmp(msgbuf, "/ping") == 0) {
		/* Received a ping from a buddy */
		if((bstate->time_recv + 5) < now) {
			/* Send pong at most every 5 seconds */
			send_msg( pstate, bstate, "/pong" );
		} else {
			/* Ignore ping */
		}
	} else if(strcmp(msgbuf, "/pong") == 0) {
		/* Nothing to do */
	} else if(strcmp(msgbuf, "/bye") == 0) {
		status = PLAIN_STATUS_OFFLINE;
	} else if(msgbuf[0] != '/') {
		/* Display message */
		serv_got_im(gc, bstate->name, msgbuf, PURPLE_MESSAGE_RECV, now);
	} else {
		/* Unknown command - ignore */
	}

	bstate->time_recv = now;

	/* Set buddy status to online */
	purple_prpl_got_user_status(account, bstate->name, status, NULL);

	return TRUE; //continue loop
}

/*
* prefix of the plainprpl icons
*/
static const char *plainprpl_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "plain";
}

static char *plainprpl_status_text(PurpleBuddy *buddy)
{
	PurplePresence *presence;
	PurpleStatus *status;

	const char *status_name;
	const char *message;
	char *status_text;

	//purple_debug_info("plainprpl", "getting %s's status text for %s\n", buddy->name, buddy->account->username);

	presence = purple_buddy_get_presence(buddy);
	if(presence) {
		status = purple_presence_get_active_status(presence);
	} else {
		//printf("presence is null for ");
		status = NULL;
	}

	if(status) {
		status_name = purple_status_get_name(status);
		message = purple_status_get_attr_string(status, "message");

		if (message && strlen(message) > 0) {
			status_text = g_strdup_printf("%s: %s", status_name, message);
		} else {
			status_text = g_strdup(status_name);
		}
		//purple_debug_info("plainprpl", "%s's status text is %s\n", buddy->name, status_text);
		return status_text;
	} else {
		return g_strdup("Not logged in");
	}
}

static GList *plainprpl_status_types(PurpleAccount *account)
{
	GList *types = NULL;
	PurpleStatusType *type;

	type = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE,
			PLAIN_STATUS_ONLINE, _("Online"), TRUE, TRUE, FALSE,
			"message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
			NULL);
	types = g_list_prepend(types, type);

	type = purple_status_type_new_with_attrs(PURPLE_STATUS_OFFLINE,
			PLAIN_STATUS_OFFLINE, _("Offline"), TRUE, TRUE, FALSE,
			"message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
			NULL);
	types = g_list_prepend(types, type);

	return g_list_reverse(types);
}

static void plainprpl_change_address_ok(void *ptr, PurpleRequestFields *fields)
{
	PurpleBuddy *buddy;
	plain_buddy_state *bstate;
	plain_plugin_state *pstate;
	PurpleRequestField *field;

	buddy = (PurpleBuddy *) ptr;
	bstate = purple_buddy_get_protocol_data(buddy);
	pstate = purple_connection_get_protocol_data(buddy->account->gc);

	field = purple_request_fields_get_field(fields, "addr_str");
	const char* addr_str = purple_request_field_string_get_value(field);

	purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "addr_str", addr_str);
	//resolve address again
	bstate->state = BUDDY_STATE_RESOLVE;
	bstate->state_step = 0;
	bstate->state_next = 0;
	bstate->time_recv = 0;
	bstate->time_send = 0;
	//handle now
	pstate->time_next = 0;
}

static void plainprpl_change_address_cancel(void *ptr, PurpleRequestFields *fields)
{
	/* Nothing to do */
}

static void plainprpl_change_address(PurpleBlistNode *node, gpointer userdata)
{
	PurpleBuddy *buddy;
	plain_buddy_state *bstate;

	char* request_str;
	const char* addr_str;

	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);

	buddy = (PurpleBuddy*) node;
	bstate = purple_buddy_get_protocol_data(buddy);

	if(bstate) {
		addr_str = purple_blist_node_get_string(PURPLE_BLIST_NODE(buddy), "addr_str");
		field = purple_request_field_string_new("addr_str", _("Address"), addr_str, FALSE);
		purple_request_field_string_set_masked(field, FALSE);
		purple_request_field_group_add_field(group, field);

		request_str = g_strdup_printf("Address to reach buddy '%s'.", buddy->name);
		purple_request_fields(buddy->account, "Change Address",
							  request_str,
							  NULL, fields,
							  _("OK"), G_CALLBACK(plainprpl_change_address_ok),
							  _("Cancel"), G_CALLBACK(plainprpl_change_address_cancel),
							  NULL, NULL, NULL, (void*) buddy
							 );
		g_free(request_str);
	} else {
		purple_debug_info("plainprpl", "Buddy %s has no bstate set.\n", buddy->name);
	}
}

static GList *plainprpl_blist_node_menu(PurpleBlistNode *node)
{
	purple_debug_info("plainprpl", "plainprpl_blist_node_menu\n");

	PurpleMenuAction *action = purple_menu_action_new(
								   _("Change Address"),
								   PURPLE_CALLBACK(plainprpl_change_address),
								   NULL, /* userdata passed to the callback */
								   NULL /* child menu items */
							   );
	return g_list_append(NULL, action);
}

static void plainprpl_login(PurpleAccount *account)
{
	PurpleConnection *gc = purple_account_get_connection(account);

	purple_debug_info("plainprpl", "logging in %s\n", account->username);

	purple_connection_update_progress(gc, _("Connecting"), 0, 2);
	purple_connection_update_progress(gc, _("Connected"), 1, 2);
	purple_connection_set_state(gc, PURPLE_CONNECTED);

	/* Setup plugin data */
	plain_plugin_state* pstate = g_new0(plain_plugin_state, 1);

	/* General account data */
	const char *listen_af = purple_account_get_string(account, "listen_af", NULL);
	const char *listen_port = purple_account_get_string(account, "listen_port", NULL);

	//check port
	if( listen_port == NULL || atoi(listen_port) < 1 || atoi(listen_port) >= 65535 ) {
		listen_port = PLAIN_DEFAULT_PORT_STR;
		purple_account_set_string(account, "listen_port", listen_port);
	}

	//check protocol
	if( listen_af == NULL || (strcmp(listen_af, "ipv4") && strcmp(listen_af, "ipv6"))) {
		listen_af = "ipv4";
		purple_account_set_string(account, "listen_port", listen_af);
	}

	/* Select the address to listen on */
	const char* listen_addr = (strcmp(listen_af, "ipv4") == 0) ? "0.0.0.0" : "::1";
	pstate->sockaf = str_to_af(listen_af);
	pstate->sockfd = net_bind("plainprpl", listen_addr, listen_port, NULL, IPPROTO_UDP, pstate->sockaf );

	if(pstate->sockfd < 0) {
		purple_debug_info("plainprpl", "Failed to bind to %s\n", listen_addr);
		g_free(pstate);
		//TODO: diable plugin
		return;
	} else {
		purple_debug_info("plainprpl", "Bind to %s\n", listen_addr);
	}

	pstate->receive_timer = purple_timeout_add(80, plain_receive, gc);

	purple_connection_set_protocol_data(gc, pstate);

	/* Attach buddy data to each buddy */
	GSList *list = purple_find_buddies(account, NULL);
	purple_debug_info("plainprpl", "Buddies to load: %d\n", g_slist_length(list));

	GSList *iter = list;
	while(iter) {
		PurpleBuddy *buddy = iter->data;
		//purple_debug_info("plainprpl", "#plainprpl_login: attach custom data to buddy: %s\n", buddy->name);
		assert(purple_buddy_get_protocol_data(buddy) == NULL);

		const char* addr_str = purple_blist_node_get_string(PURPLE_BLIST_NODE(buddy), "addr_str");
		if( addr_str != NULL && strlen(addr_str) ) {
			add_buddy_sdata(buddy, pstate);
		} else {
			purple_debug_info("plainprpl", "Empty address for buddy: %s\n", buddy->name);
		}

		/* Set offline by default */
		purple_prpl_got_user_status(account, buddy->name, PLAIN_STATUS_OFFLINE, NULL);

		iter = iter->next;
	}
	g_slist_free(list);

	/* Call the on_login script - if it is set */
	const char* on_login = purple_account_get_string(account, "on_login", NULL);
	exec_process(on_login, NULL, NULL, gc, NULL);
}

static void plainprpl_close(PurpleConnection *gc)
{
	purple_debug_info("plainprpl", "plainprpl_close\n");

	PurpleAccount *account;
	PurpleBuddy *buddy;
	plain_plugin_state *pstate;
	plain_buddy_state *bstate;
	const char* on_logout;

	/* notify other plainprpl accounts */
	account = purple_connection_get_account(gc);
	pstate = purple_connection_get_protocol_data(gc);

	/* Notifiy all buddies that we are gone */
	GSList *iter = pstate->all_buddies;
	while(iter) {
		buddy = iter->data;
		bstate = purple_buddy_get_protocol_data(buddy);

		PurplePresence *presence = purple_buddy_get_presence(buddy);
		PurpleStatus *status = purple_presence_get_active_status(presence);
		PurpleStatusType *status_type = purple_status_get_type(status);
		PurpleStatusPrimitive status_primitive = purple_status_type_get_primitive(status_type);
		if(bstate && status_primitive == PURPLE_STATUS_AVAILABLE) {
			send_msg( pstate, bstate, "/bye" );
		}

		iter = iter->next;
	}

	//remove timers
	purple_timeout_remove(pstate->receive_timer);

	on_logout = purple_account_get_string(account, "on_logout", NULL);
	exec_process(on_logout, NULL, NULL, gc, NULL);

	free_plugin_data(pstate);
}

/*
* From libpurple/prpl.h:
*
* This PRPL function should return a positive value on success.
* If the message is too big to be sent, return -E2BIG.  If
* the account is not connected, return -ENOTCONN.  If the
* PRPL is unable to send the message for another reason, return
* some other negative value.  You can use one of the valid
* errno values, or just big something.  If the message should
* not be echoed to the conversation window, return 0.
*/
static int plainprpl_send_im(PurpleConnection *gc, const char *who, const char *msg, PurpleMessageFlags flags)
{
	purple_debug_info("plainprpl", "Try to send message of %d bytes to %s\n", strlen(msg), who);

	plain_buddy_state *bstate;
	plain_plugin_state *pstate;
	PurpleBuddy *buddy;

	/*
	if(strlen(msg) > MAX_MESSAGE_SIZE) {
		purple_debug_info("plainprpl", "Message too long. Cannot send %d bytes to %s\n", strlen(msg), who);
		serv_got_im(gc, who, "The messag was too long to be send.", PURPLE_MESSAGE_SYSTEM, time(NULL));
		return -E2BIG;
	}
	*/

	buddy = purple_find_buddy(gc->account, who);
	if( buddy == NULL ) {
		return -999;
	}

	bstate = purple_buddy_get_protocol_data(buddy);
	if( bstate == NULL ) {
		return -999;
	}

	pstate = purple_connection_get_protocol_data(gc);
	if( send_msg(pstate, bstate, msg) < 0 ) {
		return -999;
	}

	return 1;
}

const char *str_time( time_t ago, char buf[])
{
	int diff;
	const char *fmt;

	diff = time(NULL) - ago;
	if(diff < (60)) {
		diff /= (1);
		fmt = (diff == 1) ? "%d second ago" : "%d seconds ago";
	} else if(diff < (60*60)) {
		diff /= (60);
		fmt = (diff == 1) ? "%d minute ago" : "%d minutes ago";
	} else if(diff < (60*60*24)) {
		diff /= (60*60);
		fmt = (diff == 1) ? "%d hour ago" : "%d hours ago";
	} else if(diff < (60*60*24*365)) {
		diff /= (60*60*24);
		fmt = (diff == 1) ? "%d day ago" : "%d days ago";
	} else {
		diff /= (60*60*24*365);
		fmt = (diff == 1) ? "%d year ago" : "%d years ago";

		//20 years ago..
		if( diff > 20 ) {
			fmt = "Never";
		}
	}

	sprintf(buf, fmt, diff );
	return buf;
}

static void plainprpl_get_info(PurpleConnection *gc, const char *buddy_name)
{
	PurpleBuddy *buddy;
	plain_buddy_state *bstate;
	PurpleNotifyUserInfo *info;
	char addrbuf[FULL_ADDSTRLEN+1];
	char timebuf[64];
	const char* addr_str;

	buddy = purple_find_buddy(gc->account, buddy_name);
	bstate = purple_buddy_get_protocol_data(buddy);
	info = purple_notify_user_info_new();

	if(bstate) {

		PurplePresence *presence = purple_buddy_get_presence(buddy);
		PurpleStatus *status = purple_presence_get_active_status(presence);
		const char *status_name = purple_status_get_name(status);

		purple_notify_user_info_add_pair(info, "Status", status_name);
		addr_str = purple_blist_node_get_string(PURPLE_BLIST_NODE(buddy), "addr_str");
		purple_notify_user_info_add_pair(info, "Address", addr_str);
		if(bstate->state == BUDDY_STATE_RESOLVE) {
			/* The IP address has not been resolved yet */
			purple_notify_user_info_add_pair(info, "Resolved", "Unknown");
		} else {
			purple_notify_user_info_add_pair(info, "Resolved", str_addr( &bstate->addr, addrbuf ));
		}
		purple_notify_user_info_add_pair(info, "Last Seen", str_time( bstate->time_recv, timebuf ) );
	} else {
		purple_notify_user_info_add_pair(info, "Info", "Missing Data");
	}

	/* Show a buddy's user info in a nice dialog box */
	purple_notify_userinfo(gc, buddy_name, info, NULL, NULL);
}

static void plainprpl_add_buddy_ok(void *ptr, PurpleRequestFields *fields)
{
	PurpleBuddy *buddy;
	PurpleConnection *gc;
	plain_plugin_state *pstate;
	plain_buddy_state *bstate;
	const char* addr_str;
	//const char* invite_msg;

	purple_debug_info("plainprpl", "plainprpl_add_buddy_ok\n");

	buddy = (PurpleBuddy *) ptr;
	gc = purple_account_get_connection(buddy->account);

	addr_str = purple_request_fields_get_string(fields, "addr_str");
	//invite_msg = purple_request_fields_get_string(fields, "invite_msg");

	if( addr_str == NULL || strlen(addr_str) == 0 ) {
		purple_notify_error(ptr, "Invalid Address", _("The address was empty."), _("You need to enter a host name or an IP address."));
		purple_blist_remove_buddy(buddy);
	} else {
		/* Finalize buddy creation */
		purple_debug_info("plainprpl", "Add buddy %s\n", buddy->name);
		purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "addr_str", addr_str);
		assert(purple_blist_node_get_string(PURPLE_BLIST_NODE(buddy), "addr_str") != NULL);

		pstate = purple_connection_get_protocol_data(gc);
		bstate = add_buddy_sdata(buddy, pstate);
		pstate->time_next = 0; //handle now

		purple_prpl_got_user_status(buddy->account, buddy->name, PLAIN_STATUS_OFFLINE, NULL);
		/*
		if(invite_msg) {
			plainprpl_send_im(gc, buddy->name, invite_msg,  0);
		}*/
	}
}

static void plainprpl_add_buddy_cancel(void *ptr, PurpleRequestFields *fields)
{
	PurpleBuddy *buddy = (PurpleBuddy *) ptr;
	purple_blist_remove_buddy(buddy);
}

/* Add buddy dialog */
static void plainprpl_add_buddy_with_invite(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *buddy_group, const char *msg)
{
	purple_debug_info( "plainprpl", "plainprpl_add_buddy_with_invite: %s (msg: '%s')\n", buddy->name, msg );
	PurpleRequestFields *request;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;

	group = purple_request_field_group_new(NULL);

	field = purple_request_field_string_new( "addr_str", _("IP Address"), "", FALSE );
	purple_request_field_group_add_field( group, field );

	field = purple_request_field_string_new( "invite_msg", _("Invite Message"), "Please allow me to add you as a contact!", FALSE );
	purple_request_field_group_add_field( group, field );

	request = purple_request_fields_new();
	purple_request_fields_add_group(request, group);

	purple_request_fields(gc, "Add Contact", "Add a new contact.",
						  NULL, request,
						  "OK",  G_CALLBACK(plainprpl_add_buddy_ok),
						  "Cancel",  G_CALLBACK(plainprpl_add_buddy_cancel),
						  NULL, NULL, NULL, (void*) buddy
						 );

	purple_prpl_got_user_status(gc->account, buddy->name, PLAIN_STATUS_OFFLINE, NULL);
}

static void plainprpl_add_buddy_by_contact_request_ok(void *ptr, PurpleRequestFields *fields)
{
	PurpleBuddy *buddy = (PurpleBuddy *) ptr;
	PurpleAccount *account = buddy->account;
	plain_plugin_state *pstate;
	plain_buddy_state *bstate;
	char* addr_str;
	const char *name;
	IP addr;

	name = purple_request_fields_get_string(fields, "name");
	//invite_msg = purple_request_fields_get_string(fields, "invite_msg");
	if(name == NULL && strlen(name) == 0) {
		purple_notify_error(ptr, "Invalid Name", _("Name was empty."), _("You need to enter a name."));
		purple_blist_remove_buddy(buddy);
	} else {
		addr_str = g_strdup(buddy->name);
		purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "addr_str", addr_str);
		assert(purple_blist_node_get_string(PURPLE_BLIST_NODE(buddy), "addr_str") != NULL);
		purple_blist_rename_buddy(buddy, name);
		g_free(addr_str);

		pstate = purple_connection_get_protocol_data(buddy->account->gc);
		bstate = add_buddy_sdata(buddy, pstate);

		assert(addr_parse_full(&addr, addr_str, PLAIN_DEFAULT_PORT_STR, pstate->sockaf ) == 0);
		addr_parse_full(&addr, addr_str, PLAIN_DEFAULT_PORT_STR, pstate->sockaf );
		memcpy(&bstate->addr, &addr, sizeof(IP));

		purple_prpl_got_user_status(account, buddy->name, PLAIN_STATUS_ONLINE, NULL);
	}

	pstate->block_unknown = FALSE;
}

static void plainprpl_add_buddy_by_contact_request_cancel(void *ptr, PurpleRequestFields *fields)
{
	PurpleBuddy *buddy = (PurpleBuddy *) ptr;
	PurpleAccount *account = buddy->account;
	plain_plugin_state *pstate = purple_connection_get_protocol_data(buddy->account->gc);

	purple_blist_remove_buddy(buddy);

	pstate->block_unknown = FALSE;
}

//with invite message
static void plainprpl_add_buddy_by_contact_request(PurpleConnection *gc, const char *addr_str, const char *message)
{
	PurpleBuddy* buddy;

	/* Create the basic buddy item */
	buddy = purple_buddy_new(gc->account, addr_str, NULL);
	purple_blist_add_buddy(buddy, NULL, NULL, NULL);

	PurpleRequestFields *request;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;

	group = purple_request_field_group_new(NULL);

	field = purple_request_field_string_new( "name", _("Name"), addr_str, FALSE );
	purple_request_field_group_add_field( group, field );

	request = purple_request_fields_new();
	purple_request_fields_add_group(request, group);

	char *msg = g_strdup_printf("Add a new contact from %s. Message: %s", addr_str, message);
	purple_request_fields(gc, "Contact Request", msg,
						  NULL, request,
						  "OK",  G_CALLBACK(plainprpl_add_buddy_by_contact_request_ok),
						  "Cancel",  G_CALLBACK(plainprpl_add_buddy_by_contact_request_cancel),
						  NULL, NULL, NULL, (void*) buddy
						 );
	g_free(msg);

	purple_prpl_got_user_status(gc->account, buddy->name, PLAIN_STATUS_OFFLINE, NULL);
}

static void plainprpl_free_buddy(PurpleBuddy *buddy)
{
	/* Keep all_buddies in sync with the existing buddies */
	purple_debug_info("plainprpl", "plainprpl_free_buddy\n");
	plain_plugin_state *pstate;

	pstate = purple_connection_get_protocol_data(buddy->account->gc);
	if(pstate) {
		pstate->all_buddies = g_slist_remove(pstate->all_buddies, buddy);
		free_buddy_data(buddy->proto_data);
	}
}

/*
* normalize a username (e.g. remove whitespace, add default domain, etc.)
 * for plainprpl, this is a noop.
 */
static const char *plainprpl_normalize(const PurpleAccount *account, const char *input)
{
	return NULL;
}


/* plainprpl doesn't support file transfer...yet... */
static gboolean plainprpl_can_receive_file(PurpleConnection *gc, const char *who)
{
	return FALSE;
}

/*
* prpl stuff. see prpl.h for more information.
*/
static PurplePluginProtocolInfo prpl_info = {
	OPT_PROTO_NO_PASSWORD,  /* options */
	NULL, /* user_splits, initialized in plainprpl_init() */
	NULL, /* protocol_options, initialized in plainprpl_init() */
	NO_BUDDY_ICONS,
	plainprpl_list_icon, /* list_icon */
	NULL, /* list_emblem */
	plainprpl_status_text, /* status_text */
	NULL, /* tooltip_text */
	plainprpl_status_types, /* status_types */
	plainprpl_blist_node_menu, /* blist_node_menu */
	NULL, /* chat_info */
	NULL, /* chat_info_defaults */
	plainprpl_login, /* login */
	plainprpl_close, /* close */
	plainprpl_send_im, /* send_im */
	NULL, /* set_info */
	NULL, /* send_typing */
	plainprpl_get_info, /* get_info */
	NULL, /* set_status */
	NULL, /* set_idle */
	NULL, /* change_passwd */
	NULL, /* add_buddy */
	NULL, /* add_buddies */
	NULL, /* remove_buddy */
	NULL, /* remove_buddies */
	NULL, /* add_permit */
	NULL, /* add_deny */
	NULL, /* rem_permit */
	NULL, /* rem_deny */
	NULL, /* set_permit_deny */
	NULL, /* join_chat */
	NULL, /* reject_chat */
	NULL, /* get_chat_name */
	NULL, /* chat_invite */
	NULL, /* chat_leave */
	NULL, /* chat_whisper */
	NULL, /* chat_send */
	NULL, /* keepalive */
	NULL, /* register_user */
	NULL, /* get_cb_info */
	NULL, /* get_cb_away */
	NULL, /* alias_buddy */
	NULL, /* group_buddy */
	NULL, /* rename_group */
	plainprpl_free_buddy, /* buddy_free */
	NULL, /* convo_closed */
	plainprpl_normalize, /* normalize */
	NULL, /* set_buddy_icon */
	NULL, /* remove_group */
	NULL, /* get_cb_real_name */
	NULL, /* set_chat_topic */
	NULL, /* find_blist_chat */
	NULL, /* roomlist_get_list */
	NULL, /* roomlist_cancel */
	NULL, /* roomlist_expand_category */
	plainprpl_can_receive_file, /* can_receive_file */
	NULL, /* send_file */
	NULL, /* new_xfer */
	NULL, /* offline_message */
	NULL, /* whiteboard_prpl_ops */
	NULL, /* send_raw */
	NULL, /* roomlist_room_serialize */
	NULL, /* unregister_user */
	NULL, /* send_attention */
	NULL, /* get_attention_types */
	sizeof(PurplePluginProtocolInfo), /* struct_size */
	NULL, /* get_account_text_table */
	NULL, /* initiate_media */
	NULL, /* get_media_caps */
	NULL, /* get_moods */
	NULL, /* set_public_alias */
	NULL, /* get_public_alias */
	plainprpl_add_buddy_with_invite, /* add_buddy_with_invite */
	NULL /* add_buddies_with_invite */
};

static void plainprpl_init(PurplePlugin *plugin)
{
	PurpleAccountOption *option;
	PurpleKeyValuePair *kvp;
	GList *list;

	kvp = g_new0(PurpleKeyValuePair, 1);
	kvp->key = g_strdup(_("IPv4"));
	kvp->value = g_strdup("ipv4");
	list = g_list_append(NULL, kvp);

	kvp = g_new0(PurpleKeyValuePair, 1);
	kvp->key = g_strdup(_("IPv6"));
	kvp->value = g_strdup("ipv6");
	list = g_list_append(list, kvp);

	option = purple_account_option_list_new( _("Protocol"), "listen_af", list);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new( _("Port"), "listen_port", PLAIN_DEFAULT_PORT_STR);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_bool_new( _("Allow messages from unknown contacts."), "allow_unknown", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new( _("On Login"), "on_login","");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new( _("On Logout"), "on_logout","");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	/* To lookup an IP address */
	option = purple_account_option_string_new( _("On Resolve"), "on_lookup", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

#if 0
	/* When verification fails */
	option = purple_account_option_string_new( _("On Invalid"), "on_invalid", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
#endif
}

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC, /* magic */
	PURPLE_MAJOR_VERSION, /* major_version */
	PURPLE_MINOR_VERSION, /* minor_version */
	PURPLE_PLUGIN_PROTOCOL, /* type */
	NULL, /* ui_requirement */
	0, /* flags */
	NULL, /* dependencies */
	PURPLE_PRIORITY_DEFAULT, /* priority */
	LINKPRPL_ID, /* id */
	"Plain", /* name */
	PLAIN_VERSION, /* version */
	"Plain Protocol Plugin", /* summary */
	"Plain Protocol Plugin", /* description */
	PLAIN_AUTHOR, /* author */
	PLAIN_WEBSITE, /* homepage */
	NULL, /* load */
	NULL, /* unload */
	NULL, /* destroy */
	NULL, /* ui_info */
	&prpl_info, /* extra_info */
	NULL, /* prefs_info */
	NULL, /* actions */
	NULL, /* padding... */
	NULL,
	NULL,
	NULL,
};

PURPLE_INIT_PLUGIN(null, plainprpl_init, info);
