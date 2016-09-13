/*
 *   FunYahoo++ - A replacement Yahoo prpl for Pidgin
 *   Copyright (C) 2016  Eion Robb
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

// Glib
#include <glib.h>

#if !GLIB_CHECK_VERSION(2, 32, 0)
#define g_hash_table_contains(hash_table, key) g_hash_table_lookup_extended(hash_table, key, NULL, NULL)
#endif /* 2.32.0 */

static gboolean
g_str_insensitive_equal(gconstpointer v1, gconstpointer v2)
{
	return (g_ascii_strcasecmp(v1, v2) == 0);
}
static guint
g_str_insensitive_hash(gconstpointer v)
{
	guint hash;
	gchar *lower_str = g_ascii_strdown(v, -1);
	
	hash = g_str_hash(lower_str);
	g_free(lower_str);
	
	return hash;
}


// GNU C libraries
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __GNUC__
	#include <unistd.h>
#endif
#include <errno.h>

#include <json-glib/json-glib.h>
// Supress overzealous json-glib 'critical errors'
#define json_object_get_int_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_int_member(JSON_OBJECT, MEMBER) : 0)
#define json_object_get_string_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_string_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_array_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_array_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_object_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_object_member(JSON_OBJECT, MEMBER) : NULL)
#define json_object_get_boolean_member(JSON_OBJECT, MEMBER) \
	(json_object_has_member(JSON_OBJECT, MEMBER) ? json_object_get_boolean_member(JSON_OBJECT, MEMBER) : FALSE)


static void
json_array_foreach_element_reverse (JsonArray        *array,
                                    JsonArrayForeach  func,
                                    gpointer          data)
{
	gint i;

	g_return_if_fail (array != NULL);
	g_return_if_fail (func != NULL);

	for (i = json_array_get_length(array) - 1; i >= 0; i--)
	{
		JsonNode *element_node;

		element_node = json_array_get_element(array, i);

		(* func) (array, i, element_node, data);
	}
}


#include <purple.h>
#if PURPLE_VERSION_CHECK(3, 0, 0)
#include <http.h>
#endif

#ifndef PURPLE_PLUGINS
#	define PURPLE_PLUGINS
#endif

#ifndef _
#	define _(a) (a)
#	define N_(a) (a)
#endif

#define YAHOO_PLUGIN_ID "prpl-eionrobb-funyahoo-plusplus"
#ifndef YAHOO_PLUGIN_VERSION
#define YAHOO_PLUGIN_VERSION "0.9"
#endif
#define YAHOO_PLUGIN_WEBSITE "https://github.com/EionRobb/funyahoo-plusplus"

#define YAHOO_USERAGENT "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"

#define YAHOO_BUFFER_DEFAULT_SIZE 40960

#define YAHOO_PRETEND_VERSION "929"


// Purple2 compat functions
#if !PURPLE_VERSION_CHECK(3, 0, 0)

#define purple_connection_error                 purple_connection_error_reason
#define PURPLE_CONNECTION_CONNECTING       PURPLE_CONNECTING
#define PURPLE_CONNECTION_CONNECTED        PURPLE_CONNECTED
#define purple_blist_find_group        purple_find_group
#define PurpleProtocolChatEntry  struct proto_chat_entry
#define PurpleChatConversation             PurpleConvChat
#define PurpleIMConversation               PurpleConvIm
#define purple_conversations_find_chat_with_account(id, account) \
		PURPLE_CONV_CHAT(purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT, id, account))
#define purple_chat_conversation_has_left     purple_conv_chat_has_left
#define PURPLE_CONVERSATION(chatorim)         (chatorim == NULL ? NULL : chatorim->conv)
#define PURPLE_IM_CONVERSATION(conv)          PURPLE_CONV_IM(conv)
#define PURPLE_CHAT_CONVERSATION(conv)        PURPLE_CONV_CHAT(conv)
#define purple_serv_got_joined_chat(pc, id, name)  PURPLE_CONV_CHAT(serv_got_joined_chat(pc, id, name))
#define purple_conversations_find_chat(pc, id)  PURPLE_CONV_CHAT(purple_find_chat(pc, id))
#define purple_serv_got_chat_in                    serv_got_chat_in
#define purple_chat_conversation_add_user     purple_conv_chat_add_user
#define purple_chat_conversation_remove_user  purple_conv_chat_remove_user
#define PurpleChatUserFlags  PurpleConvChatBuddyFlags
#define PURPLE_CHAT_USER_NONE     PURPLE_CBFLAGS_NONE
#define PURPLE_CHAT_USER_OP       PURPLE_CBFLAGS_OP
#define purple_conversation_get_connection      purple_conversation_get_gc
#define purple_chat_conversation_get_id         purple_conv_chat_get_id
#define PURPLE_CMD_FLAG_PROTOCOL_ONLY  PURPLE_CMD_FLAG_PRPL_ONLY
#define PURPLE_IS_BUDDY                PURPLE_BLIST_NODE_IS_BUDDY
#define PURPLE_IS_CHAT                 PURPLE_BLIST_NODE_IS_CHAT
#define purple_chat_get_name_only      purple_chat_get_name
#define purple_blist_find_buddy        purple_find_buddy
#define purple_serv_got_alias                      serv_got_alias
#define purple_account_set_private_alias    purple_account_set_alias
#define purple_account_get_private_alias    purple_account_get_alias
#define purple_protocol_got_user_status		purple_prpl_got_user_status
#define purple_serv_got_im                         serv_got_im
#define purple_conversations_find_im_with_account(name, account)  \
		PURPLE_CONV_IM(purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, name, account))
#define purple_im_conversation_new(account, from) PURPLE_CONV_IM(purple_conversation_new(PURPLE_CONV_TYPE_IM, account, from))
#define PurpleMessage  PurpleConvMessage
#define purple_message_set_time(msg, time)  ((msg)->when = (time))
#define purple_conversation_write_message(conv, msg)  purple_conversation_write(conv, msg->who, msg->what, msg->flags, msg->when)
static inline PurpleMessage *
purple_message_new_outgoing(const gchar *who, const gchar *contents, PurpleMessageFlags flags)
{
	PurpleMessage *message = g_new0(PurpleMessage, 1);
	
	message->who = g_strdup(who);
	message->what = g_strdup(contents);
	message->flags = flags;
	message->when = time(NULL);
	
	return message;
}
static inline void
purple_message_destroy(PurpleMessage *message)
{
	g_free(message->who);
	g_free(message->what);
	g_free(message);
}

#define purple_account_privacy_deny_add     purple_privacy_deny_add
#define purple_account_privacy_deny_remove  purple_privacy_deny_remove
#define PurpleHttpConnection  PurpleUtilFetchUrlData
#define purple_buddy_set_name  purple_blist_rename_buddy

#else
// Purple3 helper functions
#define purple_conversation_set_data(conv, key, value)  g_object_set_data(G_OBJECT(conv), key, value)
#define purple_conversation_get_data(conv, key)         g_object_get_data(G_OBJECT(conv), key)
#define purple_message_destroy          g_object_unref
#endif


typedef struct {
	PurpleAccount *account;
	PurpleConnection *pc;
	
	GHashTable *cookie_table;
	gchar *session_token;
	gchar *channel;
	gchar *self_user;
	
	PurpleSslConnection *websocket;
	gboolean websocket_header_received;
	gboolean sync_complete;
	guchar packet_code;
	gchar *frame;
	guint64 frame_len;
	guint64 frame_len_progress;
	
	gint64 seq;
	gint64 ack;
	gint64 opid;
	
	GHashTable *one_to_ones;     // A store of known groupId's->userId's
	GHashTable *one_to_ones_rev; // A store of known userId's->groupId's
	GHashTable *group_chats;     // A store of known multi-user groupId's
	GHashTable *sent_message_ids;// A store of message id's that we generated from this instance
	GHashTable *media_urls;      // MediaId -> URL

	GSList *http_conns; /**< PurpleHttpConnection to be cancelled on logout */
	gint frames_since_reconnect;
} YahooAccount;

typedef void (*YahooProxyCallbackFunc)(YahooAccount *ya, JsonNode *node, gpointer user_data);

typedef struct {
	YahooAccount *ya;
	YahooProxyCallbackFunc callback;
	gpointer user_data;
} YahooProxyConnection;





static gchar *
purple_base32_encode(const guchar *data, gsize len)
{
	static const char base32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	char *out, *rv;
	guchar work[5];
	
	g_return_val_if_fail(data != NULL, NULL);
	g_return_val_if_fail(len > 0,  NULL);
	
	rv = out = g_malloc(((len / 5) + 1) * 8 + 1);
	
	for (; len; len -= MIN(5, len))
	{
		memset(work, 0, 5);
		memcpy(work, data, MIN(5, len));
		
		*out++ = base32_alphabet[work[0] >> 3];
		*out++ = base32_alphabet[((work[0] & 0x07) << 2) | (work[1] >> 6)];
		*out++ = base32_alphabet[(work[1] >> 1) & 0x1f];
		*out++ = base32_alphabet[((work[1] & 0x01) << 4) | (work[2] >> 4)];
		*out++ = base32_alphabet[((work[2] & 0x0f) << 1) | (work[3] >> 7)];
		*out++ = base32_alphabet[(work[3] >> 2) & 0x1f];
		*out++ = base32_alphabet[((work[3] & 0x03) << 3) | (work[4] >> 5)];
		*out++ = base32_alphabet[work[4] & 0x1f];
		
		data += MIN(5, len);
	}
	
	*out = '\0';
	
	return rv;
}

gchar *
yahoo_string_get_chunk(const gchar *haystack, gsize len, const gchar *start, const gchar *end)
{
	const gchar *chunk_start, *chunk_end;
	g_return_val_if_fail(haystack && start && end, NULL);
	
	if (len > 0) {
		chunk_start = g_strstr_len(haystack, len, start);
	} else {
		chunk_start = strstr(haystack, start);
	}
	g_return_val_if_fail(chunk_start, NULL);
	chunk_start += strlen(start);
	
	if (len > 0) {
		chunk_end = g_strstr_len(chunk_start, len - (chunk_start - haystack), end);
	} else {
		chunk_end = strstr(chunk_start, end);
	}
	g_return_val_if_fail(chunk_end, NULL);
	
	return g_strndup(chunk_start, chunk_end - chunk_start);
}

#if PURPLE_VERSION_CHECK(3, 0, 0)
static void
yahoo_update_cookies(YahooAccount *ya, const GList *cookie_headers)
{
	const gchar *cookie_start;
	const gchar *cookie_end;
	gchar *cookie_name;
	gchar *cookie_value;
	const GList *cur;
	
	for (cur = cookie_headers; cur != NULL; cur = g_list_next(cur))
	{
		cookie_start = cur->data;
		
		cookie_end = strchr(cookie_start, '=');
		cookie_name = g_strndup(cookie_start, cookie_end-cookie_start);
		cookie_start = cookie_end + 1;
		cookie_end = strchr(cookie_start, ';');
		cookie_value= g_strndup(cookie_start, cookie_end-cookie_start);
		cookie_start = cookie_end;

		g_hash_table_replace(ya->cookie_table, cookie_name, cookie_value);
	}
}

#else
static void
yahoo_update_cookies(YahooAccount *ya, const gchar *headers)
{
	const gchar *cookie_start;
	const gchar *cookie_end;
	gchar *cookie_name;
	gchar *cookie_value;
	int header_len;

	g_return_if_fail(headers != NULL);

	header_len = strlen(headers);

	/* look for the next "Set-Cookie: " */
	/* grab the data up until ';' */
	cookie_start = headers;
	while ((cookie_start = strstr(cookie_start, "\r\nSet-Cookie: ")) && (cookie_start - headers) < header_len)
	{
		cookie_start += 14;
		cookie_end = strchr(cookie_start, '=');
		cookie_name = g_strndup(cookie_start, cookie_end-cookie_start);
		cookie_start = cookie_end + 1;
		cookie_end = strchr(cookie_start, ';');
		cookie_value= g_strndup(cookie_start, cookie_end-cookie_start);
		cookie_start = cookie_end;

		g_hash_table_replace(ya->cookie_table, cookie_name, cookie_value);
	}
}
#endif

static void
yahoo_cookie_foreach_cb(gchar *cookie_name, gchar *cookie_value, GString *str)
{
	g_string_append_printf(str, "%s=%s;", cookie_name, cookie_value);
}

static gchar *
yahoo_cookies_to_string(YahooAccount *ya)
{
	GString *str;

	str = g_string_new(NULL);

	g_hash_table_foreach(ya->cookie_table, (GHFunc)yahoo_cookie_foreach_cb, str);

	return g_string_free(str, FALSE);
}

static void
yahoo_response_callback(PurpleHttpConnection *http_conn, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleHttpResponse *response, gpointer user_data)
{
	gsize len;
	const gchar *url_text = purple_http_response_get_data(response, &len);
#else
gpointer user_data, const gchar *url_text, gsize len, const gchar *error_message)
{
#endif
	const gchar *body;
	gsize body_len;
	YahooProxyConnection *conn = user_data;
	JsonParser *parser = json_parser_new();
	
	conn->ya->http_conns = g_slist_remove(conn->ya->http_conns, http_conn);

#if !PURPLE_VERSION_CHECK(3, 0, 0)
	yahoo_update_cookies(conn->ya, url_text);
	
	body = g_strstr_len(url_text, len, "\r\n\r\n");
	body_len = len - (body - url_text);
#else
	yahoo_update_cookies(conn->ya, purple_http_response_get_headers_by_name(response, "Set-Cookie"));

	body = url_text;
	body_len = len;
#endif
	
	if (!json_parser_load_from_data(parser, body, body_len, NULL))
	{
		purple_debug_error("yahoo", "Error parsing response: %s\n", body);
		if (conn->callback) {
			conn->callback(conn->ya, NULL, conn->user_data);
		}
	} else {
		JsonNode *root = json_parser_get_root(parser);
		
		purple_debug_misc("yahoo", "Got response: %s\n", body);
		if (conn->callback) {
			conn->callback(conn->ya, root, conn->user_data);
		}
	}
	
	g_object_unref(parser);
	g_free(conn);
}

static void
yahoo_fetch_url(YahooAccount *ya, const gchar *url, const gchar *postdata, YahooProxyCallbackFunc callback, gpointer user_data)
{
	PurpleAccount *account;
	YahooProxyConnection *conn;
	gchar *cookies;
	
	account = ya->account;
	if (purple_account_is_disconnected(account)) return;
	
	conn = g_new0(YahooProxyConnection, 1);
	conn->ya = ya;
	conn->callback = callback;
	conn->user_data = user_data;
	
	cookies = yahoo_cookies_to_string(ya);
	
	purple_debug_info("yahoo", "Fetching url %s\n", url);

#if PURPLE_VERSION_CHECK(3, 0, 0)
	
	PurpleHttpRequest *request = purple_http_request_new(url);
	purple_http_request_header_set(request, "Accept", "*/*");
	purple_http_request_header_set(request, "User-Agent", YAHOO_USERAGENT);
	purple_http_request_header_set(request, "Cookie", cookies);
	
	if (postdata) {
		purple_debug_info("yahoo", "With postdata %s\n", postdata);
		
		if (postdata[0] == '{') {
			purple_http_request_header_set(request, "Content-Type", "application/json");
		} else {
			purple_http_request_header_set(request, "Content-Type", "application/x-www-form-urlencoded");
		}
		purple_http_request_set_contents(request, postdata, -1);
	}
	
	purple_http_request(ya->pc, request, yahoo_response_callback, conn);
	purple_http_request_unref(request);

	// TODO: add something to ya->http_conns

#else
	PurpleHttpConnection *http_conn;
	GString *headers;
	gchar *host = NULL, *path = NULL, *user = NULL, *password = NULL;
	int port;
	purple_url_parse(url, &host, &port, &path, &user, &password);
	
	headers = g_string_new(NULL);
	
	//Use the full 'url' until libpurple can handle path's longer than 256 chars
	g_string_append_printf(headers, "%s /%s HTTP/1.0\r\n", (postdata ? "POST" : "GET"), path);
	//g_string_append_printf(headers, "%s %s HTTP/1.0\r\n", (postdata ? "POST" : "GET"), url);
	g_string_append_printf(headers, "Connection: close\r\n");
	g_string_append_printf(headers, "Host: %s\r\n", host);
	g_string_append_printf(headers, "Accept: */*\r\n");
	g_string_append_printf(headers, "User-Agent: " YAHOO_USERAGENT "\r\n");
	g_string_append_printf(headers, "Cookie: %s\r\n", cookies);

	if (postdata) {
		purple_debug_info("yahoo", "With postdata %s\n", postdata);
		
		if (postdata[0] == '{') {
			g_string_append(headers, "Content-Type: application/json\r\n");
		} else {
			g_string_append(headers, "Content-Type: application/x-www-form-urlencoded\r\n");
		}
		g_string_append_printf(headers, "Content-Length: %" G_GSIZE_FORMAT "\r\n", strlen(postdata));
		g_string_append(headers, "\r\n");

		g_string_append(headers, postdata);
	} else {
		g_string_append(headers, "\r\n");
	}

	g_free(host);
	g_free(path);
	g_free(user);
	g_free(password);

	http_conn = purple_util_fetch_url_request_len_with_account(ya->account, url, FALSE, YAHOO_USERAGENT, TRUE, headers->str, TRUE, 6553500, yahoo_response_callback, conn);
	
	if (http_conn != NULL)
		ya->http_conns = g_slist_prepend(ya->http_conns, http_conn);

	g_string_free(headers, TRUE);
#endif

	g_free(cookies);
}

static void
yahoo_process_mutation_op_entity(JsonArray *array, guint index_, JsonNode *element_node, gpointer user_data)
{
	YahooAccount *ya = user_data;
	JsonArray *change_array = json_node_get_array(element_node);
	JsonArray *entity;
	gint entity_length;
	
	if (json_array_get_length(change_array) < 3) {
		return;
	}
	
	entity = json_array_get_array_element(change_array, 0);
	entity_length = json_array_get_length(entity);
	
	if (entity_length == 4 &&
		purple_strequal(json_array_get_string_element(entity, 0), "Group") &&
		purple_strequal(json_array_get_string_element(entity, 2), "items")) {
		
		const gchar *oldItemId = json_array_get_string_element(change_array, 2);
		if (g_hash_table_contains(ya->sent_message_ids, oldItemId)) {
			const gchar *newItemId = json_array_get_string_element(entity, 3);
			
			g_hash_table_remove(ya->sent_message_ids, oldItemId);
			g_hash_table_replace(ya->sent_message_ids, g_strdup(newItemId), NULL);
		}
		
	} else if (entity_length == 2 &&
		purple_strequal(json_array_get_string_element(entity, 0), "Group")) {
		
		const gchar *oldItemId = json_array_get_string_element(change_array, 2);
		if (g_hash_table_contains(ya->group_chats, oldItemId)) {
			const gchar *newItemId = json_array_get_string_element(entity, 1);
			PurpleChat *chat;
			
			g_hash_table_remove(ya->group_chats, oldItemId);
			g_hash_table_replace(ya->group_chats, g_strdup(newItemId), NULL);
			
			while ((chat = purple_blist_find_chat(ya->account, oldItemId))) {
				purple_blist_node_set_string(PURPLE_BLIST_NODE(chat), "groupId", newItemId);
				g_hash_table_replace(purple_chat_get_components(chat), g_strdup("groupId"), g_strdup(newItemId));
			}
			
		} else if (g_hash_table_contains(ya->one_to_ones, oldItemId)) {
			const gchar *newItemId = json_array_get_string_element(entity, 1);
			gchar *userId = g_strdup(g_hash_table_lookup(ya->one_to_ones, oldItemId));
			PurpleBuddy *buddy = purple_blist_find_buddy(ya->account, userId);
				
			if (buddy != NULL) {
				purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "groupId", newItemId);
			}
			
			g_hash_table_remove(ya->one_to_ones, oldItemId);
			g_hash_table_remove(ya->one_to_ones_rev, userId);
			
			g_hash_table_replace(ya->one_to_ones, g_strdup(newItemId), g_strdup(userId));
			g_hash_table_replace(ya->one_to_ones_rev, g_strdup(userId), g_strdup(newItemId));
			
			g_free(userId);
		}
		
	} else if (entity_length == 2 &&
		purple_strequal(json_array_get_string_element(entity, 0), "User")) {
		
		const gchar *oldItemId = json_array_get_string_element(change_array, 2);
		if (g_hash_table_contains(ya->one_to_ones_rev, oldItemId)) {
			const gchar *newItemId = json_array_get_string_element(entity, 1);
			gchar *groupId = g_strdup(g_hash_table_lookup(ya->one_to_ones_rev, oldItemId));
			PurpleBuddy *bad_buddy;
				
			while ((bad_buddy = purple_blist_find_buddy(ya->account, oldItemId))) {
				purple_buddy_set_name(bad_buddy, newItemId);
			}
			
			g_hash_table_remove(ya->one_to_ones_rev, oldItemId);
			g_hash_table_remove(ya->one_to_ones, groupId);
			
			g_hash_table_replace(ya->one_to_ones_rev, g_strdup(newItemId), g_strdup(groupId));
			g_hash_table_replace(ya->one_to_ones, g_strdup(groupId), g_strdup(newItemId));
			
			g_free(groupId);
			
			purple_protocol_got_user_status(ya->account, newItemId, "online", NULL);
		}
		
	}
}

static void
yahoo_process_mutation_op(JsonArray *array, guint index_, JsonNode *element_node, gpointer user_data)
{
	YahooAccount *ya = user_data;
	JsonObject *op = json_node_get_object(element_node);
	
	json_array_foreach_element_reverse(json_object_get_array_member(op, "entities"), yahoo_process_mutation_op_entity, ya);
}

void yahoo_block_user(PurpleConnection *pc, const char *who);
static void yahoo_socket_write_json(YahooAccount *ya, JsonObject *data);
static GHashTable *yahoo_chat_info_defaults(PurpleConnection *pc, const char *chatname);

static void
yahoo_auth_allow(
#if PURPLE_VERSION_CHECK(3, 0, 0)
const gchar *message,
#endif
gpointer userdata)
{
	PurpleBuddy *buddy = userdata;
	PurpleAccount *account = purple_buddy_get_account(buddy);
	PurpleConnection *pc = purple_account_get_connection(account);
	YahooAccount *ya = purple_connection_get_protocol_data(pc);
	const gchar *userId = purple_buddy_get_name(buddy);
	JsonObject *data = json_object_new();
	
	json_object_set_string_member(data, "msg", "AcceptUser");
	json_object_set_string_member(data, "userId", userId);
	json_object_set_int_member(data, "opId", ya->opid++);
	
	yahoo_socket_write_json(ya, data);
}

static void
yahoo_auth_deny(
#if PURPLE_VERSION_CHECK(3, 0, 0)
const gchar *message,
#endif
gpointer userdata)
{
	PurpleBuddy *buddy = userdata;
	PurpleAccount *account = purple_buddy_get_account(buddy);
	PurpleConnection *pc = purple_account_get_connection(account);
	const gchar *userId = purple_buddy_get_name(buddy);
	
	yahoo_block_user(pc, userId);
}
	
static void
yahoo_process_msg(JsonArray *array, guint index_, JsonNode *element_node, gpointer user_data)
{
	JsonObject *response = NULL;
	YahooAccount *ya = user_data;
	JsonObject *obj = json_node_get_object(element_node);
	PurpleGroup *yahoo_group = NULL;
	const gchar *msg = json_object_get_string_member(obj, "msg");
	gint64 createdTime = json_object_get_int_member(obj, "createdTime");
	gboolean old_event = !ya->sync_complete;
	
	if (purple_strequal(msg, "NewEntity")) {
		JsonArray *key_array = json_object_get_array_member(obj, "key");
		const gchar *key = json_array_get_string_element(key_array, 0);
		const gchar *subkey = json_array_get_length(key_array) > 2 ? json_array_get_string_element(key_array, 2) : NULL;
		
		if (purple_strequal(key, "User")) {
			if (subkey == NULL) {
				// New buddy
				const gchar *userId = json_object_get_string_member(obj, "userId");
				const gchar *fullName = json_object_get_string_member(obj, "fullName");
				PurpleBuddy *buddy = purple_blist_find_buddy(ya->account, userId);
				
				// Check that we didn't try to add a funky buddy to the buddy list
				if (json_object_has_member(obj, "inviteIdentifier")) {
					const gchar *inviteIdentifier = json_object_get_string_member(obj, "inviteIdentifier");
					PurpleBuddy *bad_buddy;
					
					while ((bad_buddy = purple_blist_find_buddy(ya->account, inviteIdentifier))) {
						purple_buddy_set_name(bad_buddy, userId);
					}
					
					buddy = purple_blist_find_buddy(ya->account, userId);
				}
				
				if (buddy == NULL) {
					buddy = purple_buddy_new(ya->account, userId, fullName);
					if (yahoo_group == NULL) {
						yahoo_group = purple_blist_find_group(_("Yahoo"));
						if (!yahoo_group)
						{
							yahoo_group = purple_group_new(_("Yahoo"));
							purple_blist_add_group(yahoo_group, NULL);
						}
					}
					purple_blist_add_buddy(buddy, NULL, yahoo_group, NULL);
				}
				
				if (purple_buddy_get_server_alias(buddy) == NULL || !purple_strequal(purple_buddy_get_server_alias(buddy), fullName)) {
					purple_serv_got_alias(ya->pc, userId, fullName);
				}
				
				if (G_UNLIKELY(purple_strequal(userId, ya->self_user))) {
					const gchar *account_alias = purple_account_get_private_alias(ya->account);
					if (G_UNLIKELY(!account_alias || !*account_alias)) {
						purple_account_set_private_alias(ya->account, fullName);
					}
				}
				
				purple_protocol_got_user_status(ya->account, userId, "online", NULL);
				
				if (json_object_has_member(obj, "picture")) {
					const gchar *mediaId = json_array_get_string_element(json_object_get_array_member(obj, "picture"), 3);
					const gchar *media_url = g_hash_table_lookup(ya->media_urls, mediaId);
					
					if (!purple_strequal(purple_buddy_icons_get_checksum_for_user(buddy), media_url)) {
						//TODO
						//yahoo_fetch_url(ya, url, NULL, yahoo_got_buddy_icon, buddy);
					}
				}
			} else if (purple_strequal(subkey, "media")) {
				const gchar *mediaId = json_array_get_string_element(key_array, 3);
				const gchar *originalUrl = json_object_get_string_member(obj, "originalUrl");
				
				purple_debug_info("yahoo", "Received media id %s with url %s\n", mediaId, originalUrl);
				g_hash_table_replace(ya->media_urls, g_strdup(mediaId), g_strdup(originalUrl));
			}
			
		} else if (purple_strequal(key, "Group")) {
			if (subkey == NULL) {
				// New group
				const gchar *groupId = json_object_get_string_member(obj, "groupId");
				gint64 memberCount = json_object_get_int_member(obj, "memberCount");
				if (json_object_get_boolean_member(obj, "defaultGroup") && memberCount == 2) {
					const gchar *otherUser = json_array_get_string_element(json_object_get_array_member(obj, "defaultGroupOtherUser"), 1);
					PurpleBuddy *buddy = purple_blist_find_buddy(ya->account, otherUser);
					
					// This is a one-to-one IM
					g_hash_table_replace(ya->one_to_ones, g_strdup(groupId), g_strdup(otherUser));
					g_hash_table_replace(ya->one_to_ones_rev, g_strdup(otherUser), g_strdup(groupId));
					
					if (buddy != NULL) {
						purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "groupId", groupId);
					}
				} else if (memberCount > 2) {
					PurpleChat *chat = purple_blist_find_chat(ya->account, groupId);
					const gchar *name = json_object_get_string_member(obj, "name");
					
					// This is a group chat
					g_hash_table_replace(ya->group_chats, g_strdup(groupId), NULL);
					
					if (chat == NULL) {
						if (yahoo_group == NULL) {
							yahoo_group = purple_blist_find_group(_("Yahoo"));
							if (!yahoo_group)
							{
								yahoo_group = purple_group_new(_("Yahoo"));
								purple_blist_add_group(yahoo_group, NULL);
							}
						}
						purple_blist_add_chat(purple_chat_new(ya->account, name?name:groupId, yahoo_chat_info_defaults(ya->pc, groupId)), yahoo_group, NULL);
					}
				}
				
			} else {
				if (!old_event && purple_strequal(json_object_get_string_member(obj, "type"), "post")) {
					gchar *message = purple_markup_escape_text(json_object_get_string_member(obj, "message"), -1);
					const gchar *user = json_array_get_string_element(json_object_get_array_member(obj, "user"), 1);
					const gchar *group = json_array_get_string_element(json_object_get_array_member(obj, "group"), 1);
					gint64 timestamp = createdTime / 1000;
					PurpleMessageFlags msg_flags = (purple_strequal(user, ya->self_user) ? PURPLE_MESSAGE_SEND : PURPLE_MESSAGE_RECV);
					const gchar *itemId = json_object_get_string_member(obj, "itemId");
					
					//check we didn't send this
					if (msg_flags == PURPLE_MESSAGE_RECV || !g_hash_table_remove(ya->sent_message_ids, itemId)) {
						if (g_hash_table_contains(ya->group_chats, group)) {
							//Group chat message
							PurpleChatConversation *chatconv = purple_conversations_find_chat_with_account(group, ya->account);
							if (chatconv == NULL) {
								chatconv = purple_serv_got_joined_chat(ya->pc, g_str_hash(group), group);
								purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "group", g_strdup(group));
							}
							
							purple_serv_got_chat_in(ya->pc, g_str_hash(group), user, msg_flags, message, timestamp);
						} else {
							if (msg_flags == PURPLE_MESSAGE_RECV) {
								purple_serv_got_im(ya->pc, user, message, msg_flags, timestamp);
								
								//sometimes we get chat messages before we get the list of groups
								// if (!g_hash_table_contains(ya->one_to_ones, group)) {
									// g_hash_table_replace(ya->one_to_ones, g_strdup(group), g_strdup(user));
									// g_hash_table_replace(ya->one_to_ones_rev, g_strdup(user), g_strdup(group));
								// }
							} else {
								const gchar *other_user = g_hash_table_lookup(ya->one_to_ones, group);
								//TODO null check
								PurpleIMConversation *imconv = purple_conversations_find_im_with_account(other_user, ya->account);
								PurpleMessage *msg = purple_message_new_outgoing(other_user, message, msg_flags);
								
								if (imconv == NULL) {
									imconv = purple_im_conversation_new(ya->account, other_user);
								}
								purple_message_set_time(msg, timestamp);
								purple_conversation_write_message(PURPLE_CONVERSATION(imconv), msg);
								purple_message_destroy(msg);
							}
						}
					}
					
					g_free(message);
				} else if (purple_strequal(subkey, "members")) {
					if (purple_strequal(json_object_get_string_member(obj, "invitationState"), "joined")) {
						const gchar *message = NULL; //"%s has invited %s to the chat room %s\n"
						const gchar *userId = json_array_get_string_element(json_object_get_array_member(obj, "user"), 1);
						const gchar *groupId = json_array_get_string_element(json_object_get_array_member(obj, "group"), 1);
						//const gchar *invitedBy = json_array_get_string_element(json_object_get_array_member(obj, "invitedBy"), 1);
						PurpleChatUserFlags cbflags = json_object_get_boolean_member(obj, "admin") ? PURPLE_CHAT_USER_OP : PURPLE_CHAT_USER_NONE;
						PurpleChatConversation *chatconv = purple_conversations_find_chat_with_account(groupId, ya->account);
						
						if (chatconv == NULL && !old_event) {
							if (g_hash_table_contains(ya->group_chats, groupId)) {
								chatconv = purple_serv_got_joined_chat(ya->pc, g_str_hash(groupId), groupId);
								purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "groupId", g_strdup(groupId));
							}
						}
						
						if (chatconv != NULL) {
							purple_chat_conversation_add_user(chatconv, userId, message, cbflags, TRUE);
						}
					}
				} else if (purple_strequal(json_object_get_string_member(obj, "type"), "memberRemoved")) {
					const gchar *message = NULL; //"%s left the room."
					const gchar *groupId = json_array_get_string_element(json_object_get_array_member(obj, "group"), 1);
					const gchar *userId = json_array_get_string_element(json_object_get_array_member(obj, "user"), 1);
					PurpleChatConversation *chatconv = purple_conversations_find_chat_with_account(groupId, ya->account);
					
					if (chatconv != NULL) {
						purple_chat_conversation_remove_user(chatconv, userId, message);
					}
				} else if (!old_event && purple_strequal(subkey, "Item") && purple_strequal(json_array_get_string_element(key_array, 4), "media")) {
					//TODO split this out for the regular message receive handling code
					
					// Received a message with a photo
					JsonArray *media_array = json_object_get_array_member(obj, "media");
					const gchar *mediaId = json_array_get_string_element(media_array, 3);
					const gchar *media_url = g_hash_table_lookup(ya->media_urls, mediaId);
					const gchar *userId = json_array_get_string_element(media_array, 1);
					const gchar *groupId = json_array_get_string_element(json_object_get_array_member(obj, "group"), 1);
					gint64 timestamp = createdTime / 1000;
					PurpleMessageFlags msg_flags = (purple_strequal(userId, ya->self_user) ? PURPLE_MESSAGE_SEND : PURPLE_MESSAGE_RECV);

					if (g_hash_table_contains(ya->group_chats, groupId)) {
						//Group chat message
						PurpleChatConversation *chatconv = purple_conversations_find_chat_with_account(groupId, ya->account);
						if (chatconv == NULL) {
							chatconv = purple_serv_got_joined_chat(ya->pc, g_str_hash(groupId), groupId);
							purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "groupId", g_strdup(groupId));
						}
						
						purple_serv_got_chat_in(ya->pc, g_str_hash(groupId), userId, msg_flags, media_url, timestamp);
					} else {
						if (msg_flags == PURPLE_MESSAGE_RECV) {
							purple_serv_got_im(ya->pc, userId, media_url, msg_flags, timestamp);
						} else {
							const gchar *other_user = g_hash_table_lookup(ya->one_to_ones, groupId);
							//TODO null check
							PurpleIMConversation *imconv = purple_conversations_find_im_with_account(other_user, ya->account);
							PurpleMessage *msg = purple_message_new_outgoing(other_user, media_url, msg_flags);
							
							if (imconv == NULL) {
								imconv = purple_im_conversation_new(ya->account, other_user);
							}
							purple_message_set_time(msg, timestamp);
							purple_conversation_write_message(PURPLE_CONVERSATION(imconv), msg);
							purple_message_destroy(msg);
						}
					}
				}
			}
		} else if (purple_strequal(key, "BlockedUser")) {
			const gchar *userId = json_array_get_string_element(key_array, 1);
			purple_account_privacy_deny_add(ya->account, userId, TRUE);
		} else if (purple_strequal(key, "GroupPrivate")) {
			if (json_object_has_member(obj, "unknownInviter")) {
				JsonArray *unknownInviter = json_object_get_array_member(obj, "unknownInviter");
				const gchar *userId = json_array_get_string_element(unknownInviter, 1);
				PurpleBuddy *buddy = purple_blist_find_buddy(ya->account, userId);
				const gchar *alias = purple_buddy_get_server_alias(buddy);
				
				if (buddy == NULL) {
					buddy = purple_buddy_new(ya->account, userId, NULL);
				}
				
				purple_account_request_authorization(ya->account, userId, NULL, alias, NULL, TRUE, yahoo_auth_allow, yahoo_auth_deny, buddy);
			}
		}
	} else if (purple_strequal(msg, "SyncBatch")) {
		response = json_object_new();
		json_object_set_string_member(response, "msg", "SyncAck");
		json_object_set_string_member(response, "pushId", json_object_get_string_member(obj, "pushId"));
	} else if (purple_strequal(msg, "MutationResponse")) {
		
		json_array_foreach_element_reverse(json_object_get_array_member(obj, "ops"), yahoo_process_mutation_op, ya);
		
		response = json_object_new();
		json_object_set_string_member(response, "msg", "MutationResponseAck");
		json_object_set_string_member(response, "ackId", json_object_get_string_member(obj, "ackId"));
	} else if (purple_strequal(msg, "DropEntity")) {
		JsonArray *key_array = json_object_get_array_member(obj, "key");
		const gchar *key = json_array_get_string_element(key_array, 0);
		
		if (purple_strequal(key, "BlockedUser")) {
			const gchar *userId = json_array_get_string_element(key_array, 1);
			purple_account_privacy_deny_remove(ya->account, userId, TRUE);
		}
	}
	
	if (response != NULL) {
		yahoo_socket_write_json(ya, response);
	}
}

static void
yahoo_process_msg_array(JsonArray *array, guint index_, JsonNode *element_node, gpointer user_data)
{
	json_array_foreach_element_reverse(json_node_get_array(element_node), yahoo_process_msg, user_data);
}

static void yahoo_start_socket(YahooAccount *ya);

static void
yahoo_rpc_callback(YahooAccount *ya, JsonNode *node, gpointer user_data)
{
	JsonObject *obj = json_node_get_object(node);
	const gchar *msg = json_object_get_string_member(obj, "msg");
	
	if (purple_strequal(msg, "SessionOpened")) {
		//connected
		ya->session_token = g_strdup(json_object_get_string_member(obj, "sessionToken"));
		ya->channel = g_strdup(json_object_get_string_member(obj, "channelId"));
		ya->self_user = g_strdup(json_object_get_string_member(obj, "userId"));
		
		purple_connection_set_display_name(ya->pc, ya->self_user);
		purple_connection_set_state(ya->pc, PURPLE_CONNECTION_CONNECTED);
		
		//process batch
		json_array_foreach_element_reverse(json_object_get_array_member(obj, "batch"), yahoo_process_msg, ya);
		
		yahoo_start_socket(ya);
	} else if (purple_strequal(msg, "UserMustActivate")) {
		purple_notify_uri(ya->pc, "https://messenger.yahoo.com/");
		purple_connection_error(ya->pc, PURPLE_CONNECTION_ERROR_OTHER_ERROR, _("Please login to the Yahoo messenger website once, to continue"));
	} else if (purple_strequal(msg, "InvalidCredentials")) {
		purple_connection_error(ya->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, "Session expired");
	} else {
		purple_connection_error(ya->pc, PURPLE_CONNECTION_ERROR_OTHER_ERROR, json_object_get_string_member(obj, "reason"));
	}
}
	
static void
yahoo_auth_callback(YahooAccount *ya, JsonNode *node, gpointer user_data)
{
	JsonObject *obj = json_node_get_object(node);
	
	if (purple_strequal(json_object_get_string_member(obj, "status"), "error")) {
		if (purple_strequal(json_object_get_string_member(obj, "code"), "1212")) {
			purple_connection_error(ya->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,  json_object_get_string_member(obj, "message"));
		} else {
			purple_connection_error(ya->pc, PURPLE_CONNECTION_ERROR_OTHER_ERROR, json_object_get_string_member(obj, "message"));
		}
	} else {
		const gchar *rpcdata = "{\"msg\":\"OpenSession\",\"device\":{\"kind\":\"mobile\"},\"auth\":{\"provider\":\"signin\"},\"version\":{\"platform\":\"web\",\"app\":\"iris/dogfood\",\"appVersion\":" YAHOO_PRETEND_VERSION "},\"batch\":[]}";
		
		purple_connection_set_state(ya->pc, PURPLE_CONNECTION_CONNECTING);
		yahoo_fetch_url(ya, "https://prod.iris.yahoo.com/prod/rpc?wait=1&v=1", rpcdata, yahoo_rpc_callback, NULL);
	}
}

static void
yahoo_restart_channel(YahooAccount *ya)
{
	gchar *rpcdata = g_strdup_printf("{\"msg\":\"ReopenSession\",\"sessionToken\":\"%s\",\"batch\":[],\"version\":{\"platform\":\"web\",\"app\":\"iris/dogfood\",\"appVersion\":" YAHOO_PRETEND_VERSION "}}", ya->session_token);
	
	purple_connection_set_state(ya->pc, PURPLE_CONNECTION_CONNECTING);
	yahoo_fetch_url(ya, "https://prod.iris.yahoo.com/prod/rpc?wait=1&v=1", rpcdata, yahoo_rpc_callback, NULL);

	ya->seq = 0;
	ya->ack = 1;
	
	g_free(rpcdata);
}

static void
yahoo_preauth_callback(PurpleHttpConnection *http_conn, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleHttpResponse *response, gpointer user_data)
{
	gsize len;
	const gchar *url_text = purple_http_response_get_data(response, &len);
#else
gpointer user_data, const gchar *url_text, gsize len, const gchar *error_message)
{
#endif
	YahooAccount *ya = user_data;
	GString *postdata = g_string_new("");
	gchar *crumb = yahoo_string_get_chunk(url_text, len, "<input name=\"_crumb\" type=\"hidden\" value=\"", "\"");

	ya->http_conns = g_slist_remove(ya->http_conns, http_conn);
	
#if PURPLE_VERSION_CHECK(3, 0, 0)
	yahoo_update_cookies(ya, purple_http_response_get_headers_by_name(response, "Set-Cookie"));
#else
	yahoo_update_cookies(ya, url_text);
#endif
	if (g_hash_table_lookup(ya->cookie_table, "B") == NULL) {
		purple_connection_error(ya->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, "Couldn't get login cookies");
		return;
	}
	
	g_string_append_printf(postdata, "username=%s&", purple_url_encode(purple_account_get_username(ya->account)));
	g_string_append_printf(postdata, "passwd=%s&", purple_url_encode(purple_connection_get_password(ya->pc)));
	g_string_append_printf(postdata, "_crumb=%s&", purple_url_encode(crumb));
	g_string_append(postdata, "countrycode=1&");
	g_string_append(postdata, "signin=&");
	g_string_append(postdata, "otp_channel=&");
	g_string_append(postdata, ".persistent=y&");
	g_string_append(postdata, "_format=json&");
	g_string_append(postdata, "_seqid=1&");
	
	purple_connection_set_state(ya->pc, PURPLE_CONNECTION_CONNECTING);
	yahoo_fetch_url(ya, "https://login.yahoo.com/?.pd=&.src=messenger&.done=https%3A%2F%2Fmessenger.yahoo.com%2F", postdata->str, yahoo_auth_callback, NULL);
	
	g_free(crumb);
	g_string_free(postdata, TRUE);
}

static void
yahoo_build_groups_from_blist(YahooAccount *ya)
{
	PurpleBlistNode *node;
	
	for (node = purple_blist_get_root();
	     node != NULL;
		 node = purple_blist_node_next(node, TRUE)) {
		if (PURPLE_IS_CHAT(node)) {
			const gchar *groupId;
			PurpleChat *chat = PURPLE_CHAT(node);
			if (purple_chat_get_account(chat) != ya->account) {
				continue;
			}
			
			groupId = purple_blist_node_get_string(node, "groupId");
			if (groupId == NULL) {
				GHashTable *components = purple_chat_get_components(chat);
				if (components != NULL) {
					groupId = g_hash_table_lookup(components, "groupId");
				}
			}
			if (groupId != NULL) {
				g_hash_table_replace(ya->group_chats, g_strdup(groupId), NULL);
			}
		} else if (PURPLE_IS_BUDDY(node)) {
			const gchar *groupId;
			const gchar *name;
			PurpleBuddy *buddy = PURPLE_BUDDY(node);
			if (purple_buddy_get_account(buddy) != ya->account) {
				continue;
			}
			
			name = purple_buddy_get_name(buddy);
			groupId = purple_blist_node_get_string(node, "groupId");
			if (groupId != NULL) {
				g_hash_table_replace(ya->one_to_ones, g_strdup(groupId), g_strdup(name));
				g_hash_table_replace(ya->one_to_ones_rev, g_strdup(name), g_strdup(groupId));
			}
		}
	}
}


static void yahoo_blist_node_removed(PurpleBlistNode *node);

void
yahoo_login(PurpleAccount *account)
{
	YahooAccount *ya;
	PurpleHttpConnection *http_conn;
	PurpleConnection *pc = purple_account_get_connection(account);
	GString *preauth_url = g_string_new("https://login.yahoo.com/?");
	
	g_string_append_printf(preauth_url, ".done=%s&", purple_url_encode("https://messenger.yahoo.com/"));
	g_string_append_printf(preauth_url, ".src=%s&", purple_url_encode("messenger"));
	g_string_append(preauth_url, ".asdk_embedded=1&");
	
	ya = g_new0(YahooAccount, 1);
	purple_connection_set_protocol_data(pc, ya);
	ya->account = account;
	ya->pc = pc;
	ya->cookie_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ya->ack = 1;
	ya->seq = 1;
	
	ya->one_to_ones = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ya->one_to_ones_rev = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	ya->group_chats = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	ya->sent_message_ids = g_hash_table_new_full(g_str_insensitive_hash, g_str_insensitive_equal, g_free, NULL);
	ya->media_urls = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	
	purple_connection_set_state(ya->pc, PURPLE_CONNECTION_CONNECTING);
#if !PURPLE_VERSION_CHECK(3, 0, 0)
	http_conn = purple_util_fetch_url_request_len_with_account(account, preauth_url->str, FALSE, YAHOO_USERAGENT, FALSE, NULL, TRUE, 6553500, yahoo_preauth_callback, ya);
#else
	{
		PurpleHttpRequest *request = purple_http_request_new(preauth_url->str);
		purple_http_request_header_set(request, "User-Agent", YAHOO_USERAGENT);
		http_conn = purple_http_request(ya->pc, request, yahoo_preauth_callback, ya);
		purple_http_request_unref(request);
	}
#endif
	
	if (http_conn != NULL) {
		ya->http_conns = g_slist_prepend(ya->http_conns, http_conn);
	}
	
	g_string_free(preauth_url, TRUE);
	
	//Build the initial hash tables from the current buddy list
	yahoo_build_groups_from_blist(ya);
	
	purple_signal_connect(purple_blist_get_handle(), "blist-node-removed", account, PURPLE_CALLBACK(yahoo_blist_node_removed), NULL);
}


static void 
yahoo_close(PurpleConnection *pc)
{
	YahooAccount *ya = purple_connection_get_protocol_data(pc);
	// PurpleAccount *account;
	
	g_return_if_fail(ya != NULL);
	
	// account = purple_connection_get_account(pc);
	if (ya->websocket != NULL) purple_ssl_close(ya->websocket);
	
	g_hash_table_remove_all(ya->one_to_ones);
	g_hash_table_unref(ya->one_to_ones);
	g_hash_table_remove_all(ya->one_to_ones_rev);
	g_hash_table_unref(ya->one_to_ones_rev);
	g_hash_table_remove_all(ya->group_chats);
	g_hash_table_unref(ya->group_chats);
	g_hash_table_remove_all(ya->sent_message_ids);
	g_hash_table_unref(ya->sent_message_ids);
	g_hash_table_remove_all(ya->media_urls);
	g_hash_table_unref(ya->media_urls);

#if !PURPLE_VERSION_CHECK(3, 0, 0)
	while (ya->http_conns) {
		purple_util_fetch_url_cancel(ya->http_conns->data);
		ya->http_conns = g_slist_delete_link(ya->http_conns, ya->http_conns);
	}
#else
	// TODO: cancel ya->http_conns here
#endif
	
	g_hash_table_destroy(ya->cookie_table); ya->cookie_table = NULL;
	g_free(ya->frame); ya->frame = NULL;
	g_free(ya->session_token); ya->session_token = NULL;
	g_free(ya->channel); ya->channel = NULL;
	g_free(ya->self_user); ya->self_user = NULL;
	g_free(ya);
}















//static void yahoo_start_polling(YahooAccount *ya);

static gboolean
yahoo_process_frame(YahooAccount *ya, const gchar *frame)
{
	JsonParser *parser = json_parser_new();
	JsonNode *root;
	
	purple_debug_info("yahoo", "got frame data: %s\n", frame);
	
	if (!json_parser_load_from_data(parser, frame, -1, NULL))
	{
		purple_debug_error("yahoo", "Error parsing response: %s\n", frame);
		return TRUE;
	}
	
	root = json_parser_get_root(parser);
	
	if (root != NULL) {
		JsonObject *message = json_node_get_object(root);
		if (G_UNLIKELY(json_object_has_member(message, "msg"))) {
			const gchar *msg = json_object_get_string_member(message, "msg");
			
			if (purple_strequal(msg, "ChannelNotFound")) {
				yahoo_restart_channel(ya);
			} else if (purple_strequal(msg, "InvalidCredentials")) {
				purple_connection_error(ya->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, "Session expired");
			} else if (purple_strequal(msg, "ChannelProtocolError")) {
				//Client skipped ahead (frame.seq=18, numResent=-17, numAcked=0, clientSeq=1)
				//Client ack 16 exceeds server seq 4
				
				ya->seq = 0;
				//ya->ack = 0;

				if (ya->frames_since_reconnect < 2) {
					char *error = g_strdup_printf("Server error: \"%s\". If this keeps happening, report a bug. Try to include the debug window messages before the error happens.",
						json_object_get_string_member(message, "reason"));
					purple_connection_error(ya->pc, PURPLE_CONNECTION_ERROR_OTHER_ERROR, error);
					g_free(error);
				} else {
					yahoo_start_socket(ya);
				}
				
				g_object_unref(parser);
				return FALSE;
			}
			
		} else {
			gint64 seq = json_object_get_int_member(message, "seq");
			gint64 ack = json_object_get_int_member(message, "ack");
			JsonArray *data = json_object_get_array_member(message, "data");
			
			ya->seq = MAX(ya->seq, ack);
			ya->ack = seq + json_array_get_length(data);
			
			if (data && json_array_get_length(data)) {
				json_array_foreach_element(data, yahoo_process_msg_array, ya);
			}

			ya->sync_complete = TRUE;
		}
	}
	ya->frames_since_reconnect += 1;
	
	g_object_unref(parser);
	return TRUE;
}

static guchar *
yahoo_websocket_mask(guchar key[4], const guchar *pload, guint64 psize)
{
	guint64 i;
	guchar *ret = g_new0(guchar, psize);

	for (i = 0; i < psize; i++) {
		ret[i] = pload[i] ^ key[i % 4];
	}

	return ret;
}

static void
yahoo_socket_write_data(YahooAccount *ya, guchar *data, gsize data_len, guchar type)
{
	guchar *full_data;
	guint len_size = 1;
	guchar mkey[4] = { 0x12, 0x34, 0x56, 0x78 };
	
	if (data_len) {
		purple_debug_info("yahoo", "sending frame: %*s\n", (int)data_len, data);
	}
	
	data = yahoo_websocket_mask(mkey, data, data_len);
	
	if (data_len > 125) {
		if (data_len <= G_MAXUINT16) {
			len_size += 2;
		} else {
			len_size += 8;
		}
	}
	full_data = g_new0(guchar, 1 + data_len + len_size + 4);
	
	if (type == 0) {
		type = 129;
	}
	full_data[0] = type;
	
	if (data_len <= 125) {
		full_data[1] = data_len | 0x80;
	} else if (data_len <= G_MAXUINT16) {
		guint16 be_len = GUINT16_TO_BE(data_len);
		full_data[1] = 126 | 0x80;
		memmove(full_data + 2, &be_len, 2);
	} else {
		guint64 be_len = GUINT64_TO_BE(data_len);
		full_data[1] = 127 | 0x80;
		memmove(full_data + 2, &be_len, 8);
	}
	
	memmove(full_data + (1 + len_size), &mkey, 4);
	memmove(full_data + (1 + len_size + 4), data, data_len);
	
	purple_ssl_write(ya->websocket, full_data, 1 + data_len + len_size + 4);
	
	g_free(full_data);
	g_free(data);
}

/* takes ownership of data parameter */
static void
yahoo_socket_write_json(YahooAccount *ya, JsonObject *data)
{
	JsonNode *node;
	JsonObject *object;
	JsonArray *data_array;
	JsonArray *inner_data_array;
	gchar *str;
	gsize len;
	JsonGenerator *generator;
	
	if (ya->websocket == NULL) {
		if (data != NULL) {
			json_object_unref(data);
		}
		//TODO error?
		return;
	}
	
	data_array = json_array_new();
	
	if (data != NULL) {
		inner_data_array = json_array_new();
		json_array_add_object_element(inner_data_array, data);
		json_array_add_array_element(data_array, inner_data_array);
	}
	
	object = json_object_new();
	json_object_set_int_member(object, "seq", ya->seq);
	json_object_set_int_member(object, "ack", ya->ack);
	json_object_set_array_member(object, "data", data_array);
	
	node = json_node_new(JSON_NODE_OBJECT);
	json_node_set_object(node, object);
	
	generator = json_generator_new();
	json_generator_set_root(generator, node);
	str = json_generator_to_data(generator, &len);
	g_object_unref(generator);
	
	yahoo_socket_write_data(ya, (guchar *)str, len, 0);
	
	g_free(str);
	json_node_free(node);
	json_object_unref(object);
	
	if (data != NULL) {
		ya->seq += 1;
	}
}

static void
yahoo_socket_got_data(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
	YahooAccount *ya = userdata;
	guchar length_code;
	int read_len = 0;
	gboolean done_some_reads = FALSE;
	
	
	if (G_UNLIKELY(!ya->websocket_header_received)) {
		// HTTP/1.1 101 Switching Protocols
		// Server: nginx
		// Date: Sun, 19 Jul 2015 23:44:27 GMT
		// Connection: upgrade
		// Upgrade: websocket
		// Sec-WebSocket-Accept: pUDN5Js0uDN5KhEWoPJGLyTqwME=
		// Expires: 0
		// Cache-Control: no-cache
		gint nlbr_count = 0;
		gchar nextchar;
		
		while(nlbr_count < 4 && purple_ssl_read(conn, &nextchar, 1)) {
			if (nextchar == '\r' || nextchar == '\n') {
				nlbr_count++;
			} else {
				nlbr_count = 0;
			}
		}
		
		ya->websocket_header_received = TRUE;
		done_some_reads = TRUE;
	}
	
	while(ya->frame || (read_len = purple_ssl_read(conn, &ya->packet_code, 1)) == 1) {
		if (!ya->frame) {
			if (ya->packet_code != 129) {
				if (ya->packet_code == 136) {
					purple_debug_error("yahoo", "websocket closed\n");
					
					// Try reconnect
					yahoo_start_socket(ya);
					
					return;
				} else if (ya->packet_code == 137) {
					// Ping
					gint ping_frame_len;
					length_code = 0;
					purple_ssl_read(conn, &length_code, 1);
					if (length_code <= 125) {
						ping_frame_len = length_code;
					} else if (length_code == 126) {
						guchar len_buf[2];
						purple_ssl_read(conn, len_buf, 2);
						ping_frame_len = (len_buf[0] << 8) + len_buf[1];
					} else if (length_code == 127) {
						purple_ssl_read(conn, &ping_frame_len, 8);
						ping_frame_len = GUINT64_FROM_BE(ping_frame_len);
					}
					if (ping_frame_len) {
						guchar *pong_data = g_new0(guchar, ping_frame_len);
						purple_ssl_read(conn, pong_data, ping_frame_len);

						yahoo_socket_write_data(ya, pong_data, ping_frame_len, 138);
						g_free(pong_data);
					} else {
						yahoo_socket_write_data(ya, (guchar *) "", 0, 138);
					}
					return;
				} else if (ya->packet_code == 138) {
					// Pong
					//who cares
					return;
				} else if (ya->packet_code == '{') {
					// They've provided us a JSON response!
					purple_debug_error("yahoo", "json response given to websocket channel\n");
					
					// Try reconnect
					yahoo_start_socket(ya);
					
					return;
				}
				purple_debug_error("yahoo", "unknown websocket error %d\n", ya->packet_code);
				return;
			}
			
			length_code = 0;
			purple_ssl_read(conn, &length_code, 1);
			if (length_code <= 125) {
				ya->frame_len = length_code;
			} else if (length_code == 126) {
				guchar len_buf[2];
				purple_ssl_read(conn, len_buf, 2);
				ya->frame_len = (len_buf[0] << 8) + len_buf[1];
			} else if (length_code == 127) {
				purple_ssl_read(conn, &ya->frame_len, 8);
				ya->frame_len = GUINT64_FROM_BE(ya->frame_len);
			}
			purple_debug_info("yahoo", "frame_len: %" G_GUINT64_FORMAT "\n", ya->frame_len);
			
			ya->frame = g_new0(gchar, ya->frame_len + 1);
			ya->frame_len_progress = 0;
		}
		
		do {
			read_len = purple_ssl_read(conn, ya->frame + ya->frame_len_progress, ya->frame_len - ya->frame_len_progress);
			if (read_len > 0) {
				ya->frame_len_progress += read_len;
			}
		} while (read_len > 0 && ya->frame_len_progress < ya->frame_len);
		done_some_reads = TRUE;
		
		if (ya->frame_len_progress == ya->frame_len) {
			gboolean success = yahoo_process_frame(ya, ya->frame);
			g_free(ya->frame); ya->frame = NULL;
			ya->packet_code = 0;
			ya->frame_len = 0;
			
			if (G_UNLIKELY(ya->websocket == NULL || success == FALSE)) {
				return;
			}
		} else {
			return;
		}
	}

	if (done_some_reads == FALSE && read_len <= 0) {
		if (read_len < 0 && errno == EAGAIN) {
			return;
		}

		purple_debug_error("yahoo", "got errno %d, read_len %d from websocket thread\n", errno, read_len);

		if (ya->frames_since_reconnect < 2) {
			purple_connection_error(ya->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, "Lost connection to server");
		} else {
			// Try reconnect
			yahoo_start_socket(ya);
		}
	}
}

static void
yahoo_socket_connected(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
	YahooAccount *ya = userdata;
	gchar *websocket_header;
	gchar *cookies;
	const gchar *websocket_key = "15XF+ptKDhYVERXoGcdHTA=="; //TODO don't be lazy
	GString *url = g_string_new("/prod/websocket?");
	
	purple_ssl_input_add(ya->websocket, yahoo_socket_got_data, ya);
	
	g_string_append_printf(url, "session-token=%s&", ya->session_token);
	g_string_append_printf(url, "channel=%s&", ya->channel);
	g_string_append_printf(url, "ack=%" G_GINT64_FORMAT "&", ya->ack);
	g_string_append(url, "v=1&");
	
	cookies = yahoo_cookies_to_string(ya);
	
	websocket_header = g_strdup_printf("GET %s HTTP/1.1\r\n"
							"Host: prod.iris.yahoo.com\r\n"
							"Connection: Upgrade\r\n"
							"Pragma: no-cache\r\n"
							"Cache-Control: no-cache\r\n"
							"Upgrade: websocket\r\n"
							"Sec-WebSocket-Version: 13\r\n"
							"Sec-WebSocket-Key: %s\r\n"
							"User-Agent: " YAHOO_USERAGENT "\r\n"
							"Cookie: %s\r\n"
							//"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
							"\r\n", url->str, websocket_key, cookies);
	
	purple_ssl_write(ya->websocket, websocket_header, strlen(websocket_header));
	
	g_free(websocket_header);
	g_string_free(url, TRUE);
	g_free(cookies);
}

static void
yahoo_socket_failed(PurpleSslConnection *conn, PurpleSslErrorType errortype, gpointer userdata)
{
	YahooAccount *ya = userdata;
	
	ya->websocket = NULL;
	ya->websocket_header_received = FALSE;
	
	yahoo_restart_channel(ya);
}

static void
yahoo_start_socket(YahooAccount *ya)
{
	//Reset all the old stuff
	if (ya->websocket != NULL) {
		purple_ssl_close(ya->websocket);
	}
	
	ya->websocket = NULL;
	ya->websocket_header_received = FALSE;
	g_free(ya->frame); ya->frame = NULL;
	ya->packet_code = 0;
	ya->frame_len = 0;
	ya->frames_since_reconnect = 0;

	ya->websocket = purple_ssl_connect(ya->account, "prod.iris.yahoo.com", 443, yahoo_socket_connected, yahoo_socket_failed, ya);
}




void
yahoo_block_user(PurpleConnection *pc, const char *who)
{
	YahooAccount *ya = purple_connection_get_protocol_data(pc);
	JsonObject *data = json_object_new();
	
	json_object_set_string_member(data, "msg", "SetUserBlocked");
	json_object_set_string_member(data, "userId", who);
	json_object_set_int_member(data, "opId", ya->opid++);
	json_object_set_boolean_member(data, "blocked", TRUE);
	
	yahoo_socket_write_json(ya, data);
}

void
yahoo_unblock_user(PurpleConnection *pc, const char *who)
{
	YahooAccount *ya = purple_connection_get_protocol_data(pc);
	JsonObject *data = json_object_new();
	
	json_object_set_string_member(data, "msg", "SetUserBlocked");
	json_object_set_string_member(data, "userId", who);
	json_object_set_int_member(data, "opId", ya->opid++);
	json_object_set_boolean_member(data, "blocked", FALSE);
	
	yahoo_socket_write_json(ya, data);
}

static void
yahoo_chat_leave_by_group_id(PurpleConnection *pc, const gchar *groupId)
{
	YahooAccount *ya;
	JsonObject *data = json_object_new();
	
	ya = purple_connection_get_protocol_data(pc);
	
	json_object_set_string_member(data, "msg", "LeaveGroup");
	json_object_set_string_member(data, "groupId", groupId);
	json_object_set_int_member(data, "opId", ya->opid++);
	
	yahoo_socket_write_json(ya, data);
}

static void
yahoo_chat_leave(PurpleConnection *pc, int id)
{
	const gchar *groupId = NULL;
	PurpleChatConversation *chatconv;
	
	chatconv = purple_conversations_find_chat(pc, id);
	groupId = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "groupId");
	if (groupId == NULL) {
		groupId = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
	}
	
	yahoo_chat_leave_by_group_id(pc, groupId);
}

static void
yahoo_chat_invite(PurpleConnection *pc, int id, const char *message, const char *who)
{
	YahooAccount *ya;
	const gchar *groupId;
	PurpleChatConversation *chatconv;
	JsonObject *data = json_object_new();
	
	ya = purple_connection_get_protocol_data(pc);
	chatconv = purple_conversations_find_chat(pc, id);
	groupId = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "groupId");
	if (groupId == NULL) {
		groupId = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
	}
	
	json_object_set_string_member(data, "msg", "InviteGroupMember");
	json_object_set_string_member(data, "groupId", groupId);
	json_object_set_int_member(data, "opId", ya->opid++);
	json_object_set_string_member(data, "userId", who);
	json_object_set_string_member(data, "memberId", "00000000000FFFFF");
	json_object_set_string_member(data, "firstName", "");
	json_object_set_string_member(data, "lastName", "");
	
	yahoo_socket_write_json(ya, data);
}

static GList *
yahoo_chat_info(PurpleConnection *pc)
{
	GList *m = NULL;
	PurpleProtocolChatEntry *pce;

	pce = g_new0(PurpleProtocolChatEntry, 1);
	pce->label = _("Group ID");
	pce->identifier = "groupId";
	pce->required = TRUE;
	m = g_list_append(m, pce);
	
	return m;
}

static GHashTable *
yahoo_chat_info_defaults(PurpleConnection *pc, const char *chatname)
{
	GHashTable *defaults = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, g_free);
	
	if (chatname != NULL)
	{
		g_hash_table_insert(defaults, "groupId", g_strdup(chatname));
	}
	
	return defaults;
}

static gchar *
yahoo_get_chat_name(GHashTable *data)
{
	gchar *temp;

	if (data == NULL)
		return NULL;
	
	temp = g_hash_table_lookup(data, "groupId");

	if (temp == NULL)
		return NULL;

	return g_strdup(temp);
}

static void
yahoo_join_chat(PurpleConnection *pc, GHashTable *data)
{
	YahooAccount *ya = purple_connection_get_protocol_data(pc);
	gchar *groupId;
	PurpleChatConversation *chatconv;
	
	groupId = (gchar *)g_hash_table_lookup(data, "groupId");
	if (groupId == NULL)
	{
		return;
	}
	
	chatconv = purple_conversations_find_chat_with_account(groupId, ya->account);
	if (chatconv != NULL && !purple_chat_conversation_has_left(chatconv)) {
		purple_conversation_present(PURPLE_CONVERSATION(chatconv));
		return;
	}
	
	chatconv = purple_serv_got_joined_chat(pc, g_str_hash(groupId), groupId);
	purple_conversation_set_data(PURPLE_CONVERSATION(chatconv), "groupId", g_strdup(groupId));
	
	purple_conversation_present(PURPLE_CONVERSATION(chatconv));
}

static gint
yahoo_conversation_send_message(YahooAccount *ya, const gchar *groupId, const gchar *message)
{
	JsonObject *data = json_object_new();
	gchar *stripped;
	gchar *itemId;
	
	json_object_set_string_member(data, "msg", "InsertItem");
	json_object_set_string_member(data, "groupId", groupId);
	json_object_set_int_member(data, "opId", ya->opid++);
	
	stripped = g_strstrip(purple_markup_strip_html(message));
	json_object_set_string_member(data, "message", stripped);
	g_free(stripped);
	
	itemId = g_strdup_printf("%012XFFFF", g_random_int());
	g_hash_table_replace(ya->sent_message_ids, itemId, NULL);
	json_object_set_string_member(data, "itemId", itemId);
	
	json_object_set_int_member(data, "expectedMediaCount", 0);
	
	yahoo_socket_write_json(ya, data);
	
	return 1;
}

static gint
yahoo_chat_send(PurpleConnection *pc, gint id, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleMessage *msg)
{
	const gchar *message = purple_message_get_contents(msg);
#else
const gchar *message, PurpleMessageFlags flags)
{
#endif
	
	YahooAccount *ya;
	const gchar *groupId;
	PurpleChatConversation *chatconv;
	gint ret;
	
	ya = purple_connection_get_protocol_data(pc);
	chatconv = purple_conversations_find_chat(pc, id);
	groupId = purple_conversation_get_data(PURPLE_CONVERSATION(chatconv), "groupId");
	if (!groupId) {
		// Fix for a race condition around the chat data and serv_got_joined_chat()
		groupId = purple_conversation_get_name(PURPLE_CONVERSATION(chatconv));
		g_return_val_if_fail(groupId, -1);
	}
	g_return_val_if_fail(g_hash_table_contains(ya->group_chats, groupId), -1);
	
	ret = yahoo_conversation_send_message(ya, groupId, message);
	if (ret > 0) {
		purple_serv_got_chat_in(pc, g_str_hash(groupId), ya->self_user, PURPLE_MESSAGE_SEND, message, time(NULL));
	}
	return ret;
}

static int
yahoo_send_im(PurpleConnection *pc, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleMessage *msg)
{
	const gchar *who = purple_message_get_recipient(msg);
	const gchar *message = purple_message_get_contents(msg);
#else
const gchar *who, const gchar *message, PurpleMessageFlags flags)
{
#endif

	YahooAccount *ya = purple_connection_get_protocol_data(pc);
	gchar *group_id = g_hash_table_lookup(ya->one_to_ones_rev, who);
	
	return yahoo_conversation_send_message(ya, group_id, message);
}

// static const gchar *
// yahoo_normalise_buddy(const PurpleAccount *account, const gchar *str)
// {
	// static gchar buf[26 + 1];
	// gchar *tmp1, *tmp2;

	// g_return_val_if_fail(str != NULL, NULL);

	// tmp1 = g_ascii_strup(str, -1);
	// use g_ascii_isalnum on each char
	// g_snprintf(buf, sizeof(buf), "%26s", tmp1 ? tmp1 : "");
	// g_free(tmp1);

	// return buf;
// }

static gchar *
yahoo_make_base32guid(guint64 id)
{
	guchar guid[16];
	guint64 be_id = GUINT64_TO_BE(id);
	gchar *base32guid;
	
	memset(guid, 0, 16);
	memmove(guid + 8, &be_id, 8);
	
	base32guid = purple_base32_encode(guid, 16);
	base32guid[26] = 0; // Strip off trailing padding
	
	return base32guid;
}

static void
yahoo_add_buddy(PurpleConnection *pc, PurpleBuddy *buddy, PurpleGroup *group
#if PURPLE_VERSION_CHECK(3, 0, 0)
, const char *message
#endif
)
{
	YahooAccount *ya = purple_connection_get_protocol_data(pc);
	JsonObject *data;
	const gchar *buddy_name = purple_buddy_get_name(buddy);
	gchar *userId;
	gchar *groupId;
	gchar *memberId;
	gchar *otherMemberId;
	gboolean is_email_address = (strchr(buddy_name, '@') != NULL ? TRUE : FALSE);
	
	// If this isn't a 'real' user id, then freak out a little
	if (is_email_address || strlen(buddy_name) != 26) {
		//TODO should probably check that its not a 26 character long username
		gchar *serviceIdentifier = g_strdup_printf("%s:%s", (is_email_address == TRUE ? "smtp" : "ymessenger"), buddy_name);
		
		// Needs to be a valid Base32 GUID
		userId = yahoo_make_base32guid(ya->opid * 2);
		data = json_object_new();
		
		json_object_set_string_member(data, "msg", "ResolveUser");
		json_object_set_int_member(data, "opId", ya->opid++);
		json_object_set_string_member(data, "userId", userId);
		json_object_set_string_member(data, "serviceIdentifier", serviceIdentifier);
		
		yahoo_socket_write_json(ya, data);
		
		g_free(serviceIdentifier);
		
		purple_buddy_set_name(buddy, userId);
	} else {
		userId = g_strdup(buddy_name);
	}
	
	// Needs to be a valid Base32 GUID
	groupId = yahoo_make_base32guid(ya->opid * 2 + 1);
	memberId = g_strdup_printf("%012" G_GUINT64_FORMAT "FFFF", ya->opid * 2);
	otherMemberId = g_strdup_printf("%012" G_GUINT64_FORMAT "FFFF", ya->opid * 2 + 1);
	data = json_object_new();
	
	json_object_set_string_member(data, "msg", "ResolveGroup");
	json_object_set_int_member(data, "opId", ya->opid++);
	json_object_set_string_member(data, "groupId", groupId);
	json_object_set_string_member(data, "memberId", memberId);
	json_object_set_string_member(data, "otherUserId", userId);
	json_object_set_string_member(data, "otherMemberId", otherMemberId);
	
	yahoo_socket_write_json(ya, data);
	
	data = json_object_new();
	json_object_set_string_member(data, "msg", "EnsureUser");
	json_object_set_int_member(data, "opId", ya->opid++);
	json_object_set_string_member(data, "userId", userId);
	
	yahoo_socket_write_json(ya, data);
	
	g_hash_table_replace(ya->one_to_ones, g_strdup(groupId), g_strdup(userId));
	g_hash_table_replace(ya->one_to_ones_rev, g_strdup(userId), g_strdup(groupId));
	
	purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "groupId", groupId);
	
	g_free(userId);
	g_free(groupId);
	g_free(memberId);
	g_free(otherMemberId);
}


static const char *
yahoo_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "yahoo";
}

static GList *
yahoo_status_types(PurpleAccount *account)
{
	GList *types = NULL;
	PurpleStatusType *status;

	status = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, "online", "Online", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, NULL, "Offline", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	
	return types;
}

static void
yahoo_blist_node_removed(PurpleBlistNode *node)
{
	PurpleChat *chat = NULL;
	PurpleAccount *account = NULL;
	PurpleConnection *pc;
	const gchar *groupId;
	GHashTable *components;
	
	if (PURPLE_IS_CHAT(node)) {
		chat = PURPLE_CHAT(node);
		account = purple_chat_get_account(chat);
	}
	
	if (account == NULL) {
		return;
	}
	
	if (g_strcmp0(purple_account_get_protocol_id(account), YAHOO_PLUGIN_ID)) {
		return;
	}
	
	pc = purple_account_get_connection(account);
	if (pc == NULL) {
		return;
	}
	
	if (chat != NULL) {
		components = purple_chat_get_components(chat);
		groupId = g_hash_table_lookup(components, "groupId");
		if (groupId == NULL) {
			groupId = purple_chat_get_name_only(chat);
		}
		
		yahoo_chat_leave_by_group_id(pc, groupId);
	}
}

static PurpleCmdRet
yahoo_cmd_leave(PurpleConversation *conv, const gchar *cmd, gchar **args, gchar **error, void *data)
{
	PurpleConnection *pc = NULL;
	int id = -1;
	
	pc = purple_conversation_get_connection(conv);
	id = purple_chat_conversation_get_id(PURPLE_CHAT_CONVERSATION(conv));
	
	if (pc == NULL || id == -1)
		return PURPLE_CMD_RET_FAILED;
	
	yahoo_chat_leave(pc, id);
	
	return PURPLE_CMD_RET_OK;
}

static gboolean
plugin_load(PurplePlugin *plugin, GError **error)
{
	purple_cmd_register("leave", "", PURPLE_CMD_P_PLUGIN, PURPLE_CMD_FLAG_CHAT |
						PURPLE_CMD_FLAG_PROTOCOL_ONLY | PURPLE_CMD_FLAG_ALLOW_WRONG_ARGS,
						YAHOO_PLUGIN_ID, yahoo_cmd_leave,
						_("leave:  Leave the group chat"), NULL);
	
	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin, GError **error)
{
	purple_signals_disconnect_by_handle(plugin);
	
	return TRUE;
}

// Purple2 Plugin Load Functions
#if !PURPLE_VERSION_CHECK(3, 0, 0)
static gboolean
libpurple2_plugin_load(PurplePlugin *plugin)
{
	return plugin_load(plugin, NULL);
}

static gboolean
libpurple2_plugin_unload(PurplePlugin *plugin)
{
	return plugin_unload(plugin, NULL);
}

static void
plugin_init(PurplePlugin *plugin)
{
	// PurpleAccountOption *option;
	// PurplePluginInfo *info = plugin->info;
	// PurplePluginProtocolInfo *prpl_info = info->extra_info;
	//purple_signal_connect(purple_get_core(), "uri-handler", plugin, PURPLE_CALLBACK(mightytext_uri_handler), NULL);
	
	// option = purple_account_option_bool_new("Show calls", "show_calls", TRUE);
	// prpl_info->protocol_options = g_list_append(prpl_info->protocol_options, option);
	
	// option = purple_account_option_bool_new("Only show 'mobile' contacts", "mobile_contacts_only", FALSE);
	// prpl_info->protocol_options = g_list_append(prpl_info->protocol_options, option);
	
	PurplePluginInfo *info;
	PurplePluginProtocolInfo *prpl_info = g_new0(PurplePluginProtocolInfo, 1);
	
	info = plugin->info;
	if (info == NULL) {
		plugin->info = info = g_new0(PurplePluginInfo, 1);
	}
	info->extra_info = prpl_info;
	#if PURPLE_MINOR_VERSION >= 5
		prpl_info->struct_size = sizeof(PurplePluginProtocolInfo);
	#endif
	#if PURPLE_MINOR_VERSION >= 8
		//prpl_info->add_buddy_with_invite = yahoo_add_buddy_with_invite;
	#endif
	
	prpl_info->options = OPT_PROTO_SLASH_COMMANDS_NATIVE;
	prpl_info->icon_spec.format = "png,gif,jpeg";
	prpl_info->icon_spec.min_width = 0;
	prpl_info->icon_spec.min_height = 0;
	prpl_info->icon_spec.max_width = 96;
	prpl_info->icon_spec.max_height = 96;
	prpl_info->icon_spec.max_filesize = 0;
	prpl_info->icon_spec.scale_rules = PURPLE_ICON_SCALE_DISPLAY;
	
	prpl_info->list_icon = yahoo_list_icon;
	prpl_info->status_types = yahoo_status_types;
	prpl_info->chat_info = yahoo_chat_info;
	prpl_info->chat_info_defaults = yahoo_chat_info_defaults;
	prpl_info->login = yahoo_login;
	prpl_info->close = yahoo_close;
	prpl_info->send_im = yahoo_send_im;
	prpl_info->add_deny = yahoo_block_user;
	prpl_info->rem_deny = yahoo_unblock_user;
	prpl_info->join_chat = yahoo_join_chat;
	prpl_info->get_chat_name = yahoo_get_chat_name;
	prpl_info->chat_invite = yahoo_chat_invite;
	prpl_info->chat_send = yahoo_chat_send;
	prpl_info->add_buddy = yahoo_add_buddy;
	
}

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
/*	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
*/
	2, 1,
	PURPLE_PLUGIN_PROTOCOL, /* type */
	NULL, /* ui_requirement */
	0, /* flags */
	NULL, /* dependencies */
	PURPLE_PRIORITY_DEFAULT, /* priority */
	YAHOO_PLUGIN_ID, /* id */
	"Yahoo (2016)", /* name */
	YAHOO_PLUGIN_VERSION, /* version */
	"", /* summary */
	"", /* description */
	"Eion Robb <eion@robbmob.com>", /* author */
	YAHOO_PLUGIN_WEBSITE, /* homepage */
	libpurple2_plugin_load, /* load */
	libpurple2_plugin_unload, /* unload */
	NULL, /* destroy */
	NULL, /* ui_info */
	NULL, /* extra_info */
	NULL, /* prefs_info */
	NULL/*plugin_actions*/, /* actions */
	NULL, /* padding */
	NULL,
	NULL,
	NULL
};

PURPLE_INIT_PLUGIN(yahoo-plusplus, plugin_init, info);

#else
//Purple 3 plugin load functions


G_MODULE_EXPORT GType yahoo_protocol_get_type(void);
#define YAHOO_TYPE_PROTOCOL			(yahoo_protocol_get_type())
#define YAHOO_PROTOCOL(obj)			(G_TYPE_CHECK_INSTANCE_CAST((obj), YAHOO_TYPE_PROTOCOL, YahooProtocol))
#define YAHOO_PROTOCOL_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST((klass), YAHOO_TYPE_PROTOCOL, YahooProtocolClass))
#define YAHOO_IS_PROTOCOL(obj)		(G_TYPE_CHECK_INSTANCE_TYPE((obj), YAHOO_TYPE_PROTOCOL))
#define YAHOO_IS_PROTOCOL_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), YAHOO_TYPE_PROTOCOL))
#define YAHOO_PROTOCOL_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS((obj), YAHOO_TYPE_PROTOCOL, YahooProtocolClass))

typedef struct _YahooProtocol
{
	PurpleProtocol parent;
} YahooProtocol;

typedef struct _YahooProtocolClass
{
	PurpleProtocolClass parent_class;
} YahooProtocolClass;

static void
yahoo_protocol_init(PurpleProtocol *prpl_info)
{
	PurpleProtocol *info = prpl_info;

	info->id = YAHOO_PLUGIN_ID;
	info->name = "Yahoo (2016)";
}

static void
yahoo_protocol_class_init(PurpleProtocolClass *prpl_info)
{
	prpl_info->login = yahoo_login;
	prpl_info->close = yahoo_close;
	prpl_info->status_types = yahoo_status_types;
	prpl_info->list_icon = yahoo_list_icon;
}

static void
yahoo_protocol_privacy_iface_init(PurpleProtocolPrivacyIface *prpl_info)
{
	prpl_info->add_deny = yahoo_block_user;
	prpl_info->rem_deny = yahoo_unblock_user;
}

static void 
yahoo_protocol_im_iface_init(PurpleProtocolIMIface *prpl_info)
{
	prpl_info->send = yahoo_send_im;
}

static void 
yahoo_protocol_chat_iface_init(PurpleProtocolChatIface *prpl_info)
{
	prpl_info->send = yahoo_chat_send;
	prpl_info->info = yahoo_chat_info;
	prpl_info->info_defaults = yahoo_chat_info_defaults;
	prpl_info->join = yahoo_join_chat;
	prpl_info->get_name = yahoo_get_chat_name;
	prpl_info->invite = yahoo_chat_invite;
}

static void 
yahoo_protocol_server_iface_init(PurpleProtocolServerIface *prpl_info)
{
	prpl_info->add_buddy = yahoo_add_buddy;
}

static PurpleProtocol *yahoo_protocol;

PURPLE_DEFINE_TYPE_EXTENDED(
	YahooProtocol, yahoo_protocol, PURPLE_TYPE_PROTOCOL, 0,

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_IM_IFACE,
	                                  yahoo_protocol_im_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CHAT_IFACE,
	                                  yahoo_protocol_chat_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_PRIVACY_IFACE,
	                                  yahoo_protocol_privacy_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_SERVER_IFACE,
	                                  yahoo_protocol_server_iface_init)

);

static gboolean
libpurple3_plugin_load(PurplePlugin *plugin, GError **error)
{
	yahoo_protocol_register_type(plugin);
	yahoo_protocol = purple_protocols_add(YAHOO_TYPE_PROTOCOL, error);
	if (!yahoo_protocol)
		return FALSE;

	return plugin_load(plugin, error);
}

static gboolean
libpurple3_plugin_unload(PurplePlugin *plugin, GError **error)
{
	if (!plugin_unload(plugin, error))
		return FALSE;

	if (!purple_protocols_remove(yahoo_protocol, error))
		return FALSE;

	return TRUE;
}

static PurplePluginInfo *
plugin_query(GError **error)
{
	return purple_plugin_info_new(
		"id",          YAHOO_PLUGIN_ID,
		"name",        "FunYahoo++",
		"version",     YAHOO_PLUGIN_VERSION,
		"category",    N_("Protocol"),
		"summary",     N_("Yahoo Protocol Plugins."),
		"description", N_("Adds Yahoo protocol support to libpurple."),
		"website",     YAHOO_PLUGIN_WEBSITE,
		"abi-version", PURPLE_ABI_VERSION,
		"flags",       PURPLE_PLUGIN_INFO_FLAGS_INTERNAL |
		               PURPLE_PLUGIN_INFO_FLAGS_AUTO_LOAD,
		NULL
	);
}

PURPLE_PLUGIN_INIT(funyahooplusplus, plugin_query,
		libpurple3_plugin_load, libpurple3_plugin_unload);

#endif
