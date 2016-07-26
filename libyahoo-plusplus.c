#ifndef PURPLE_PLUGINS
#	define PURPLE_PLUGINS
#endif

// Glib
#include <glib.h>

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



#include <accountopt.h>
#include <core.h>
#include <debug.h>
#include <prpl.h>
#include <request.h>
#include <version.h>


#ifndef _
#	define _(a) (a)
#endif

#define YAHOO_USERAGENT "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"

#define YAHOO_BUFFER_DEFAULT_SIZE 40960

typedef struct {
	PurpleAccount *account;
	PurpleConnection *pc;
	
	GHashTable *cookie_table;
	gchar *session_token;
	gchar *channel;
	
	PurpleSslConnection *websocket;
	gboolean websocket_header_received;
	guchar packet_code;
	gchar *frame;
	guint64 frame_len;
	guint64 frame_len_progress;
	
	gint64 seq;
	gint64 ack;
	
} YahooAccount;

typedef void (*YahooProxyCallbackFunc)(YahooAccount *ya, JsonNode *node, gpointer user_data);

typedef struct {
	YahooAccount *ya;
	YahooProxyCallbackFunc callback;
	gpointer user_data;
} YahooProxyConnection;





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
yahoo_response_callback(PurpleUtilFetchUrlData *url_data, gpointer user_data, const gchar *url_text, gsize len, const gchar *error_message)
{
	const gchar *body;
	gsize body_len;
	YahooProxyConnection *conn = user_data;
	JsonParser *parser = json_parser_new();
	
	yahoo_update_cookies(conn->ya, url_text);
	
	body = g_strstr_len(url_text, len, "\r\n\r\n");
	body_len = len - (body - url_text);
	
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
	GString *headers;
	gchar *host = NULL, *path = NULL, *user = NULL, *password = NULL;
	int port;
	YahooProxyConnection *conn;
	gchar *cookies;
	
	account = ya->account;
	if (purple_account_is_disconnected(account)) return;
	
	conn = g_new0(YahooProxyConnection, 1);
	conn->ya = ya;
	conn->callback = callback;
	conn->user_data = user_data;

	purple_url_parse(url, &host, &port, &path, &user, &password);
	purple_debug_info("yahoo", "Fetching url %s\n", url);
	
	headers = g_string_new(NULL);
	
	//Use the full 'url' until libpurple can handle path's longer than 256 chars
	g_string_append_printf(headers, "%s /%s HTTP/1.0\r\n", (postdata ? "POST" : "GET"), path);
	//g_string_append_printf(headers, "%s %s HTTP/1.0\r\n", (postdata ? "POST" : "GET"), url);
	g_string_append_printf(headers, "Connection: close\r\n");
	g_string_append_printf(headers, "Host: %s\r\n", host);
	g_string_append_printf(headers, "Accept: */*\r\n");
	g_string_append_printf(headers, "User-Agent: " YAHOO_USERAGENT "\r\n");
	
	cookies = yahoo_cookies_to_string(ya);
	g_string_append_printf(headers, "Cookie: %s\r\n", cookies);
	g_free(cookies);

	if(postdata) {
		purple_debug_info("yahoo", "With postdata %s\n", postdata);
		
		if (postdata[0] == '{') {
			g_string_append(headers, "Content-Type: application/json\r\n");
		} else {
			g_string_append(headers, "Content-Type: application/x-www-form-urlencoded\r\n");
		}
		g_string_append_printf(headers, "Content-Length: %d\r\n", strlen(postdata));
		g_string_append(headers, "\r\n");

		g_string_append(headers, postdata);
	} else {
		g_string_append(headers, "\r\n");
	}

	g_free(host);
	g_free(path);
	g_free(user);
	g_free(password);

	purple_util_fetch_url_request_len_with_account(ya->account, url, FALSE, YAHOO_USERAGENT, TRUE, headers->str, TRUE, 6553500, yahoo_response_callback, conn);
	
	g_string_free(headers, TRUE);
}

static void yahoo_socket_write_json(YahooAccount *ya, JsonObject *data);

static void
yahoo_process_msg(JsonArray *array, guint index_, JsonNode *element_node, gpointer user_data)
{
	JsonObject *response = NULL;
	YahooAccount *ya = user_data;
	JsonObject *obj = json_node_get_object(element_node);
	
	if (purple_strequal(json_object_get_string_member(obj, "msg"), "NewEntity")) {
		if (purple_strequal(json_object_get_string_member(obj, "type"), "post")) {
			const gchar *message = json_object_get_string_member(obj, "message");
			const gchar *user = json_array_get_string_element(json_object_get_array_member(obj, "user"), 1);
			gint64 timestamp = json_object_get_int_member(obj, "createdTime") / 1000;
			
			serv_got_im(ya->pc, user, message, PURPLE_MESSAGE_RECV, timestamp);
		}
	} else if (purple_strequal(json_object_get_string_member(obj, "msg"), "SyncBatch")) {
		response = json_object_new();
		json_object_set_string_member(response, "msg", "SyncAck");
		json_object_set_string_member(response, "pushId", json_object_get_string_member(obj, "pushId"));
	}
	
	//yahoo_socket_write_json(ya, response);
}

static void yahoo_start_socket(YahooAccount *ya);

static void
yahoo_rpc_callback(YahooAccount *ya, JsonNode *node, gpointer user_data)
{
	JsonObject *obj = json_node_get_object(node);
	
	if (purple_strequal(json_object_get_string_member(obj, "msg"), "SessionOpened")) {
		//connected
		ya->session_token = g_strdup(json_object_get_string_member(obj, "sessionToken"));
		ya->channel = g_strdup(json_object_get_string_member(obj, "channelId"));
		
		purple_connection_set_state(ya->pc, PURPLE_CONNECTED);
		
		//process batch
		json_array_foreach_element(json_object_get_array_member(obj, "batch"), yahoo_process_msg, ya);
		
		yahoo_start_socket(ya);
	} else {
		purple_connection_error(ya->pc, json_object_get_string_member(obj, "reason"));
	}
}
	
static void
yahoo_auth_callback(YahooAccount *ya, JsonNode *node, gpointer user_data)
{
	JsonObject *obj = json_node_get_object(node);
	
	if (purple_strequal(json_object_get_string_member(obj, "status"), "error")) {
		if (purple_strequal(json_object_get_string_member(obj, "code"), "1212")) {
			purple_connection_error_reason(ya->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,  json_object_get_string_member(obj, "message"));
		} else {
			purple_connection_error(ya->pc, json_object_get_string_member(obj, "message"));
		}
	} else {
		const gchar *rpcdata = "{\"msg\":\"OpenSession\",\"device\":{\"kind\":\"mobile\"},\"auth\":{\"provider\":\"signin\"},\"version\":{\"platform\":\"web\",\"app\":\"iris/dogfood\",\"appVersion\":897},\"batch\":[]}";
		yahoo_fetch_url(ya, "https://prod.iris.yahoo.com/prod/rpc?wait=1&v=1", rpcdata, yahoo_rpc_callback, NULL);
	}
}

static void
yahoo_preauth_callback(PurpleUtilFetchUrlData *url_data, gpointer user_data, const gchar *url_text, gsize len, const gchar *error_message)
{
	YahooAccount *ya = user_data;
	GString *postdata = g_string_new("");
	gchar *crumb = yahoo_string_get_chunk(url_text, len, "<input name=\"_crumb\" type=\"hidden\" value=\"", "\"");
	
	yahoo_update_cookies(ya, url_text);
	if (g_hash_table_lookup(ya->cookie_table, "B") == NULL) {
		purple_connection_error(ya->pc, "Couldn't get login cookies");
		return;
	}
	
	g_string_append_printf(postdata, "username=%s&", purple_url_encode(purple_account_get_username(ya->account)));
	g_string_append_printf(postdata, "passwd=%s&", purple_url_encode(purple_account_get_password(ya->account)));
	g_string_append_printf(postdata, "_crumb=%s&", purple_url_encode(crumb));
	g_string_append(postdata, "countrycode=1&");
	g_string_append(postdata, "signin=&");
	g_string_append(postdata, "otp_channel=&");
	g_string_append(postdata, ".persistent=y&");
	g_string_append(postdata, "_format=json&");
	g_string_append(postdata, "_seqid=1&");
	
	yahoo_fetch_url(ya, "https://login.yahoo.com/?.pd=&.src=messenger&.done=https%3A%2F%2Fmessenger.yahoo.com%2F", postdata->str, yahoo_auth_callback, NULL);
	
	g_free(crumb);
	g_string_free(postdata, TRUE);
}


void
yahoo_login(PurpleAccount *account)
{
	YahooAccount *ya;
	PurpleConnection *pc = purple_account_get_connection(account);
	GString *preauth_url = g_string_new("https://login.yahoo.com/?");
	
	g_string_append_printf(preauth_url, ".done=%s&", purple_url_encode("https://messenger.yahoo.com/"));
	g_string_append_printf(preauth_url, ".src=%s&", purple_url_encode("messenger"));
	g_string_append(preauth_url, ".asdk_embedded=1&");
	
	ya = g_new0(YahooAccount, 1);
	pc->proto_data = ya;
	ya->account = account;
	ya->pc = pc;
	ya->cookie_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	
	purple_util_fetch_url_request_len_with_account(account, preauth_url->str, FALSE, YAHOO_USERAGENT, FALSE, NULL, TRUE, 6553500, yahoo_preauth_callback, ya);
	
	g_string_free(preauth_url, TRUE);
}


static void 
yahoo_close(PurpleConnection *pc)
{
	YahooAccount *ya = pc->proto_data;
	// PurpleAccount *account;
	
	g_return_if_fail(ya != NULL);
	
	// account = purple_connection_get_account(pc);
	if (ya->websocket != NULL) purple_ssl_close(ya->websocket);
	
	g_hash_table_destroy(ya->cookie_table); ya->cookie_table = NULL;
	g_free(ya->frame); ya->frame = NULL;
	g_free(ya->session_token); ya->session_token = NULL;
	g_free(ya->channel); ya->channel = NULL;
	g_free(ya);
}















//static void yahoo_start_polling(YahooAccount *ya);

static void
yahoo_process_frame(YahooAccount *ya, const gchar *frame)
{
	JsonParser *parser = json_parser_new();
	JsonNode *root;
	
	purple_debug_info("yahoo", "got frame data: %s\n", frame);
	
	if (!json_parser_load_from_data(parser, frame, -1, NULL))
	{
		purple_debug_error("yahoo", "Error parsing response: %s\n", frame);
		return;
	}
	
	root = json_parser_get_root(parser);
	
	if (root != NULL) {
		JsonObject *message = json_node_get_object(root);
		guint64 seq = json_object_get_int_member(message, "seq");
		guint64 ack = json_object_get_int_member(message, "ack");
		JsonArray *data = json_object_get_array_member(message, "data");
		
		ya->seq = ack;
		ya->ack = seq;
		json_array_foreach_element(json_array_get_array_element(data, 0), yahoo_process_msg, ya);
		
	}
	
	g_object_unref(parser);
}

static void
yahoo_socket_write_data(YahooAccount *ya, guchar *data, gsize data_len, guchar type)
{
	guchar *full_data;
	guint len_size = 1;
	
	if (data_len > 125) {
		if (data_len <= 0xFFFF) {
			len_size = 5;
		} else {
			len_size = 9;
		}
	}
	full_data = g_new0(guchar, 1 + data_len + len_size);
	
	if (type == 0) {
		type = 129;
	}
	full_data[0] = type;
	
	if (data_len <= 125) {
		full_data[1] = data_len;
	} else if (data_len <= 0xFFFF) {
		full_data[1] = 126;
		full_data[2] = (data_len >> 8) & 0xFF;
		full_data[3] = data_len & 0xFF;
	} else {
		guint64 be_len = GUINT64_TO_BE(data_len);
		full_data[1] = 127;
		memmove(&full_data[2], &be_len, 8);
	}
	
	memmove(&full_data[1 + len_size], data, data_len);
	
	purple_ssl_write(ya->websocket, full_data, 1 + data_len + len_size);
	
	g_free(full_data);
}

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
		//TODO error?
		return;
	}
	
	data_array = json_array_new();
	inner_data_array = json_array_new();
	
	if (data != NULL) {
		json_array_add_object_element(inner_data_array, data);
		json_array_add_array_element(data_array, inner_data_array);
	}
	
	object = json_object_new();
	json_object_set_int_member(object, "seq", ya->seq);
	json_object_set_int_member(object, "ack", ya->ack + 1);
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
					
					purple_ssl_close(conn);
					ya->websocket = NULL;
					ya->websocket_header_received = FALSE;
					
					// revert to polling
					//yahoo_start_polling(ya);
					purple_connection_error(ya->pc, "Websocket closed");
					
					return;
				} else if (ya->packet_code == 137) {
					// Ping
					gint ping_frame_len;
					guchar *pong_data;
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
					//TODO - dont be dumb
					pong_data = g_new0(guchar, ping_frame_len);
					purple_ssl_read(conn, pong_data, ping_frame_len);
					
					yahoo_socket_write_data(ya, pong_data, ping_frame_len, 138);
					g_free(pong_data);
					return;
				} else if (ya->packet_code == 138) {
					// Pong
					//who cares
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
		} while (read_len > 0);
		done_some_reads = TRUE;
		
		if (ya->frame_len_progress == ya->frame_len) {
			yahoo_process_frame(ya, ya->frame);
			g_free(ya->frame); ya->frame = NULL;
			ya->packet_code = 0;
			ya->frame_len = 0;
		} else {
			return;
		}
	}
	
	if ((done_some_reads == FALSE && read_len <= 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
		purple_connection_error_reason(ya->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, "Lost connection to server");
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
	g_string_append(url, "ack=1&");
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
	
	// revert to polling
	//yahoo_start_polling(ya);
}

static void
yahoo_start_socket(YahooAccount *ya)
{
	ya->websocket = purple_ssl_connect(ya->account, "prod.iris.yahoo.com", 443, yahoo_socket_connected, yahoo_socket_failed, ya);
}







static int 
yahoo_send_im(PurpleConnection *pc, const gchar *who, const gchar *message, PurpleMessageFlags flags)
{
	JsonObject *data = json_object_new();
	YahooAccount *ya = pc->proto_data;
	gchar *stripped;
	//gchar *group_id = "O64RNTW2EFHX5FIMJV7FRZQ52M";
	
	json_object_set_string_member(data, "msg", "InsertItem");
	
	stripped = g_strstrip(purple_markup_strip_html(message));
	json_object_set_string_member(data, "message", stripped);
	g_free(stripped);
	
	//TODO
	json_object_set_string_member(data, "groupId", "O64RNTW2EFHX5FIMJV7FRZQ52M");
	//json_object_set_string_member(data, "itemId", "000000000001FFFF");
	json_object_set_int_member(data, "expectedMediaCount", 0);
	//json_object_set_int_member(data, "opId", 1);
	
	
	yahoo_socket_write_json(ya, data);
	
	return 1;
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

	status = purple_status_type_new_full(PURPLE_STATUS_AVAILABLE, NULL, "Online", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, NULL, "Offline", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	
	return types;
}

static gboolean
plugin_load(PurplePlugin *plugin)
{
	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
	return TRUE;
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
}

PurplePluginProtocolInfo prpl_info = {
	/* options */
	//TODO, use OPT_PROTO_IM_IMAGE for sending inline messages
	OPT_PROTO_SLASH_COMMANDS_NATIVE/*|OPT_PROTO_IM_IMAGE*/,

	NULL,                /* user_splits */
	NULL,                /* protocol_options */
	{"png,gif,jpeg", 0, 0, 96, 96, 0, PURPLE_ICON_SCALE_SEND}, /* icon_spec */
	yahoo_list_icon,    /* list_icon */
	NULL,                /* list_emblem */
	NULL,                /* status_text */
	NULL,                /* tooltip_text */
	yahoo_status_types,  /* status_types */
	NULL/*mt_node_menu*/,        /* blist_node_menu */
	NULL,                /* chat_info */
	NULL,                /* chat_info_defaults */
	yahoo_login,         /* login */
	yahoo_close,         /* close */
	yahoo_send_im,       /* send_im */
	NULL,                /* set_info */
	NULL,                /* send_typing */
	NULL,                /* get_info */
	NULL,                /* set_status */
	NULL,                /* set_idle */
	NULL,                /* change_passwd */
	NULL,                /* add_buddy */
	NULL,                /* add_buddies */
	NULL,                /* remove_buddy */
	NULL,                /* remove_buddies */
	NULL,                /* add_permit */
	NULL,                /* add_deny */
	NULL,                /* rem_permit */
	NULL,                /* rem_deny */
	NULL,                /* set_permit_deny */
	NULL,                /* join_chat */
	NULL,                /* reject chat invite */
	NULL,                /* get_chat_name */
	NULL,                /* chat_invite */
	NULL,                /* chat_leave */
	NULL,                /* chat_whisper */
	NULL,                /* chat_send */
	NULL/*mt_keepalive*/,        /* keepalive */
	NULL,                /* register_user */
	NULL,                /* get_cb_info */
	NULL,                /* get_cb_away */
	NULL,                /* alias_buddy */
	NULL,                /* group_buddy */
	NULL,                /* rename_group */
	NULL,                /* buddy_free */
	NULL,                /* convo_closed */
	NULL,                /* normalize */
	NULL,                /* set_buddy_icon */
	NULL,                /* remove_group */
	NULL,                /* get_cb_real_name */
	NULL,                /* set_chat_topic */
	NULL,                /* find_blist_chat */
	NULL,                /* roomlist_get_list */
	NULL,                /* roomlist_cancel */
	NULL,                /* roomlist_expand_category */
	NULL,                /* can_receive_file */
	NULL,                /* send_file */
	NULL,                /* new_xfer */
	NULL,                /* offline_message */
	NULL,                /* whiteboard_prpl_ops */
	NULL,                /* send_raw */
	NULL,                /* roomlist_room_serialize */
	NULL,                /* unregister_user */
	NULL,                /* send_attention */
	NULL,                /* attention_types */
#if PURPLE_MAJOR_VERSION == 2 && PURPLE_MINOR_VERSION == 1
	(gpointer)
#endif
	sizeof(PurplePluginProtocolInfo), /* struct_size */
	NULL/*mt_account_text*/,     /* get_account_text_table */
	NULL,                /* initiate_media */
	NULL,                /* can_do_media */
	NULL,                /* get_moods */
	NULL,                /* set_public_alias */
	NULL                 /* get_public_alias */
#if PURPLE_MAJOR_VERSION == 2 && PURPLE_MINOR_VERSION >= 8
,	NULL,                /* add_buddy_with_invite */
	NULL                 /* add_buddies_with_invite */
#endif
};

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
	"prpl-eionrobb-funyahoo-plusplus", /* id */
	"Yahoo (2016)", /* name */
	"1.0", /* version */
	"", /* summary */
	"", /* description */
	"Eion Robb <eion@robbmob.com>", /* author */
	"", /* homepage */
	plugin_load, /* load */
	plugin_unload, /* unload */
	NULL, /* destroy */
	NULL, /* ui_info */
	&prpl_info, /* extra_info */
	NULL, /* prefs_info */
	NULL/*plugin_actions*/, /* actions */
	NULL, /* padding */
	NULL,
	NULL,
	NULL
};

PURPLE_INIT_PLUGIN(yahoo-plusplus, plugin_init, info);
