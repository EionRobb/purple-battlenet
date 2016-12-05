


#include <glib.h>
#include <purple.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __GNUC__
	#include <unistd.h>
#endif
#include <errno.h>

#include "bnet/rpc.pb-c.h"
#include "bnet/connection_service.pb-c.h"
#include "bnet/authentication_service.pb-c.h"
#include "bnet/challenge_service.pb-c.h"
#include "bnet/presence_service.pb-c.h"
#include "bnet/notification_service.pb-c.h"
#include "bnet/friends_service.pb-c.h"
#include "bnet/channel_service.pb-c.h"
#include "bnet/channel_invitation_service.pb-c.h"

#define BATTLENET_PLUGIN_ID "prpl-eionrobb-battlenet"
#define BATTLENET_PLUGIN_WEBSITE "https://bitbucket.org/EionRobb/purple-battlenet/overview"


#if !PURPLE_VERSION_CHECK(3, 0, 0)

#define purple_blist_find_group                 purple_find_group
#define purple_blist_find_buddy                 purple_find_buddy
                                              
#define purple_connection_error                 purple_connection_error_reason
#define PURPLE_CONNECTION_CONNECTING            PURPLE_CONNECTING
#define PURPLE_CONNECTION_CONNECTED             PURPLE_CONNECTED

#define PurpleIMTypingState	                    PurpleTypingState
#define PURPLE_IM_TYPING                        PURPLE_TYPING

#define purple_protocol_got_user_status		    purple_prpl_got_user_status

#define purple_request_cpar_from_connection(a)  purple_connection_get_account(a), NULL, NULL

#define purple_serv_got_im                      serv_got_im
#define purple_serv_got_typing                  serv_got_typing

#endif

#ifndef _
#	define _(a) (a)
#endif


typedef struct {
	PurpleAccount *account;
	PurpleConnection *pc;
	PurpleSslConnection *socket;
	
	guchar *frame_header;
	gsize frame_header_len;
	gsize frame_header_len_progress;
	guchar *frame_body;
	gsize frame_body_len;
	gsize frame_body_len_progress;
	Bnet__Protocol__Header *last_header;
	
	GHashTable *token_callbacks;
	GHashTable *imported_services;
	GHashTable *exported_services;
	
	GList *services_to_import;
	GList *services_to_export;
	guint32 auth_service_id;
	guint32 presence_service_id;
	guint32 friends_service_id;
	guint32 channel_invitation_service_id;
	guint32 notify_service_id;
	
	guint next_token;
	guint next_object_id;
	Bnet__Protocol__EntityId *account_entity;
	
	GHashTable *entity_id_to_battle_tag;
	GHashTable *battle_tag_to_entity_id;
} BattleNetAccount;

typedef struct {
	guint32 id;
	gchar *name;
	
	GHashTable *methods;
} BattleNetService;

typedef void (*BattleNetCallback)(BattleNetAccount *bna, ProtobufCMessage *body, gpointer user_data);
typedef ProtobufCMessage *(*BattleNetServiceMethod)(BattleNetAccount *bna, ProtobufCMessage *request);

typedef struct {
	BattleNetServiceMethod callback;
	ProtobufCMessageDescriptor *request_descriptor;
} BattleNetServiceWrapper;

typedef struct {
	BattleNetCallback callback;
	ProtobufCMessageDescriptor *response_descriptor;
	gpointer user_data;
} BattleNetCallbackWrapper;


static guint
bn_entity_id_hash(gconstpointer key)
{
	const Bnet__Protocol__EntityId *entity_id = key;
	guint hash = 23;
	
	hash = hash * 37 + g_int64_hash(&entity_id->high);
	hash = hash * 37 + g_int64_hash(&entity_id->low);
	
	return hash;
}

static gboolean
bn_entity_id_equal(gconstpointer a, gconstpointer b) {
	const Bnet__Protocol__EntityId *entity_id_a = a, *entity_id_b = b;
	
	return (entity_id_a->high == entity_id_b->high && entity_id_a->low == entity_id_b->low);
}

static Bnet__Protocol__EntityId *
bn_copy_entity_id(const Bnet__Protocol__EntityId *in) {
	Bnet__Protocol__EntityId *out = g_new0(Bnet__Protocol__EntityId, 1);
	
	bnet__protocol__entity_id__init(out);
	out->high = in->high;
	out->low = in->low;
	
	return out;
}

static PurpleGroup *bn_get_buddy_group();

static void
bn_add_buddy_internal(BattleNetAccount *bna, const Bnet__Protocol__EntityId *entity_id, const gchar *battle_tag, const gchar *full_name)
{
	PurpleBuddy *buddy;
	gchar *temp_id;
	
	g_return_if_fail(entity_id);
	g_return_if_fail(battle_tag);
	
	buddy = purple_blist_find_buddy(bna->account, battle_tag);
	if (buddy == NULL) {
		buddy = purple_buddy_new(bna->account, battle_tag, full_name);
		purple_blist_add_buddy(buddy, NULL, bn_get_buddy_group(), NULL);
		
		temp_id = g_strdup_printf("%" G_GUINT64_FORMAT, entity_id->high);
		purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "entity_id_high", temp_id);
		g_free(temp_id);
		
		temp_id = g_strdup_printf("%" G_GUINT64_FORMAT, entity_id->low);
		purple_blist_node_set_string(PURPLE_BLIST_NODE(buddy), "entity_id_low", temp_id);
		g_free(temp_id);
	}
	
	if (!g_hash_table_lookup(bna->battle_tag_to_entity_id, battle_tag)) {
		g_hash_table_insert(bna->battle_tag_to_entity_id, g_strdup(battle_tag), bn_copy_entity_id(entity_id));
		g_hash_table_insert(bna->entity_id_to_battle_tag, bn_copy_entity_id(entity_id), g_strdup(battle_tag));
	}
}

static const Bnet__Protocol__EntityId *
bn_get_buddy_entity_id(BattleNetAccount *bna, const gchar *battle_tag)
{
	Bnet__Protocol__EntityId *entity_id;
	// PurpleBuddy *buddy;
	
	entity_id = g_hash_table_lookup(bna->battle_tag_to_entity_id, battle_tag);
	
	if (entity_id != NULL) {
		return entity_id;
	}
	
	// buddy = purple_blist_find_buddy(bna->account, battle_tag);
	// if (buddy != NULL) {
		// const gchar *entity_id_high = purple_blist_node_get_string(PURPLE_BLIST_NODE(buddy), "entity_id_high");
		// const gchar *entity_id_low = purple_blist_node_get_string(PURPLE_BLIST_NODE(buddy), "entity_id_low");
		
		// if (entity_id_high != NULL && entity_id_low != NULL) {
			// entity_id = g_new0(Bnet__Protocol__EntityId, 1);
			// entity_id->high = g_ascii_strtoull(entity_id_high, NULL, 10);
			// entity_id->low = g_ascii_strtoull(entity_id_low, NULL, 10);
			
			// g_hash_table_insert(bna->battle_tag_to_entity_id, g_strdup(battle_tag), entity_id); // don't copy this entity_id to prevent memleak
			// g_hash_table_insert(bna->entity_id_to_battle_tag, bn_copy_entity_id(entity_id), g_strdup(battle_tag));
			
			// return entity_id;
		// }
	// }
	
	return NULL;
}


static void
bn_free_service_method(gpointer data)
{
	BattleNetServiceWrapper *wrapper = data;
	
	if (wrapper != NULL) {
		g_free(wrapper->request_descriptor);
	}
}

static BattleNetService *
bn_create_service(BattleNetAccount *bna, const gchar *service_name)
{
	BattleNetService *service = g_new0(BattleNetService, 1);
	
	service->name = g_strdup(service_name);
	service->methods = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, bn_free_service_method);
	
	return service;
}

static void
bn_free_service(BattleNetService *service) 
{
	g_free(service->name);
	
	g_hash_table_remove_all(service->methods);
	g_hash_table_unref(service->methods);
	
	g_free(service);
}

static void
bn_service_add_method(BattleNetService *service, guint method_id, const ProtobufCMessageDescriptor request_type, BattleNetServiceMethod callback)
{
	BattleNetServiceWrapper *wrapper;
	
	wrapper = g_new0(BattleNetServiceWrapper, 1);
	wrapper->callback = callback;
	wrapper->request_descriptor = g_memdup(&request_type, sizeof(ProtobufCMessageDescriptor));
	
	g_hash_table_insert(service->methods, GINT_TO_POINTER(method_id), wrapper);
}

static BattleNetServiceMethod
bn_get_service_method(BattleNetAccount *bna, guint service_id, guint method_id, ProtobufCMessage **request)
{
	BattleNetService *service = g_hash_table_lookup(bna->exported_services, GINT_TO_POINTER(service_id));
	BattleNetServiceWrapper *wrapper = NULL;
	
	if (service != NULL) {
		wrapper = g_hash_table_lookup(service->methods, GINT_TO_POINTER(method_id));
	}
	
	if (wrapper != NULL) {
		if (request) {
			*request = g_malloc0(wrapper->request_descriptor->sizeof_message);
			protobuf_c_message_init(wrapper->request_descriptor, *request);
		}
		return wrapper->callback;
	}	
	
	if (request) {
		*request = NULL;
	}
	return NULL;
}

static void bn_send_request(BattleNetAccount *bna, guint service_id, guint method_id, ProtobufCMessage *body, BattleNetCallback callback, const ProtobufCMessageDescriptor *response_type, gpointer user_data);

static void
bn_socket_got_data(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
	BattleNetAccount *bna = userdata;
	int read_len = 0;
	gboolean done_some_reads = FALSE;
	guchar header_len_buf[2];
	
	while(bna->frame_header || bna->frame_body || (read_len = purple_ssl_read(conn, header_len_buf, 2)) == 2) {
		if (!bna->frame_header) {
			bna->frame_header_len = (header_len_buf[0] << 8) + header_len_buf[1];
			bna->frame_header = g_new0(guchar, bna->frame_header_len);
			bna->frame_header_len_progress = 0;
			
			bna->frame_body = NULL;
			bna->frame_body_len = 0;
			bna->frame_body_len_progress = 0;
		}
		
		if (!bna->frame_body) {
			while (bna->frame_header_len_progress < bna->frame_header_len) {
				read_len = purple_ssl_read(conn, bna->frame_header + bna->frame_header_len_progress, bna->frame_header_len - bna->frame_header_len_progress);
				if (read_len > 0) {
					bna->frame_header_len_progress += read_len;
				} else {
					break;
				}
			}
			done_some_reads = TRUE;
		
			if (bna->frame_header_len_progress == bna->frame_header_len) {
				
				Bnet__Protocol__Header *proto_header = bnet__protocol__header__unpack(NULL, bna->frame_header_len, bna->frame_header);
				bna->frame_body_len = proto_header->size;
				bna->frame_body = g_new0(guchar, MAX(bna->frame_body_len, 1));
				bna->frame_body_len_progress = 0;
				
				if (bna->last_header) {
					bnet__protocol__header__free_unpacked(bna->last_header, NULL);
				}
				bna->last_header = proto_header;
				
				if (G_UNLIKELY(bna->socket == NULL)) {
					return;
				}
			} else {
				return;
			}
		}
		
		if (bna->frame_body) {
			while (bna->frame_body_len_progress < bna->frame_body_len) {
				read_len = purple_ssl_read(conn, bna->frame_body + bna->frame_body_len_progress, bna->frame_body_len - bna->frame_body_len_progress);
				if (read_len > 0) {
					bna->frame_body_len_progress += read_len;
				} else {
					break;
				}
			}
			done_some_reads = TRUE;
			
			
			if (bna->frame_body_len_progress == bna->frame_body_len) {
				
				Bnet__Protocol__Header *proto_header = bna->last_header;
				
				if (proto_header->service_id == 254) {
					// This is a response to a request from us
					if (proto_header->status) {
						purple_debug_error("battlenet", "Response error %ud for token %ud\n", proto_header->status, proto_header->token);
					} else {
						BattleNetCallbackWrapper *callback_wrapper = g_hash_table_lookup(bna->token_callbacks, GINT_TO_POINTER(proto_header->token));
						ProtobufCMessageDescriptor *body_desc;
						
						purple_debug_info("battlenet", "Callback for token %u\n", proto_header->token);
						if (callback_wrapper && callback_wrapper->callback) {
							ProtobufCMessage *proto_body = NULL;
							
							body_desc = callback_wrapper->response_descriptor;
							if (body_desc != NULL) {
								proto_body = protobuf_c_message_unpack(body_desc, NULL, bna->frame_body_len, bna->frame_body);
							}
							callback_wrapper->callback(bna, proto_body, callback_wrapper->user_data);
							
							g_hash_table_remove(bna->token_callbacks, GINT_TO_POINTER(proto_header->token));
							if (body_desc != NULL) {
								protobuf_c_message_free_unpacked(proto_body, NULL);
							}
						}
					}
				} else {
					// Server requesting info from us
					BattleNetServiceMethod service_method;
					ProtobufCMessage *response, *request;
					
					purple_debug_info("battlenet", "Request %u.%u\n", proto_header->service_id, proto_header->method_id);
					service_method = bn_get_service_method(bna, proto_header->service_id, proto_header->method_id, &request);
					if (service_method != NULL) {
						request = protobuf_c_message_unpack(request->descriptor, NULL, bna->frame_body_len, bna->frame_body);
						response = service_method(bna, request);
						
						if (response != NULL) {
							bn_send_request(bna, 254, proto_header->token, response, NULL, NULL, NULL);
							protobuf_c_message_free_unpacked(response, NULL); //TODO this is probably the wrong _free() function?
						}
						
						protobuf_c_message_free_unpacked(request, NULL);
					} else {
						BattleNetService *service = g_hash_table_lookup(bna->exported_services, GINT_TO_POINTER(proto_header->service_id));
						if (service != NULL) {
							purple_debug_error("battlenet", "Unknown method %u for service %s requested\n", proto_header->method_id, service->name);
						} else {
							purple_debug_error("battlenet", "Unknown service requested\n");
						}
					}
				}
				
				//gboolean success = rc_process_frame(ya, bna->frame);
				g_free(bna->frame_header); bna->frame_header = NULL;
				g_free(bna->frame_body); bna->frame_body = NULL;
				bna->frame_header_len = 0;
				bna->frame_body_len = 0;
			}
		}
	}

	if (done_some_reads == FALSE && read_len <= 0) {
		if (read_len < 0 && errno == EAGAIN) {
			return;
		}

		purple_debug_error("battlenet", "got errno %d, read_len %d from socket\n", errno, read_len);

		// if (bna->frames_since_reconnect < 2) {
			purple_connection_error(bna->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, "Lost connection to server");
		// } else {
			// // Try reconnect
			// rc_start_socket(ya);
		// }
	}
}

static guint
bn_next_token(BattleNetAccount *bna)
{
	guint next_token = bna->next_token;
	
	bna->next_token += 1;
	bna->next_token = bna->next_token % 512;
	
	return next_token;
}

static guint
bn_next_object_id(BattleNetAccount *bna)
{
	guint next_object_id = bna->next_object_id + 1;
	
	bna->next_object_id += 1;
	
	return next_object_id;
}


static PurpleGroup *
bn_get_buddy_group()
{
    PurpleGroup *bn_group = purple_blist_find_group(_("Battle.net"));
	
	if (!bn_group)
	{
		bn_group = purple_group_new(_("Battle.net"));
		purple_blist_add_group(bn_group, NULL);
	}
	
    return bn_group;
}

typedef struct {
	ProtobufCBuffer base;
	PurpleSslConnection *socket;
} ProtoBufferAppendToPurpleSSL;

static void
purple_buffer_ssl_append(ProtobufCBuffer *buffer, unsigned len, const unsigned char *data)
{
	ProtoBufferAppendToPurpleSSL *purple_buffer = (ProtoBufferAppendToPurpleSSL *) buffer;
	
	//TODO do we need to check the return?
	purple_ssl_write(purple_buffer->socket, data, len);
}

static void
bn_send_request(BattleNetAccount *bna, guint service_id, guint method_id, ProtobufCMessage *body, BattleNetCallback callback, const ProtobufCMessageDescriptor *response_type, gpointer user_data)
{
	Bnet__Protocol__Header header = BNET__PROTOCOL__HEADER__INIT;
	size_t header_len;
	size_t body_len;
	guint16 be_len;
	guchar header_size_out[2];
	ProtoBufferAppendToPurpleSSL purple_buffer;
	
	header.service_id = service_id;
	
	if (service_id != 254) {
		header.has_method_id = TRUE;
		header.method_id = method_id;
		
		header.token = bn_next_token(bna);
	} else {
		// hacks
		header.has_method_id = TRUE;
		header.method_id = 0;
		
		header.token = method_id;
	}
	
	header.has_size = TRUE;
	header.size = body_len = protobuf_c_message_get_packed_size(body);
	
	if (callback != NULL) {
		BattleNetCallbackWrapper *wrapper = g_new0(BattleNetCallbackWrapper, 1);
		wrapper->callback = callback;
		if (response_type != NULL) {
			wrapper->response_descriptor = g_memdup(response_type, sizeof(ProtobufCMessageDescriptor));
		}
		wrapper->user_data = user_data;
		
		g_hash_table_insert(bna->token_callbacks, GINT_TO_POINTER(header.token), wrapper);
	}
	
	header_len = protobuf_c_message_get_packed_size((ProtobufCMessage *) &header);
	be_len = GUINT16_TO_BE(header_len);
	memmove(header_size_out, &be_len, 2);
	
	purple_ssl_write(bna->socket, header_size_out, 2);
	
	purple_buffer.socket = bna->socket;
	purple_buffer.base.append = purple_buffer_ssl_append;
	
	protobuf_c_message_pack_to_buffer((ProtobufCMessage *) &header, (ProtobufCBuffer *) &purple_buffer);
	protobuf_c_message_pack_to_buffer(body, (ProtobufCBuffer *) &purple_buffer);
}

#include <string.h>
#define FNV_PRIME_32 16777619
#define FNV_OFFSET_32 2166136261U
guint32
bn_fnv1a_32_hash(const gchar *s)
{
    guint32 hash = FNV_OFFSET_32;
	gsize i;
	
    for(i = 0; s[i]; i++) {
        hash = hash ^ (s[i]);
        hash = hash * FNV_PRIME_32;
    }
	
    return hash;
} 


void bn_authentication_logon(BattleNetAccount *bna);

static void
bn_on_connect(BattleNetAccount *bna, ProtobufCMessage *body, gpointer user_data)
{
	Bnet__Protocol__Connection__ConnectResponse *response = (Bnet__Protocol__Connection__ConnectResponse *) body;
	guint i;
	GList *list;
	
	for (i = 0, list = bna->services_to_import; i < response->bind_response->n_imported_service_id && list; i++, list = list->next) {
		BattleNetService *service = (BattleNetService *) list->data;
		guint32 service_id = response->bind_response->imported_service_id[i];
		
		purple_debug_info("battlenet", "got service id %d for service %s\n", service_id, service->name);
		
		service->id = service_id;
		g_hash_table_insert(bna->imported_services, GINT_TO_POINTER(service_id), service);
		
		// TODO make a hash table for name => service
		if (purple_strequal(service->name, "bnet.protocol.authentication.AuthenticationServer")) {
			bna->auth_service_id = service_id;
		} else if (purple_strequal(service->name, "bnet.protocol.presence.PresenceService")) {
			bna->presence_service_id = service_id;
		} else if (purple_strequal(service->name, "bnet.protocol.friends.FriendsService")) {
			bna->friends_service_id = service_id;
		} else if (purple_strequal(service->name, "bnet.protocol.notification.NotificationService")) {
			bna->notify_service_id = service_id;
		} else if (purple_strequal(service->name, "bnet.protocol.channel_invitation.ChannelInvitationService")) {
			bna->channel_invitation_service_id = service_id;
		}
	}
	
	bn_authentication_logon(bna);
}

static void
bn_socket_connected(gpointer userdata, PurpleSslConnection *conn, PurpleInputCondition cond)
{
	BattleNetAccount *bna = userdata;
	Bnet__Protocol__Connection__ConnectRequest request = BNET__PROTOCOL__CONNECTION__CONNECT_REQUEST__INIT;
	Bnet__Protocol__Connection__BindRequest bind_request = BNET__PROTOCOL__CONNECTION__BIND_REQUEST__INIT;
	guint i;
	GList *list;
	
	purple_ssl_input_add(bna->socket, bn_socket_got_data, bna);
	
	request.bind_request = &bind_request;
	
	
	// size_t n_imported_service_hash;
	// uint32_t *imported_service_hash;
	bind_request.n_imported_service_hash = g_list_length(bna->services_to_import);
	bind_request.imported_service_hash = g_new0(guint32, bind_request.n_imported_service_hash);
	
	for(i = 0, list = bna->services_to_import; list; i++, list = list->next) {
		BattleNetService *service = (BattleNetService *) list->data;
		
		bind_request.imported_service_hash[i] = bn_fnv1a_32_hash(service->name);
	}
	
	// size_t n_exported_service;
	// Bnet__Protocol__Connection__BoundService **exported_service;
	bind_request.n_exported_service = g_list_length(bna->services_to_export);
	bind_request.exported_service = g_new0(Bnet__Protocol__Connection__BoundService *, bind_request.n_exported_service);
	
	for(i = 0, list = bna->services_to_export; list; i++, list = list->next) {
		BattleNetService *service = (BattleNetService *) list->data;
		Bnet__Protocol__Connection__BoundService *bound_service = g_new0(Bnet__Protocol__Connection__BoundService, 1);
		
		bnet__protocol__connection__bound_service__init(bound_service);
		bound_service->id = service->id = i + 1;
		bound_service->hash = bn_fnv1a_32_hash(service->name);
		
		bind_request.exported_service[i] = bound_service;
		g_hash_table_insert(bna->exported_services, GINT_TO_POINTER(service->id), service);
	}
	
	//Invoke a RPC call to ConnectionService.connect (service_id=0, method_id=1 ) and provide a list of services exported by the client
	bn_send_request(bna, 0, 1, (ProtobufCMessage *) &request, bn_on_connect, &bnet__protocol__connection__connect_response__descriptor, NULL);
	
	g_free(bind_request.imported_service_hash);
}

static void
bn_socket_failed(PurpleSslConnection *conn, PurpleSslErrorType errortype, gpointer userdata)
{
	BattleNetAccount *bna = userdata;
	
	bna->socket = NULL;
	
	purple_connection_error(bna->pc, PURPLE_CONNECTION_ERROR_NETWORK_ERROR, NULL);
}

static void
bn_connect(BattleNetAccount *bna)
{
	//Reset all the old stuff
	if (bna->socket != NULL) {
		purple_ssl_close(bna->socket);
	}
	
	//TODO switch server
	bna->socket = purple_ssl_connect(bna->account, "us.actual.battle.net", 1119, bn_socket_connected, bn_socket_failed, bna);
}


void
bn_authentication_logon(BattleNetAccount *bna)
{
	Bnet__Protocol__Authentication__LogonRequest request = BNET__PROTOCOL__AUTHENTICATION__LOGON_REQUEST__INIT;
	
	request.program = "App";
	request.platform = "Win"; //TODO?
	request.locale = "enUS"; //TODO?
	request.version = "8180";
	request.has_application_version = TRUE;
	request.application_version = 1;
	request.has_public_computer = TRUE;
	request.public_computer = FALSE;
	request.has_disconnect_on_cookie_fail = TRUE;
	request.disconnect_on_cookie_fail = FALSE;
	request.has_allow_logon_queue_notifications = TRUE;
	request.allow_logon_queue_notifications = TRUE;
	request.has_web_client_verification = TRUE;
	request.web_client_verification = TRUE;
	request.user_agent = "Battle.net/1.5.2.8180 (PC;Intel_R_Core_TM_i7_2600K_CPU_3.40GHz_16352_MB_;Desktop;c05571db8b3f670d74b2238da294daef0e278166;26424;AMD_Radeon_HD_6800_Series;ATI;4098;Direct3D_9.0c_aticfx32.dll_8.17.10.1404_;1011;30;Full;Windows_7_Service_Pack_1_6.1.7601_64bit;8;Intel_R_Core_TM_i7_2600K_CPU_3.40GHz;4;True;False;False;False;True;False;False;True;True;True;False;1;False;16352;True;True;True;False;1920;1080;96;Desktop;True) Battle.net/CSharp";
	
	// response is sent via RPC to bn_authentication_logon_result
	bn_send_request(bna, bna->auth_service_id, 1, (ProtobufCMessage *) &request, NULL, NULL, NULL);
	
}

static void
bn_presence_subscribe(BattleNetAccount *bna, Bnet__Protocol__EntityId *entity)
{
	Bnet__Protocol__Presence__SubscribeRequest request = BNET__PROTOCOL__PRESENCE__SUBSCRIBE_REQUEST__INIT;
	
	request.entity_id = entity;
	request.object_id = bn_next_object_id(bna);
	
	bn_send_request(bna, bna->presence_service_id, 1, (ProtobufCMessage *) &request, NULL, NULL, NULL);
}

typedef struct {
	BattleNetAccount *bna;
	guint64 invite_id;
} BattleNetInviteResponseStore;

static void bn_friends_auth_accept(gpointer data);
static void bn_friends_auth_reject(gpointer data);

static void
bn_friends_subscribe_result(BattleNetAccount *bna, ProtobufCMessage *body, gpointer user_data)
{
	Bnet__Protocol__Friends__SubscribeToFriendsResponse *response = (Bnet__Protocol__Friends__SubscribeToFriendsResponse *) body;
	guint i;
	
	if (body == NULL) {
		purple_debug_error("battlenet", "Friends subscription failed\n");
		return;
	}
	
	for (i = 0; i < response->n_friends; i++) {
		Bnet__Protocol__Friends__Friend *friend = response->friends[i];
		
		bn_presence_subscribe(bna, friend->id);
		purple_debug_info("battlenet", "This friend has high %" G_GUINT64_FORMAT " and low %" G_GUINT64_FORMAT "\n", friend->id->high, friend->id->low);
		
		if (friend->battle_tag != NULL) {
			bn_add_buddy_internal(bna, friend->id, friend->battle_tag, friend->full_name);
		}
	}
	
	for (i = 0; i < response->n_received_invitations; i++) {
		Bnet__Protocol__Invitation__Invitation *invitation = response->received_invitations[i];
		BattleNetInviteResponseStore *store = g_new0(BattleNetInviteResponseStore, 1);
		
		store->bna = bna;
		store->invite_id = invitation->id;
				
		purple_account_request_authorization(bna->account, invitation->inviter_name, NULL, NULL, invitation->invitation_message, FALSE, bn_friends_auth_accept, bn_friends_auth_reject, store);
	}
	
}

static void
bn_friends_subscribe_to_friends(BattleNetAccount *bna)
{
	Bnet__Protocol__Friends__SubscribeToFriendsRequest request = BNET__PROTOCOL__FRIENDS__SUBSCRIBE_TO_FRIENDS_REQUEST__INIT;
	
	bn_send_request(bna, bna->friends_service_id, 1, (ProtobufCMessage *) &request, bn_friends_subscribe_result, &bnet__protocol__friends__subscribe_to_friends_response__descriptor, NULL);
}

static void
bn_channel_subscribe_to_channels(BattleNetAccount *bna)
{
	Bnet__Protocol__ChannelInvitation__SubscribeRequest request = BNET__PROTOCOL__CHANNEL_INVITATION__SUBSCRIBE_REQUEST__INIT;
	
	bn_send_request(bna, bna->channel_invitation_service_id, 1, (ProtobufCMessage *) &request, NULL, NULL, NULL);
}


static void
bn_auth_on_select_game_account(BattleNetAccount *bna, ProtobufCMessage *body, gpointer user_data)
{
	bn_friends_subscribe_to_friends(bna);
	bn_channel_subscribe_to_channels(bna);
	
	purple_connection_set_state(bna->pc, PURPLE_CONNECTION_CONNECTED);
}

static void
bn_auth_select_game_account_DEPRECATED(BattleNetAccount *bna, Bnet__Protocol__EntityId *entity)
{
	bn_send_request(bna, bna->auth_service_id, 4, (ProtobufCMessage *) entity, bn_auth_on_select_game_account, NULL, NULL);
}

ProtobufCMessage *
bn_authentication_logon_result(BattleNetAccount *bna, ProtobufCMessage *request_in)
{
	Bnet__Protocol__Authentication__LogonResult *request = (Bnet__Protocol__Authentication__LogonResult *) request_in;
	guint i;
	
	purple_debug_info("battlenet", "Battle tag is %s\n", request->battle_tag);
	bna->account_entity = bn_copy_entity_id(request->account);
	
	bn_presence_subscribe(bna, request->account);
	for (i = 0; i < request->n_game_account; i++) {
		bn_presence_subscribe(bna, request->game_account[i]);
		if (i == 0) {
			bn_auth_select_game_account_DEPRECATED(bna, request->game_account[i]);
		}
	}
	
	if (request->n_game_account == 0) {
		bn_friends_subscribe_to_friends(bna);
		// dont do this, it errors
		//bn_channel_subscribe_to_channels(bna);
		
		purple_connection_set_state(bna->pc, PURPLE_CONNECTION_CONNECTED);
	}
	
	return NULL;
}

static void bn_auth_verify_web_credentials(BattleNetAccount *bna, const gchar *auth_url);

static void
bn_webcred_input_cb(gpointer user_data, const gchar *auth_code)
{
	BattleNetAccount *bna = user_data;

	purple_account_set_string(bna->account, "web_credentials", auth_code);
	bn_auth_verify_web_credentials(bna, NULL);
}

static void
bn_webcred_input_cancel_cb(gpointer user_data)
{
	BattleNetAccount *bna = user_data;
	purple_connection_error(bna->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE, 
		_("User cancelled authorization"));
}

static void
bn_auth_verify_web_credentials(BattleNetAccount *bna, const gchar *auth_url)
{
	Bnet__Protocol__Authentication__VerifyWebCredentialsRequest verify_request = BNET__PROTOCOL__AUTHENTICATION__VERIFY_WEB_CREDENTIALS_REQUEST__INIT;
	const gchar *web_credentials = purple_account_get_string(bna->account, "web_credentials", NULL);
	
	if (web_credentials == NULL && auth_url != NULL) {
		purple_request_input(bna->pc, _("Authorization Code"), auth_url,
			_ ("Please follow the URL to get the ST= info header and paste here"),
			_ ("US-"), FALSE, FALSE, NULL, 
			_("OK"), G_CALLBACK(bn_webcred_input_cb), 
			_("Cancel"), G_CALLBACK(bn_webcred_input_cancel_cb), 
			purple_request_cpar_from_connection(bna->pc), bna);
		
		//TODO use the auth_url to auth
		// then grab the content of 
		//Location: http://localhost:0/?ST={this-bit}&region=&accountName=...
		return;
	}
	
	verify_request.has_web_credentials = TRUE;
	verify_request.web_credentials.len = strlen(web_credentials) * sizeof(guint8);
	verify_request.web_credentials.data = (guint8 *) web_credentials;
	
	bn_send_request(bna, bna->auth_service_id, 7, (ProtobufCMessage *) &verify_request, NULL, NULL, NULL);
	
}

ProtobufCMessage *
bn_challenge_on_external_challenge(BattleNetAccount *bna, ProtobufCMessage *request_in)
{
	Bnet__Protocol__Challenge__ChallengeExternalRequest *request = (Bnet__Protocol__Challenge__ChallengeExternalRequest *) request_in;
	gchar *payload;
	
	if (!purple_strequal(request->payload_type, "web_auth_url")) {
		gchar *error_message = g_strdup_printf("Unknown auth payload_type '%s'", request->payload_type);
		purple_connection_error(bna->pc, PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE, error_message);
		g_free(error_message);
		return NULL;
	}
	
	payload = g_strndup((gchar *)request->payload.data, request->payload.len);
	bn_auth_verify_web_credentials(bna, payload);
	g_free(payload);
	
	return NULL;
}

static void
bn_dump_field_data(Bnet__Protocol__Presence__Field *field)
{
	Bnet__Protocol__Attribute__Variant *value = field->value;
	gchar *program_str = g_new0(gchar, 10);
	guint program_pos = 8;
	guint program_int = field->key->program;
	
	while(program_int && program_pos) {
		program_str[program_pos--] = program_int & 0xFF;
		program_int = program_int >> 16;
	}
	
	purple_debug_info("battlenet", "Program: %x %s, Group: %u, Field: %u = ", field->key->program, &program_str[program_pos+1], field->key->group, field->key->field);
	
	if (value->has_bool_value)
		purple_debug_info("battlenet", "bool: %d, ", value->bool_value);
	if (value->has_int_value)
		purple_debug_info("battlenet", "int: %" G_GINT64_FORMAT ", ", value->int_value);
	if (value->has_float_value)
		purple_debug_info("battlenet", "float: %f, ", value->float_value);
	if (value->string_value)
		purple_debug_info("battlenet", "string: %s, ", value->string_value);
	if (value->has_blob_value)
		purple_debug_info("battlenet", "blob: %*s, ", value->blob_value.len, value->blob_value.data);
	if (value->has_message_value)
		purple_debug_info("battlenet", "message: %*s, ", value->message_value.len, value->message_value.data);
	if (value->fourcc_value)
		purple_debug_info("battlenet", "fourcc: %s, ", value->fourcc_value);
	if (value->has_uint_value)
		purple_debug_info("battlenet", "uint: %" G_GUINT64_FORMAT ", ", value->uint_value);
	if (value->entityid_value)
		purple_debug_info("battlenet", "entity_id high: %" G_GUINT64_FORMAT ", low: %" G_GUINT64_FORMAT ", ", value->entityid_value->high, value->entityid_value->low);
	
	purple_debug_info("battlenet", "\n");
}

static void
bn_channel_update_presence(BattleNetAccount *bna, Bnet__Protocol__EntityId *entity_id, size_t n_field_operation, Bnet__Protocol__Presence__FieldOperation **field_operation)
{
	guint i;
	const gchar *battle_tag = g_hash_table_lookup(bna->entity_id_to_battle_tag, entity_id);
	const gchar *full_name = NULL;
	gint64 last_online = 0;
	gboolean is_away = FALSE;
	gboolean is_online = FALSE;
	gboolean is_busy = FALSE;
	gboolean status_changed = FALSE;
	gint64 away_time = 0;
	const gchar *in_game = NULL;
	const gchar *rich_presence = NULL;
	Bnet__Protocol__EntityId *conv_entity_id = NULL;
	
	for (i = 0; i < n_field_operation; i++) {
		Bnet__Protocol__Presence__FieldOperation *fo = field_operation[i];
		
		// Program code magic is hex encoding of program name
		if (fo->field->key->program == 0x424e) { // 16974 == BN;  0x42 == B  0x4e == N
			
			// see https://github.com/HearthSim/python-bnet/wiki/Service-Methods#application-bn
			switch(fo->field->key->group) {
				
				// Account
				case 1: {
					switch(fo->field->key->field) {
						case 1: {
							//full name
							full_name = fo->field->value->string_value;
						} break;
						case 3: {
							// game account
							purple_debug_info("battlenet", "game account entity_id high %" G_GUINT64_FORMAT " and low %" G_GUINT64_FORMAT "\n", entity_id->high, entity_id->low);
							bn_presence_subscribe(bna, fo->field->value->entityid_value);
						} break;
						case 4: {
							//battle tag
							battle_tag = fo->field->value->string_value;
						} break;
						case 6: {
							// last online
							last_online = fo->field->value->int_value;
							purple_debug_info("battlenet", "last online %" G_GINT64_FORMAT "\n", last_online);
							if ((last_online / 1000000) >= time(NULL) - 1) {
								//is_online = TRUE;
							} else {
								//is_online = FALSE;
							}
						} break;
						case 7: {
							// away
							is_away = fo->field->value->bool_value;
							is_online = !is_away;
							status_changed = TRUE;
							bn_dump_field_data(fo->field);
						} break;
						case 8: {
							// away time
							away_time = fo->field->value->int_value;
						} break;
						case 11: {
							// dnd
							is_busy = fo->field->value->bool_value;
							is_online = !is_busy;
							status_changed = TRUE;
							bn_dump_field_data(fo->field);
						} break;
						default: {
							purple_debug_error("battlenet", "Unknown presence field %d for group 1\n", fo->field->key->field);
							bn_dump_field_data(fo->field);
						}
					}
				} break;
				
				// Game Account
				case 2: {
					switch(fo->field->key->field) {
						case 1: {
							//account online
							is_online = fo->field->value->bool_value;
							status_changed = TRUE;
							bn_dump_field_data(fo->field);
						} break;
						case 2: {
							// busy
							is_busy = fo->field->value->bool_value;
							is_online = !is_busy;
							status_changed = TRUE;
							bn_dump_field_data(fo->field);
						} break;
						case 3: {
							//program
							in_game = fo->field->value->fourcc_value;
							bn_dump_field_data(fo->field);
							if (purple_strequal(in_game, "Pro")) {
								in_game = "Overwatch";
							}
							status_changed = TRUE;
						} break;
						case 4: {
							// last online
							last_online = fo->field->value->int_value;
						} break;
						case 5: {
							//battle tag
							battle_tag = fo->field->value->string_value;
						} break;
						case 6: {
							//account name
							//account_name = fo->field->value->string_value;
						} break;
						case 7: {
							// account id
							purple_debug_info("battlenet", "Old entity_id high %" G_GUINT64_FORMAT " and low %" G_GUINT64_FORMAT "\n", entity_id->high, entity_id->low);
							conv_entity_id = entity_id;
							entity_id = fo->field->value->entityid_value;
						} break;
						case 8: {
							// rich_presence
							ProtobufCBinaryData presence_message = fo->field->value->message_value;
							gchar *presence_str = g_new0(gchar, 4 * presence_message.len + 1);
							gint j, pos;
							// \r o r P \000 \025 a o r p \030 \025
							// \r p p A \000 \025 s r p r \030 \000
							for (j = presence_message.len - 1, pos = 0; j >= 0; j--) {
								guchar c = presence_message.data[j];
								if (c < 0x1F || c > 0x7E) {
									presence_str[pos++] = '\\';
									presence_str[pos++] = '0' + (((c) >> 6) & 07);
									presence_str[pos++] = '0' + (((c) >> 3) & 07);
									presence_str[pos++] = '0' + ((c) & 07);
								} else {
									presence_str[pos++] = presence_message.data[j];
								}
							}
							purple_debug_misc("battlenet", "Presence %s\n", presence_str);
							g_free(presence_str);
						} break;
						case 10: {
							// afk
							is_away = fo->field->value->bool_value;
							is_online = !is_away;
							status_changed = TRUE;
							bn_dump_field_data(fo->field);
						} break;
						default: {
							purple_debug_error("battlenet", "Unknown presence field %d for group 2\n", fo->field->key->field);
							bn_dump_field_data(fo->field);
						}
					}
				} break;
				
				default:
					purple_debug_error("battlenet", "Unknown presence key group %d\n", fo->field->key->group);
					bn_dump_field_data(fo->field);
					break;
			}
		} else {
			purple_debug_error("battlenet", "Unknown presence program %x\n", fo->field->key->program);
			bn_dump_field_data(fo->field);
		}
	}
	
	purple_debug_info("battlenet", "Battle tag %s has high %" G_GUINT64_FORMAT " and low %" G_GUINT64_FORMAT "\n", battle_tag, entity_id->high, entity_id->low);
	//TODO this entity_id is wrong for this battle_tag
	if (conv_entity_id && battle_tag) {
		bn_add_buddy_internal(bna, conv_entity_id, battle_tag, full_name);
	}
	
	if (battle_tag && !g_hash_table_lookup(bna->entity_id_to_battle_tag, entity_id)) {
		// Save for lookup later, but only one way - these aren't conversation entities
		g_hash_table_insert(bna->entity_id_to_battle_tag, bn_copy_entity_id(entity_id), g_strdup(battle_tag));
	}
	
	rich_presence = in_game;
	
	if (battle_tag != NULL && status_changed == TRUE) {
		if (is_away) {
			purple_protocol_got_user_status(bna->account, battle_tag, "away", "message", rich_presence, NULL);
		} else if (is_busy) {
			purple_protocol_got_user_status(bna->account, battle_tag, "busy", "message", rich_presence, NULL);
		} else if (is_online) {
			//TODO this isn't reliable :s
			purple_protocol_got_user_status(bna->account, battle_tag, "online", "message", rich_presence, NULL);
		} else {
			purple_protocol_got_user_status(bna->account, battle_tag, "offline", NULL);
		}
	}
	
	//TODO
	(void) in_game;
	(void) away_time;
	(void) last_online;
}

ProtobufCMessage *
bn_channel_notify_add(BattleNetAccount *bna, ProtobufCMessage *request_in)
{
	Bnet__Protocol__Channel__AddNotification *request = (Bnet__Protocol__Channel__AddNotification *) request_in;
	Bnet__Protocol__Presence__ChannelState *presence = NULL;
	
	// // If we're using protobuf extensions we can use this code
	// guint i;
	
	// for (i = 0; i < request->channel_state->base.n_unknown_fields; i++) {
		// ProtobufCMessageUnknownField unknown_field = request->channel_state->base.unknown_fields[i];
		
		// if (unknown_field.tag == 101) {
			// presence = bnet__protocol__presence__channel_state__unpack(NULL, unknown_field.len, unknown_field.data);
		// }
	// }
	
	// if (presence != NULL) {
		// bn_channel_update_presence(bna, presence->entity_id, presence->n_field_operation, presence->field_operation);
		// bnet__protocol__presence__channel_state__free_unpacked(presence, NULL);
	// }
	
	// If we edited the protobufs to add the fields to the ChannelState then use this code
	presence = request->channel_state->presence;
	if (presence != NULL) {
		bn_channel_update_presence(bna, presence->entity_id, presence->n_field_operation, presence->field_operation);
	}
	
	return NULL;
}

ProtobufCMessage *
bn_channel_notify_update_channel_state(BattleNetAccount *bna, ProtobufCMessage *request_in)
{
	Bnet__Protocol__Channel__UpdateChannelStateNotification *request = (Bnet__Protocol__Channel__UpdateChannelStateNotification *) request_in;
	Bnet__Protocol__Presence__ChannelState *presence = NULL;
	
	//See above about this code
	presence = request->state_change->presence;
	if (presence != NULL) {
		bn_channel_update_presence(bna, presence->entity_id, presence->n_field_operation, presence->field_operation);
	}
	
	return NULL;
}

static void
bn_friends_auth_accept(gpointer data)
{
	BattleNetInviteResponseStore *store = data;
	Bnet__Protocol__Invitation__GenericRequest request = BNET__PROTOCOL__INVITATION__GENERIC_REQUEST__INIT;
	
	request.invitation_id = store->invite_id;
	bn_send_request(store->bna, store->bna->friends_service_id, 3, (ProtobufCMessage *) &request, NULL, NULL, NULL);
	
	g_free(store);
}

static void
bn_friends_auth_reject(gpointer data)
{
	BattleNetInviteResponseStore *store = data;
	Bnet__Protocol__Invitation__GenericRequest request = BNET__PROTOCOL__INVITATION__GENERIC_REQUEST__INIT;
	
	request.invitation_id = store->invite_id;
	bn_send_request(store->bna, store->bna->friends_service_id, 5, (ProtobufCMessage *) &request, NULL, NULL, NULL);
	
	g_free(store);
}

ProtobufCMessage *
bn_friends_on_invitation(BattleNetAccount *bna, ProtobufCMessage *request_in)
{
	Bnet__Protocol__Friends__InvitationNotification *request = (Bnet__Protocol__Friends__InvitationNotification *) request_in;
	BattleNetInviteResponseStore *store = g_new0(BattleNetInviteResponseStore, 1);
	
	store->bna = bna;
	store->invite_id = request->invitation->id;
			
	purple_account_request_authorization(bna->account, request->invitation->inviter_name, NULL, NULL, request->invitation->invitation_message, FALSE, bn_friends_auth_accept, bn_friends_auth_reject, store);
	
	return NULL;
}

ProtobufCMessage *
bn_friends_on_add(BattleNetAccount *bna, ProtobufCMessage *request_in)
{
	Bnet__Protocol__Friends__FriendNotification *request = (Bnet__Protocol__Friends__FriendNotification *) request_in;
	
	bn_add_buddy_internal(bna, request->target->id, request->target->battle_tag, request->target->full_name);
	
	bn_presence_subscribe(bna, request->target->id);
	
	return NULL;
}

ProtobufCMessage *
bn_connection_handle_echo_request(BattleNetAccount *bna, ProtobufCMessage *request_in)
{
	Bnet__Protocol__Connection__EchoRequest *request = (Bnet__Protocol__Connection__EchoRequest *) request_in;
	Bnet__Protocol__Connection__EchoResponse *response;
	
	response = g_malloc0(bnet__protocol__connection__echo_response__descriptor.sizeof_message);
	bnet__protocol__connection__echo_response__init(response);
	
	response->has_time = request->has_time;
	response->time = request->time;
	
	if (request->has_payload) {
		response->has_payload = TRUE;
		response->payload.len = request->payload.len;
		response->payload.data = g_memdup(request->payload.data, request->payload.len);
	}
	
	return (ProtobufCMessage *)response;
}

ProtobufCMessage *
bn_connection_handle_force_disconnect_request(BattleNetAccount *bna, ProtobufCMessage *request_in)
{
	Bnet__Protocol__Connection__DisconnectNotification *request = (Bnet__Protocol__Connection__DisconnectNotification *) request_in;
	
	if (request->error_code == 60) {
		// logged in elsewhere
	}
	
	purple_debug_error("battlenet", "Kicked off by server because of \"%s\" (%u)\n", request->reason, request->error_code);
	purple_connection_error(bna->pc, PURPLE_CONNECTION_ERROR_OTHER_ERROR, request->reason);
	
	return NULL;
}

static void
bn_notification_send_whisper(BattleNetAccount *bna, const Bnet__Protocol__EntityId *target_id, const gchar *message)
{
	Bnet__Protocol__Notification__Notification notification = BNET__PROTOCOL__NOTIFICATION__NOTIFICATION__INIT;
	Bnet__Protocol__Attribute__Variant value = BNET__PROTOCOL__ATTRIBUTE__VARIANT__INIT;
	Bnet__Protocol__Attribute__Attribute attribute = BNET__PROTOCOL__ATTRIBUTE__ATTRIBUTE__INIT;
	
	notification.target_id = (Bnet__Protocol__EntityId *) target_id;
	notification.type = "WHISPER";
	
	value.string_value = (gchar *) message;
	attribute.name = "whisper";
	attribute.value = &value;
	notification.n_attribute = 1;
	notification.attribute = g_new0(Bnet__Protocol__Attribute__Attribute *, 1);
	notification.attribute[0] = &attribute;
	
	bn_send_request(bna, bna->notify_service_id, 1, (ProtobufCMessage *) &notification, NULL, NULL, NULL);
	
	g_free(notification.attribute);
}

static void
bn_notification_send_typing(BattleNetAccount *bna, const Bnet__Protocol__EntityId *target_id, gboolean is_typing)
{
	Bnet__Protocol__Notification__Notification notification = BNET__PROTOCOL__NOTIFICATION__NOTIFICATION__INIT;
	Bnet__Protocol__Attribute__Variant value = BNET__PROTOCOL__ATTRIBUTE__VARIANT__INIT;
	Bnet__Protocol__Attribute__Attribute attribute = BNET__PROTOCOL__ATTRIBUTE__ATTRIBUTE__INIT;
	
	notification.target_id = (Bnet__Protocol__EntityId *) target_id;
	notification.type = "TYPING";
	
	value.has_bool_value = TRUE;
	value.bool_value = is_typing;
	attribute.name = "on";
	attribute.value = &value;
	notification.n_attribute = 1;
	notification.attribute = g_new0(Bnet__Protocol__Attribute__Attribute *, 1);
	notification.attribute[0] = &attribute;
	
	bn_send_request(bna, bna->notify_service_id, 1, (ProtobufCMessage *) &notification, NULL, NULL, NULL);
	
	g_free(notification.attribute);
}

ProtobufCMessage *
bn_notification_on_notification_received(BattleNetAccount *bna, ProtobufCMessage *request_in)
{
	Bnet__Protocol__Notification__Notification *request = (Bnet__Protocol__Notification__Notification *) request_in;
	guint i;
	
	bn_add_buddy_internal(bna, request->sender_id, request->sender_battle_tag, NULL);
	
	purple_debug_info("battlenet", "Notifcation type %s\n", request->type);
	for (i = 0; i < request->n_attribute; i++) {
		Bnet__Protocol__Attribute__Attribute *attribute = request->attribute[i];
		
		purple_debug_info("battlenet", "Notification %d has attribute %s\n", i, attribute->name);
	}
	
	purple_debug_info("battlenet", "Battle tag %s has high %" G_GUINT64_FORMAT " and low %" G_GUINT64_FORMAT "\n", request->sender_battle_tag, request->sender_id->high, request->sender_id->low);
	
	if (purple_strequal(request->type, "WHISPER")) {
		gchar *message = purple_markup_escape_text(request->attribute[0]->value->string_value, -1);
		purple_serv_got_im(bna->pc, request->sender_battle_tag, message, PURPLE_MESSAGE_RECV, time(NULL));
		g_free(message);
	} else if (purple_strequal(request->type, "TYPING")) {
		purple_serv_got_typing(bna->pc, request->sender_battle_tag, 7, request->attribute[0]->value->bool_value ? PURPLE_TYPING : PURPLE_NOT_TYPING);
	} else {
		purple_debug_error("battlenet", "Unknown notification type\n");
	}
	
	return NULL;
}



static const char *
bn_list_icon(PurpleAccount *account, PurpleBuddy *buddy)
{
	return "battlenet";
}

static GList *
bn_status_types(PurpleAccount *account)
{
	GList *types = NULL;
	PurpleStatusType *status;

	status = purple_status_type_new_with_attrs(PURPLE_STATUS_AVAILABLE, "online", "Online", TRUE, TRUE, FALSE, "message", "Presence", purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);

	status = purple_status_type_new_with_attrs(PURPLE_STATUS_AWAY, "away", "Away", TRUE, TRUE, FALSE, "message", "Presence", purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);

	status = purple_status_type_new_with_attrs(PURPLE_STATUS_UNAVAILABLE, "busy", "Busy", TRUE, TRUE, FALSE, "message", "Presence", purple_value_new(PURPLE_TYPE_STRING), NULL);
	types = g_list_append(types, status);
	
	status = purple_status_type_new_full(PURPLE_STATUS_OFFLINE, "offline", "Offline", TRUE, TRUE, FALSE);
	types = g_list_append(types, status);
	
	return types;
}

static void
bn_set_status(PurpleAccount *account, PurpleStatus *status)
{
	PurpleConnection *pc = purple_account_get_connection(account);
	BattleNetAccount *bna = purple_connection_get_protocol_data(pc);
	const gchar *new_status = purple_status_get_id(status);
	
	Bnet__Protocol__Presence__UpdateRequest request = BNET__PROTOCOL__PRESENCE__UPDATE_REQUEST__INIT;
	
	Bnet__Protocol__Presence__FieldOperation away_field_operation = BNET__PROTOCOL__PRESENCE__FIELD_OPERATION__INIT;
	Bnet__Protocol__Presence__Field away_field = BNET__PROTOCOL__PRESENCE__FIELD__INIT;
	Bnet__Protocol__Presence__FieldKey away_key = BNET__PROTOCOL__PRESENCE__FIELD_KEY__INIT;
	Bnet__Protocol__Attribute__Variant away_value = BNET__PROTOCOL__ATTRIBUTE__VARIANT__INIT;
	
	Bnet__Protocol__Presence__FieldOperation busy_field_operation = BNET__PROTOCOL__PRESENCE__FIELD_OPERATION__INIT;
	Bnet__Protocol__Presence__Field busy_field = BNET__PROTOCOL__PRESENCE__FIELD__INIT;
	Bnet__Protocol__Presence__FieldKey busy_key = BNET__PROTOCOL__PRESENCE__FIELD_KEY__INIT;
	Bnet__Protocol__Attribute__Variant busy_value = BNET__PROTOCOL__ATTRIBUTE__VARIANT__INIT;
	
	away_key.program = busy_key.program = 0x424e;
	away_key.group = busy_key.group = 1;
	
	away_key.field = 7;
	away_value.has_bool_value = TRUE;
	away_value.bool_value = purple_strequal(new_status, "away");
	
	busy_key.field = 11;
	busy_value.has_bool_value = TRUE;
	busy_value.bool_value = purple_strequal(new_status, "busy");
	
	away_field.key = &away_key;
	away_field.value = &away_value;
	away_field_operation.field = &away_field;
	busy_field.key = &busy_key;
	busy_field.value = &busy_value;
	busy_field_operation.field = &busy_field;
	away_field_operation.has_operation = busy_field_operation.has_operation = TRUE;
	away_field_operation.operation = busy_field_operation.operation = BNET__PROTOCOL__PRESENCE__FIELD_OPERATION__OPERATION_TYPE__SET;
	
	request.n_field_operation = 2;
	request.field_operation = g_new0(Bnet__Protocol__Presence__FieldOperation *, 2);
	request.field_operation[0] = &away_field_operation;
	request.field_operation[1] = &busy_field_operation;
	
	request.entity_id = bna->account_entity;
	
	bn_send_request(bna, bna->presence_service_id, 3, (ProtobufCMessage *) &request, NULL, NULL, NULL);
	
	g_free(request.field_operation);
}



static int
bn_send_im(PurpleConnection *pc, 
#if PURPLE_VERSION_CHECK(3, 0, 0)
PurpleMessage *msg)
{
	const gchar *who = purple_message_get_recipient(msg);
	const gchar *message = purple_message_get_contents(msg);
#else
const gchar *who, const gchar *message, PurpleMessageFlags flags)
{
#endif

	BattleNetAccount *bna = purple_connection_get_protocol_data(pc);
	const Bnet__Protocol__EntityId *entity_id = bn_get_buddy_entity_id(bna, who);
	gchar *stripped;
	
	if (entity_id == NULL) {
		//TODO find entity if we haven't received it yet
		return -1;
	}
	
	stripped = g_strstrip(purple_markup_strip_html(message));
	
	//TODO split into 256 characters (not bytes!!) messages
	bn_notification_send_whisper(bna, entity_id, stripped);
	
	g_free(stripped);
	
	return strlen(message);
}

static guint
bn_send_typing(PurpleConnection *pc, const gchar *who, PurpleIMTypingState state)
{
	BattleNetAccount *bna = purple_connection_get_protocol_data(pc);
	const Bnet__Protocol__EntityId *entity_id = bn_get_buddy_entity_id(bna, who);
	
	if (entity_id == NULL) {
		//TODO find entity if we haven't received it yet
		return 0;
	}
	
	bn_notification_send_typing(bna, entity_id, (state == PURPLE_IM_TYPING));
	
	return 5;
}

static gchar *
bn_status_text(PurpleBuddy *buddy)
{
	const gchar *message = purple_status_get_attr_string(purple_presence_get_active_status(purple_buddy_get_presence(buddy)), "message");
	
	if (message == NULL) {
		return NULL;
	}
	
	return g_markup_printf_escaped("%s", message);
}

static void
bn_login(PurpleAccount *account)
{
	BattleNetAccount *bna;
	PurpleConnection *pc = purple_account_get_connection(account);
	BattleNetService *service;
	// PurpleConnectionFlags pc_flags;
	
	// pc_flags = purple_connection_get_flags(pc);
	// pc_flags |= PURPLE_CONNECTION_FLAG_HTML;
	// pc_flags |= PURPLE_CONNECTION_FLAG_NO_FONTSIZE;
	// pc_flags |= PURPLE_CONNECTION_FLAG_NO_BGCOLOR;
	// purple_connection_set_flags(pc, pc_flags);
	
	bna = g_new0(BattleNetAccount, 1);
	purple_connection_set_protocol_data(pc, bna);
	bna->account = account;
	bna->pc = pc;
	
	bna->token_callbacks = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free); //TODO proper free func
	bna->imported_services = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, (GDestroyNotify) bn_free_service);
	bna->exported_services = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, (GDestroyNotify) bn_free_service);
	
	bna->entity_id_to_battle_tag = g_hash_table_new_full(bn_entity_id_hash, bn_entity_id_equal, g_free, g_free);
	bna->battle_tag_to_entity_id = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	
	
	// Imported services
	service = bn_create_service(bna, "bnet.protocol.authentication.AuthenticationServer");
	bna->services_to_import = g_list_append(bna->services_to_import, service);
	
	service = bn_create_service(bna, "bnet.protocol.challenge.ChallengeService");
	bna->services_to_import = g_list_append(bna->services_to_import, service);
	
	service = bn_create_service(bna, "bnet.protocol.presence.PresenceService");
	bna->services_to_import = g_list_append(bna->services_to_import, service);
	
	service = bn_create_service(bna, "bnet.protocol.friends.FriendsService");
	bna->services_to_import = g_list_append(bna->services_to_import, service);
	
	service = bn_create_service(bna, "bnet.protocol.notification.NotificationService");
	bna->services_to_import = g_list_append(bna->services_to_import, service);
	
	service = bn_create_service(bna, "bnet.protocol.channel_invitation.ChannelInvitationService");
	bna->services_to_import = g_list_append(bna->services_to_import, service);
	
	
	// Exported services
	service = bn_create_service(bna, "bnet.protocol.authentication.AuthenticationClient");
	bn_service_add_method(service, 5, bnet__protocol__authentication__logon_result__descriptor, bn_authentication_logon_result);
	bna->services_to_export = g_list_append(bna->services_to_export, service);
	
	service = bn_create_service(bna, "bnet.protocol.challenge.ChallengeNotify");
	bn_service_add_method(service, 3, bnet__protocol__challenge__challenge_external_request__descriptor, bn_challenge_on_external_challenge);
	bna->services_to_export = g_list_append(bna->services_to_export, service);
	
	service = bn_create_service(bna, "bnet.protocol.account.AccountNotify");
	bna->services_to_export = g_list_append(bna->services_to_export, service);
	
	service = bn_create_service(bna, "bnet.protocol.account.PresenceNotify");
	bna->services_to_export = g_list_append(bna->services_to_export, service);
	
	service = bn_create_service(bna, "bnet.protocol.friends.FriendsNotify");
	bn_service_add_method(service, 1, bnet__protocol__friends__friend_notification__descriptor, bn_friends_on_add);
	bn_service_add_method(service, 3, bnet__protocol__friends__invitation_notification__descriptor, bn_friends_on_invitation);
	bna->services_to_export = g_list_append(bna->services_to_export, service);
	
	service = bn_create_service(bna, "bnet.protocol.channel.ChannelSubscriber");
	bn_service_add_method(service, 1, bnet__protocol__channel__add_notification__descriptor, bn_channel_notify_add);
	bn_service_add_method(service, 6, bnet__protocol__channel__update_channel_state_notification__descriptor, bn_channel_notify_update_channel_state);
	bna->services_to_export = g_list_append(bna->services_to_export, service);
	
	service = bn_create_service(bna, "bnet.protocol.channel_invitation.ChannelInvitationNotify");
	bna->services_to_export = g_list_append(bna->services_to_export, service);
	
	service = bn_create_service(bna, "bnet.protocol.connection.ConnectionService");
	bn_service_add_method(service, 3, bnet__protocol__connection__echo_request__descriptor, bn_connection_handle_echo_request);
	bn_service_add_method(service, 4, bnet__protocol__connection__disconnect_notification__descriptor, bn_connection_handle_force_disconnect_request);
	bna->services_to_export = g_list_append(bna->services_to_export, service);
	
	service = bn_create_service(bna, "bnet.protocol.notification.NotificationListener");
	bn_service_add_method(service, 1, bnet__protocol__notification__notification__descriptor, bn_notification_on_notification_received);
	bna->services_to_export = g_list_append(bna->services_to_export, service);
	
	
	
	
	purple_connection_set_state(pc, PURPLE_CONNECTION_CONNECTING);
	
	bn_connect(bna);
	
	// if (!chat_conversation_typing_signal) {
		// chat_conversation_typing_signal = purple_signal_connect(purple_conversations_get_handle(), "chat-conversation-typing", purple_connection_get_protocol(pc), PURPLE_CALLBACK(rc_conv_send_typing), NULL);
	// }
	// if (!conversation_updated_signal) {
		// conversation_updated_signal = purple_signal_connect(purple_conversations_get_handle(), "conversation-updated", purple_connection_get_protocol(pc), PURPLE_CALLBACK(rc_mark_conv_seen), NULL);
	// }
}


static void 
bn_close(PurpleConnection *pc)
{
	BattleNetAccount *bna = purple_connection_get_protocol_data(pc);
	
	g_return_if_fail(bna != NULL);
	
	if (bna->socket != NULL) purple_ssl_close(bna->socket);
	
	g_hash_table_remove_all(bna->entity_id_to_battle_tag);
	g_hash_table_unref(bna->entity_id_to_battle_tag);
	
	g_hash_table_remove_all(bna->battle_tag_to_entity_id);
	g_hash_table_unref(bna->battle_tag_to_entity_id);
	
	g_hash_table_remove_all(bna->token_callbacks);
	g_hash_table_unref(bna->token_callbacks);
	
	g_hash_table_remove_all(bna->exported_services);
	g_hash_table_unref(bna->exported_services);
	
	g_hash_table_remove_all(bna->imported_services);
	g_hash_table_unref(bna->imported_services);
	
	g_free(bna->frame_header); bna->frame_header = NULL;
	g_free(bna->frame_body); bna->frame_body = NULL;
	
	g_free(bna->account_entity);
	
	g_free(bna);
}





static gboolean
plugin_load(PurplePlugin *plugin, GError **error)
{
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
		//prpl_info->add_buddy_with_invite = bn_add_buddy_with_invite;
	#endif
	
	prpl_info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_SLASH_COMMANDS_NATIVE;
	// prpl_info->protocol_options = bn_add_account_options(prpl_info->protocol_options);
	prpl_info->icon_spec.format = "png,gif,jpeg";
	prpl_info->icon_spec.min_width = 0;
	prpl_info->icon_spec.min_height = 0;
	prpl_info->icon_spec.max_width = 96;
	prpl_info->icon_spec.max_height = 96;
	prpl_info->icon_spec.max_filesize = 0;
	prpl_info->icon_spec.scale_rules = PURPLE_ICON_SCALE_DISPLAY;
	
	// prpl_info->get_account_text_table = bn_get_account_text_table;
	prpl_info->list_icon = bn_list_icon;
	prpl_info->set_status = bn_set_status;
	// prpl_info->set_idle = bn_set_idle;
	prpl_info->status_types = bn_status_types;
	// prpl_info->chat_info = bn_chat_info;
	// prpl_info->chat_info_defaults = bn_chat_info_defaults;
	prpl_info->login = bn_login;
	prpl_info->close = bn_close;
	prpl_info->send_im = bn_send_im;
	prpl_info->send_typing = bn_send_typing;
	// prpl_info->join_chat = bn_join_chat;
	// prpl_info->get_chat_name = bn_get_chat_name;
	// prpl_info->chat_invite = bn_chat_invite;
	// prpl_info->chat_send = bn_chat_send;
	// prpl_info->set_chat_topic = bn_chat_set_topic;
	// prpl_info->add_buddy = bn_add_buddy;
	prpl_info->status_text = bn_status_text;
	
	// prpl_info->roomlist_get_list = bn_roomlist_get_list;
	// prpl_info->roomlist_room_serialize = bn_roomlist_serialize;
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
	BATTLENET_PLUGIN_ID, /* id */
	"Battle.net", /* name */
	BATTLENET_PLUGIN_VERSION, /* version */
	"", /* summary */
	"", /* description */
	"Eion Robb <eion@robbmob.com>", /* author */
	BATTLENET_PLUGIN_WEBSITE, /* homepage */
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

PURPLE_INIT_PLUGIN(battlenet, plugin_init, info);

#else
//Purple 3 plugin load functions


G_MODULE_EXPORT GType bn_protocol_get_type(void);
#define BATTLENET_TYPE_PROTOCOL			(bn_protocol_get_type())
#define BATTLENET_PROTOCOL(obj)			(G_TYPE_CHECK_INSTANCE_CAST((obj), BATTLENET_TYPE_PROTOCOL, BattleNetProtocol))
#define BATTLENET_PROTOCOL_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST((klass), BATTLENET_TYPE_PROTOCOL, BattleNetProtocolClass))
#define BATTLENET_IS_PROTOCOL(obj)			(G_TYPE_CHECK_INSTANCE_TYPE((obj), BATTLENET_TYPE_PROTOCOL))
#define BATTLENET_IS_PROTOCOL_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), BATTLENET_TYPE_PROTOCOL))
#define BATTLENET_PROTOCOL_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS((obj), BATTLENET_TYPE_PROTOCOL, BattleNetProtocolClass))

typedef struct _BattleNetProtocol
{
	PurpleProtocol parent;
} BattleNetProtocol;

typedef struct _BattleNetProtocolClass
{
	PurpleProtocolClass parent_class;
} BattleNetProtocolClass;

static void
bn_protocol_init(PurpleProtocol *prpl_info)
{
	PurpleProtocol *info = prpl_info;
	PurpleAccountUserSplit *split;

	info->id = BATTLENET_PLUGIN_ID;
	info->name = "Battle.net";
	info->options = OPT_PROTO_CHAT_TOPIC | OPT_PROTO_SLASH_COMMANDS_NATIVE;
	info->account_options = bn_add_account_options(info->account_options);
	
	split = purple_account_user_split_new(_("Server"), RC_DEFAULT_SERVER, RC_SERVER_SPLIT_CHAR);
	info->user_splits = g_list_append(info->user_splits, split);
}

static void
bn_protocol_class_init(PurpleProtocolClass *prpl_info)
{
	prpl_info->login = bn_login;
	prpl_info->close = bn_close;
	prpl_info->status_types = bn_status_types;
	prpl_info->list_icon = bn_list_icon;
}

static void 
bn_protocol_im_iface_init(PurpleProtocolIMIface *prpl_info)
{
	prpl_info->send = bn_send_im;
	prpl_info->send_typing = bn_send_typing;
}

static void 
bn_protocol_chat_iface_init(PurpleProtocolChatIface *prpl_info)
{
	prpl_info->send = bn_chat_send;
	prpl_info->info = bn_chat_info;
	prpl_info->info_defaults = bn_chat_info_defaults;
	prpl_info->join = bn_join_chat;
	prpl_info->get_name = bn_get_chat_name;
	prpl_info->invite = bn_chat_invite;
	prpl_info->set_topic = bn_chat_set_topic;
}

static void 
bn_protocol_server_iface_init(PurpleProtocolServerIface *prpl_info)
{
	prpl_info->add_buddy = bn_add_buddy;
	prpl_info->set_status = bn_set_status;
	prpl_info->set_idle = bn_set_idle;
}

static void 
bn_protocol_client_iface_init(PurpleProtocolClientIface *prpl_info)
{
	prpl_info->get_account_text_table = bn_get_account_text_table;
}

static void 
bn_protocol_roomlist_iface_init(PurpleProtocolRoomlistIface *prpl_info)
{
	prpl_info->get_list = bn_roomlist_get_list;
	prpl_info->room_serialize = bn_roomlist_serialize;
}

static PurpleProtocol *bn_protocol;

PURPLE_DEFINE_TYPE_EXTENDED(
	BattleNetProtocol, bn_protocol, PURPLE_TYPE_PROTOCOL, 0,

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_IM_IFACE,
	                                  bn_protocol_im_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CHAT_IFACE,
	                                  bn_protocol_chat_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_SERVER_IFACE,
	                                  bn_protocol_server_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CLIENT_IFACE,
	                                  bn_protocol_client_iface_init)

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_ROOMLIST_IFACE,
	                                  bn_protocol_roomlist_iface_init)

);

static gboolean
libpurple3_plugin_load(PurplePlugin *plugin, GError **error)
{
	bn_protocol_register_type(plugin);
	bn_protocol = purple_protocols_add(BATTLENET_TYPE_PROTOCOL, error);
	if (!bn_protocol)
		return FALSE;

	return plugin_load(plugin, error);
}

static gboolean
libpurple3_plugin_unload(PurplePlugin *plugin, GError **error)
{
	if (!plugin_unload(plugin, error))
		return FALSE;

	if (!purple_protocols_remove(bn_protocol, error))
		return FALSE;

	return TRUE;
}

static PurplePluginInfo *
plugin_query(GError **error)
{
	return purple_plugin_info_new(
		"id",          BATTLENET_PLUGIN_ID,
		"name",        "Battle.net",
		"version",     BATTLENET_PLUGIN_VERSION,
		"category",    N_("Protocol"),
		"summary",     N_("Battle.net Protocol Plugins."),
		"description", N_("Adds Battle.net protocol support to libpurple."),
		"website",     BATTLENET_PLUGIN_WEBSITE,
		"abi-version", PURPLE_ABI_VERSION,
		"flags",       PURPLE_PLUGIN_INFO_FLAGS_INTERNAL |
		               PURPLE_PLUGIN_INFO_FLAGS_AUTO_LOAD,
		NULL
	);
}

PURPLE_PLUGIN_INIT(battlenet, plugin_query, libpurple3_plugin_load, libpurple3_plugin_unload);

#endif
