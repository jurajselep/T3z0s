// https://www.wireshark.org/docs/wsdg_html_chunked/ChDissectAdd.html

#include "config.h"
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <stdio.h>

// Simple logger for development
#define MSG(format, ...) \
    do { \
        FILE *f = fopen("/tmp/xyz.log", "a"); \
        if (f != NULL) fprintf(f, "C: " format, __VA_ARGS__); \
        fclose(f); \
    } while (0)

/* This is shared with Rust */

struct T3zosDissectorInfo {
    int hf_payload_len;
    int hf_packet_counter;
    int hf_connection_msg;
    int hf_decrypted_msg;
    int hf_error;

    int hf_debug;
};

extern int t3z03s_dissect_packet(struct T3zosDissectorInfo*, tvbuff_t*, proto_tree*, const packet_info*, const struct tcp_analysis*);
extern int t3z03s_free_conv_data(void*);
extern void tezos_preferences_update(const char* identity_json_filepath);

/* End of section shared with Rust */

static dissector_handle_t tezos_handle;
static int proto_tezos = -1;
static struct T3zosDissectorInfo info = {
    -1, -1, -1, -1, -1,
    -1,
};
static gint ett_tezos = -1; // Subtree

static gboolean wmem_cb(wmem_allocator_t* allocator, wmem_cb_event_t ev, void *data)
{
    switch (ev) {
        case WMEM_CB_FREE_EVENT:
            break;
        case WMEM_CB_DESTROY_EVENT:
            DISSECTOR_ASSERT_NOT_REACHED();
            break;
    }

    MSG("Freeing memory allocator: %p %p\n", allocator, data);
    t3z03s_free_conv_data(data);

    return FALSE;
}

static const char* identity_json_filepath;
static void preferences_update_cb(void)
{
    tezos_preferences_update(identity_json_filepath);
}

static void register_user_preferences(void)
{
    module_t *tcp_module = prefs_register_protocol(proto_tezos, preferences_update_cb);
    prefs_register_filename_preference(tcp_module, "identity_json_file",
        "Identity JSON file",
        "JSON file with node identity information",
        &identity_json_filepath, FALSE);
}

/** An old style dissector proxy.
 *
 * Proxies the old style dissector interface to the new style.
 */
static
int dissect_tezos_old(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    (void)data;
    conversation_t *conv = find_or_create_conversation(pinfo);
    DISSECTOR_ASSERT_HINT(conv, "find_or_create_conversation() returned NULL");

    struct tcp_analysis *tcpd = get_tcp_conversation_data(conv, pinfo);
    void *convd = conversation_get_proto_data(conv, proto_tezos);
    if (!convd)
    {
        conversation_add_proto_data(conv, proto_tezos, (void*)0x1);
        wmem_register_callback(wmem_file_scope(), wmem_cb, tcpd);
    }

    proto_item *ti = proto_tree_add_item(tree, proto_tezos, tvb, 0, -1, ENC_NA);
    proto_tree *t_tree = proto_item_add_subtree(ti, ett_tezos);
    proto_tree_add_int64_format(t_tree, info.hf_payload_len, tvb, 0, 0, (int64_t)conv, "Tezos conversation: %p", conv); // XYZ: Dbg.
    MSG("conv: %p %p\n", wmem_file_scope(), conv);
    return t3z03s_dissect_packet(&info, tvb, t_tree, pinfo, tcpd);
}

static gboolean
dissect_tezos(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    conversation_t *conv = NULL;

	/*** It's ours! ***/
	conv = find_or_create_conversation(pinfo);
	/* Mark it as ours. */
    conversation_set_dissector(conv, tezos_handle);

    (void)dissect_tezos_old(tvb, pinfo, tree, data);

    return TRUE;
}

void
proto_register_tezos(void)
{
    static hf_register_info hf[] = {
        { &info.hf_packet_counter,
            { "Tezos Packet Counter", "tezos.packet_counter",
            FT_INT64, BASE_DEC,
            NULL, 0x0, NULL, HFILL }
        },
        { &info.hf_payload_len,
            { "Tezos Payload Length", "tezos.payload_len",
            FT_INT64, BASE_DEC,
            NULL, 0x0, NULL, HFILL }
        },
        { &info.hf_connection_msg,
            { "Tezos Connection Msg", "tezos.connection_msg",
            FT_STRING, BASE_NONE,
            NULL, 0x0, NULL, HFILL }
        },
        { &info.hf_decrypted_msg,
            { "Tezos Decrypted Msg", "tezos.decrypted_msg",
            FT_STRING, BASE_NONE,
            NULL, 0x0, NULL, HFILL }
        },
        { &info.hf_error,
            { "Tezos Error", "tezos.error",
            FT_STRING, BASE_NONE,
            NULL, 0x0, NULL, HFILL }
        },
        { &info.hf_debug,
            { "Tezos Debug", "tezos.debug",
            FT_STRING, BASE_NONE,
            NULL, 0x0, NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_tezos
    };

    proto_tezos = proto_register_protocol (
        "Tezos Protocol", /* name        */
        "tezos",          /* short name  */
        "tezos"           /* filter_name */
        );

    proto_register_field_array(proto_tezos, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_user_preferences();
}

void
proto_reg_handoff_tezos(void)
{
    tezos_handle = create_dissector_handle(dissect_tezos_old, proto_tezos);
    heur_dissector_add("tcp", dissect_tezos, "Tezos", "tezos_tcp", proto_tezos, HEURISTIC_ENABLE);
}