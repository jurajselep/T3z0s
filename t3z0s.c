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
extern void t3z0s_preferences_update(const char* identity_json_filepath);

/* End of section shared with Rust */

static dissector_handle_t t3z0s_handle;
static int proto_t3z0s = -1;
static struct T3zosDissectorInfo info = {
    -1, -1, -1, -1, -1,
    -1,
};
static gint ett_t3z0s = -1; // Subtree

static gboolean wmem_cb(wmem_allocator_t* allocator, wmem_cb_event_t ev, void *data)
{
    switch (ev) {
        case WMEM_CB_FREE_EVENT:
            MSG("Freeing memory allocator: %p %p\n", allocator, data);
            t3z03s_free_conv_data(data);
            break;
        case WMEM_CB_DESTROY_EVENT:
            MSG("destroy: %p\n", allocator);
            break;
    }

    return TRUE;
}

static const char* identity_json_filepath;
static void preferences_update_cb(void)
{
    t3z0s_preferences_update(identity_json_filepath);
}

static void register_user_preferences(void)
{
    module_t *tcp_module = prefs_register_protocol(proto_t3z0s, preferences_update_cb);
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
int dissect_t3z0s_old(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    (void)data;
    conversation_t *conv = find_or_create_conversation(pinfo);
    DISSECTOR_ASSERT_HINT(conv, "find_or_create_conversation() returned NULL");

    struct tcp_analysis *tcpd = get_tcp_conversation_data(conv, pinfo);
    void *convd = conversation_get_proto_data(conv, proto_t3z0s);
    if (!convd)
    {
        conversation_add_proto_data(conv, proto_t3z0s, (void*)0x1);
        wmem_register_callback(wmem_file_scope(), wmem_cb, tcpd);
    }

    proto_item *ti = proto_tree_add_item(tree, proto_t3z0s, tvb, 0, -1, ENC_NA);
    proto_tree *t_tree = proto_item_add_subtree(ti, ett_t3z0s);
    proto_tree_add_int64_format(t_tree, info.hf_payload_len, tvb, 0, 0, (int64_t)conv, "T3z0s conversation: %p", conv); // XYZ: Dbg.
    MSG("conv: %p %p\n", wmem_file_scope(), conv);
    return t3z03s_dissect_packet(&info, tvb, t_tree, pinfo, tcpd);
}

static gboolean
dissect_t3z0s(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    conversation_t *conv = NULL;

	/*** It's ours! ***/
	conv = find_or_create_conversation(pinfo);
	/* Mark it as ours. */
    conversation_set_dissector(conv, t3z0s_handle);

    (void)dissect_t3z0s_old(tvb, pinfo, tree, data);

    return TRUE;
}

void
proto_register_t3z0s(void)
{
    static hf_register_info hf[] = {
        { &info.hf_packet_counter,
            { "T3z0s Packet Counter", "t3z0s.packet_counter",
            FT_INT64, BASE_DEC,
            NULL, 0x0, NULL, HFILL }
        },
        { &info.hf_payload_len,
            { "T3z0s Payload Length", "t3z0s.payload_len",
            FT_INT64, BASE_DEC,
            NULL, 0x0, NULL, HFILL }
        },
        { &info.hf_connection_msg,
            { "T3z0s Connection Msg", "t3z0s.connection_msg",
            FT_STRING, BASE_NONE,
            NULL, 0x0, NULL, HFILL }
        },
        { &info.hf_decrypted_msg,
            { "T3z0s Decrypted Msg", "t3z0s.decrypted_msg",
            FT_STRING, BASE_NONE,
            NULL, 0x0, NULL, HFILL }
        },
        { &info.hf_error,
            { "T3z0s Error", "t3z0s.error",
            FT_STRING, BASE_NONE,
            NULL, 0x0, NULL, HFILL }
        },
        { &info.hf_debug,
            { "T3z0s Debug", "t3z0s.debug",
            FT_STRING, BASE_NONE,
            NULL, 0x0, NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_t3z0s
    };

    proto_t3z0s = proto_register_protocol (
        "T3z0s Protocol", /* name        */
        "t3z0s",          /* short name  */
        "t3z0s"           /* filter_name */
        );

    proto_register_field_array(proto_t3z0s, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_user_preferences();
}

void
proto_reg_handoff_t3z0s(void)
{
    t3z0s_handle = create_dissector_handle(dissect_t3z0s_old, proto_t3z0s);
    heur_dissector_add("tcp", dissect_t3z0s, "T3z0s", "t3z0s_tcp", proto_t3z0s, HEURISTIC_ENABLE);
    // dissector_add_uint("udp.port", 1024, t3z0s_handle);
    // dissector_add_uint("tcp.port", 1024, t3z0s_handle);
    // dissector_add_string("t3z0s.tun_node", "tun0", t3z0s_handle);
    // dissector_add_string("t3z0s.tun_proxy", "tun1", t3z0s_handle);
    // dissector_add_string("t3z0s.identity_file", "identity.json", t3z0s_handle);
}