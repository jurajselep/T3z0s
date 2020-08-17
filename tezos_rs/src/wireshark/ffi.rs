// Functions and structures from Wireshark that are used by the dissector and
// that are not imported automatically by bindgen.

use crate::wireshark::packet::proto_item;
use crate::wireshark::packet::wmem_allocator_t;
use libc::{c_char, c_int, c_uint};

/// Opaque struct from Wireshark
#[repr(C)]
pub struct tvbuff_t {
    _private: [u8; 0],
}

/// Opaque struct from Wireshark
#[repr(C)]
pub struct tcp_analysis {
    _private: [u8; 0],
}

/// Opaque struct from Wireshark
#[repr(C)]
pub struct proto_tree {
    _private: [u8; 0],
}

// Functions from Wireshark.
// tvb_ -- Functions for getting informations from packet buffer.
//         See wireshark/epan/tvbuff.h.
//         tvb means packet buffer.
// proto_tree_ -- Manipulates with the tree that represents dissected frame (packet).
//                See wireshark/epan/proto.h.
//                proto_tree means tree-like structure that visualizes the parts of
//                dissected packet in wireshark interface.
extern "C" {
    pub(super) fn tvb_get_guint8(tvb: *mut tvbuff_t, offset: c_int /* gint */) -> u8;
    pub(super) fn tvb_get_ptr(
        tvb: *mut tvbuff_t,
        offset: c_int, /* gint */
        length: c_int, /* gint */
    ) -> *mut u8;
    pub(super) fn tvb_captured_length(tvb: *mut tvbuff_t) -> c_uint /* guint */;
    pub(super) fn tvb_captured_length_remaining(tvb: *mut tvbuff_t) -> c_uint /* guint */;
    pub(super) fn wmem_packet_scope() -> *mut wmem_allocator_t;
    pub(super) fn proto_tree_add_int64(
        proto_tree: *mut proto_tree,
        hfindex: c_int,
        tvb: *mut tvbuff_t,
        start: c_int,
        length: c_int,
        value: i64,
    ) -> *mut proto_item;
    pub(super) fn proto_tree_add_item_ret_string_and_length(
        proto_tree: *mut proto_tree,
        hfindex: c_int,
        tvb: *mut tvbuff_t,
        start: c_int,
        length: c_int,
        encoding: c_uint,
        scope: *mut wmem_allocator_t,
        retval: *mut *const u8,
        lenretval: *mut c_uint,
    );
    pub(super) fn proto_tree_add_string_format(
        proto_tree: *mut proto_tree,
        hfindex: c_int,
        tvb: *mut tvbuff_t,
        start: c_int,
        length: c_int,
        value: *const c_char,
        format: *const c_char,
        ...
    );
    pub(super) fn proto_tree_add_string_format_value(
        proto_tree: *mut proto_tree,
        hfindex: c_int,
        tvb: *mut tvbuff_t,
        start: c_int,
        length: c_int,
        value: *const c_char,
        format: *const c_char,
        ...
    );
}
