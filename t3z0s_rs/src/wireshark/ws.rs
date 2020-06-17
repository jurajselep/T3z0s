use libc::{c_char, c_int, c_uint};

// Opaque structs from Wireshark
#[repr(C)] pub struct tvbuff_t { _private: [u8; 0] }
#[repr(C)] pub struct tcp_analysis { _private: [u8; 0] }
#[repr(C)] pub struct proto_item { _private: [u8; 0] }
#[repr(C)] pub struct proto_tree { _private: [u8; 0] }
#[repr(C)] pub struct wmem_allocator_t { _private: [u8; 0] }

// Functions from Wireshark that are used by this dissector
extern "C" {
    fn tvb_get_guint8(tvb: *mut tvbuff_t, offset: c_int /* gint */) -> u8;
    fn tvb_get_ptr(tvb: *mut tvbuff_t, offset: c_int /* gint */, length: c_int /* gint */) -> *mut u8;
    fn tvb_captured_length(tvb: *mut tvbuff_t) -> c_uint /* guint */;
    fn tvb_captured_length_remaining(tvb: *mut tvbuff_t) -> c_uint /* guint */;
    fn wmem_packet_scope() -> *mut wmem_allocator_t;
    fn proto_tree_add_int64(
        proto_tree: *mut proto_tree,
        hfindex : c_int,
        tvb: *mut tvbuff_t,
        start: c_int,
        length: c_int,
        value: i64
    ) -> *mut proto_item;
    fn proto_tree_add_item_ret_string_and_length(
        proto_tree: *mut proto_tree,
        hfindex : c_int,
        tvb: *mut tvbuff_t,
        start: c_int,
        length: c_int,
        encoding: c_uint,
        scope: *mut wmem_allocator_t,
        retval: *mut *const u8,
        lenretval: *mut c_uint
    );
    fn proto_tree_add_string_format_value(
        proto_tree: *mut proto_tree,
        hfindex : c_int,
        tvb: *mut tvbuff_t,
        start: c_int,
        length: c_int,
        value: *const c_char,
        format: *const c_char,
        ...
    );
}

pub(crate) fn tvb_get_guint8_safe(tvb: *mut tvbuff_t, offset: c_int /* gint */) -> u8 {
    unsafe { tvb_get_guint8(tvb, offset) }
}

pub(crate) fn tvb_captured_length_safe(tvb: *mut tvbuff_t) -> c_uint {
    unsafe { tvb_captured_length(tvb) }
}

pub(crate) fn tvb_captured_length_remaining_safe(tvb: *mut tvbuff_t) -> c_uint {
    unsafe { tvb_captured_length_remaining(tvb) }
}

pub(crate) fn proto_tree_add_int64_safe(
    proto_tree: *mut proto_tree,
    hfindex : c_int,
    tvb: *mut tvbuff_t,
    start: c_int,
    length: c_int,
    value: i64
) -> *mut proto_item {
    unsafe { proto_tree_add_int64(proto_tree, hfindex, tvb, start, length, value) }
}

pub(crate) fn proto_tree_add_item_safe(
        proto_tree: *mut proto_tree,
        hfindex : c_int,
        tvb: *mut tvbuff_t,
        start: c_int,
        length: c_int,
        encoding: c_uint,
) {
    unsafe {
        let mut str: *const u8 = std::ptr::null_mut();
        let mut len: c_uint = 0;

        proto_tree_add_item_ret_string_and_length(
            proto_tree,
            hfindex,
            tvb,
            start,
            length,
            encoding,
            wmem_packet_scope(),
            &mut str,
            &mut len
        );
    }
}

pub(crate) fn proto_tree_add_string_safe(
        proto_tree: *mut proto_tree,
        hfindex : c_int,
        tvb: *mut tvbuff_t,
        start: c_int,
        length: c_int,
        value: String,
) {
    unsafe {
        let bytes_num = value.len();
        let b = value.as_bytes();

        proto_tree_add_string_format_value(
            proto_tree,
            hfindex,
            tvb,
            start,
            length,
            b.as_ptr() as *const c_char,
            b"%.*s\0".as_ptr() as *const c_char,
            bytes_num as c_int,
            b.as_ptr() as *const c_char,
        );
    }
}

pub(crate) fn get_data_safe<'a>(tvb: *mut tvbuff_t) -> &'a [u8] {
    unsafe {
        let ptr = tvb_get_ptr(tvb, 0, -1);
        let ulen = tvb_captured_length_remaining(tvb);
        // According to Wireshark documentation:
        //   https://www.wireshark.org/docs/wsar_html/group__tvbuff.html#ga31ba5c32b147f1f1e57dc8326e6fdc21
        // `get_raw_ptr()` should not be used, but it looks as easiest solution here.
        std::slice::from_raw_parts(
            ptr,
            ulen as usize)
    }
}
