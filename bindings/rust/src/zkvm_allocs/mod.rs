extern crate alloc;

use alloc::alloc::{alloc, alloc_zeroed, dealloc, handle_alloc_error, Layout};
use core::ffi::c_void;
use core::mem;

const LEN_SIZE: usize = mem::size_of::<usize>();

unsafe fn store_len(block_ptr: *mut u8, size: usize) -> *mut u8 {
    let len_ptr = block_ptr as *mut usize;
    *len_ptr = size;
    block_ptr.add(LEN_SIZE)
}

unsafe fn get_len(block_ptr: *mut u8) -> (usize, *mut u8) {
    let len_ptr = block_ptr.sub(LEN_SIZE) as *mut usize;
    (*len_ptr, len_ptr as *mut u8)
}

#[no_mangle]
pub unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    let layout =
        Layout::from_size_align(size + LEN_SIZE, 4).expect("unable to construct memory layout");
    let block_ptr = alloc(layout);
    if block_ptr.is_null() {
        handle_alloc_error(layout);
    }
    store_len(block_ptr, size) as *mut c_void
}

#[no_mangle]
pub unsafe extern "C" fn calloc(nobj: usize, size: usize) -> *mut c_void {
    let size = nobj * size;
    let layout =
        Layout::from_size_align(size + LEN_SIZE, 4).expect("unable to construct memory layout");
    let block_ptr = alloc_zeroed(layout);
    if block_ptr.is_null() {
        handle_alloc_error(layout);
    }
    store_len(block_ptr, size) as *mut c_void
}

#[no_mangle]
pub unsafe extern "C" fn free(ptr: *const c_void) {
    if ptr.is_null() {
        return;
    }
    let (size, base_ptr) = get_len(ptr as *mut u8);
    let layout =
        Layout::from_size_align(size + LEN_SIZE, 4).expect("unable to construct memory layout");
    dealloc(base_ptr, layout);
}
