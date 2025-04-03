use alloc::string::ToString;
use core::mem::size_of;

use super::{
    retcode::*,
    osutil::*, map::{bpf_map_lookup_elem, bpf_map_update_elem, bpf_map_delete_elem},
};

extern "C" {
    fn stext();
    fn etext();
    fn sstack();
}

pub type BpfHelperFn = fn(u64, u64, u64, u64, u64) -> i64;

pub const HELPER_FN_COUNT: usize = 18;
pub static HELPER_FN_TABLE: [BpfHelperFn; HELPER_FN_COUNT] = [
    bpf_helper_nop,
    bpf_helper_map_lookup_elem,
    bpf_helper_map_update_elem,
    bpf_helper_map_delete_elem,
    bpf_helper_probe_read,
    bpf_helper_ktime_get_ns,
    bpf_helper_trace_printk,
    bpf_helper_get_prandom_u32,
    bpf_helper_get_smp_processor_id,
    bpf_helper_nop, // bpf_skb_store_bytes
    bpf_helper_nop, // bpf_l3_csum_replace
    bpf_helper_nop, // bpf_l4_csum_replace
    bpf_helper_nop, // bpf_tail_call
    bpf_helper_nop, // bpf_clone_redirect
    bpf_helper_get_current_pid_tgid,
    bpf_helper_nop, // bpf_get_current_uid_gid
    bpf_helper_get_current_comm,
    bpf_helper_get_depth
];

// WARNING: be careful to use bpf_probe_read, bpf_get_current_pid_tgid & bpf_get_current_comm
// in syscall contexts. obtaining current process information may cause deadlock!

fn bpf_helper_map_lookup_elem(fd: u64, key: u64, value: u64, _4: u64, _5: u64) -> i64 {
    match bpf_map_lookup_elem(fd as u32, key as *const u8, value as *mut u8, 0) {
        Ok(val) => val as i64,
        Err(_) => -1
    }
}
fn bpf_helper_map_update_elem(fd: u64, key: u64, value: u64, flags: u64, _5: u64) -> i64 {
    match bpf_map_update_elem(fd as u32, key as *const u8, value as *mut u8, flags) {
        Ok(val) => val as i64,
        Err(_) => -1
    }
}
fn bpf_helper_map_delete_elem(fd: u64, key: u64, _3: u64, _4: u64, _5: u64) -> i64 {
    match bpf_map_delete_elem(fd as u32, key as *const u8, 0 as *mut u8, 0) {
        Ok(val) => val as i64,
        Err(_) => -1
    }
}

fn bpf_helper_nop(_1: u64, _2: u64, _3: u64, _4: u64, _5: u64) -> i64 {
    0
}

fn probe_read_user(_dst: *mut u8, _src: *const u8, _len: usize) -> BpfResult {
    // let thread = current_thread().unwrap();
    // let vm = thread.vm.lock();
    // let src_slice = unsafe { vm.check_read_array(src, len)? };
    // let dst_slice = unsafe { core::slice::from_raw_parts_mut(dst, len) };
    // dst_slice.copy_from_slice(src_slice);
    // Ok(0)
    todo!()
}

// long bpf_probe_read(void *dst, u32 size, const void *unsafe_ptr)
fn bpf_helper_probe_read(_dst: u64, _size: u64, _src: u64, _1: u64, _2: u64) -> i64 {
    // let src_addr = src as usize;
    // let dst_addr = dst as usize;
    // let len = size as usize;

    // use crate::arch::consts::KERNEL_OFFSET;
    // if src_addr >= KERNEL_OFFSET {
    //     // this is probably a kernel address
    //     // WARNING: this may cause kernel crash!
    //     let src_slice = unsafe { core::slice::from_raw_parts(src_addr as *const u8, len) };
    //     let dst_slice = unsafe { core::slice::from_raw_parts_mut(dst_addr as *mut u8, len) };
    //     dst_slice.copy_from_slice(src_slice);
    //     0
    // } else {
    //     let res = probe_read_user(dst_addr as *mut u8, src_addr as *const u8, len);
    //     convert_result(res)
    // }
    todo!()
}

// u64 bpf_ktime_get_ns(void)
// return current ktime
fn bpf_helper_ktime_get_ns(_1: u64, _2: u64, _3: u64, _4: u64, _5: u64) -> i64 {
    os_current_time() as i64
}

// long bpf_trace_printk(const char *fmt, u32 fmt_size, ...)
fn bpf_helper_trace_printk(fmt: u64, fmt_size: u64, p1: u64, p2: u64, p3: u64) -> i64 {
    // // TODO: check pointer
    let fmt = unsafe { core::slice::from_raw_parts(fmt as *const u8, fmt_size as u32 as usize) };
    
    let output = dyn_fmt::Arguments::new(
        unsafe { core::str::from_utf8_unchecked(fmt) },
        &[p1, p2, p3]
    ).to_string();

    kernel_hal::console::console_write_str(output.as_str());
    0 // TODO: return number of bytes written
}

fn bpf_helper_get_prandom_u32(_1: u64, _2: u64, _3: u64, _4: u64, _5: u64) -> i64 {
    todo!()
}

fn bpf_helper_get_smp_processor_id(_1: u64, _2: u64, _3: u64, _4: u64, _5: u64) -> i64 {
    os_get_current_cpu() as i64
}

fn bpf_helper_get_current_pid_tgid(_1: u64, _2: u64, _3: u64, _4: u64, _5: u64) -> i64 {
    let thread = match os_current_thread() {
        Some(thread) => thread,
        None => return -1,
    };
    let pid = thread.get_pid();
    // NOTE: tgid is the same with pid
    ((pid << 32) | pid) as i64
}

fn bpf_helper_get_current_comm(dst: u64, buf_size: u64, _1: u64, _2: u64, _3: u64) -> i64 {
    let thread = os_current_thread().unwrap();
    let dst_ptr = dst as *mut u8;
    let name = thread.get_name();
    let name_ptr = name.as_bytes();
    let len = name.len();
    if len > buf_size as usize {
        return -1;
    }
    unsafe {
        let dst_slice = core::slice::from_raw_parts_mut(dst_ptr, len);
        dst_slice.copy_from_slice(name_ptr);
        *dst_ptr.add(len) = 0;
    }
    len as i64
}

fn bpf_helper_get_depth(current_pc: u64, current_fp: u64, _3: u64, _4: u64, _5: u64) -> i64 {
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    unsafe {
        let mut current_pc = current_pc as usize;
        let mut current_fp = current_fp as usize;
        let mut trace_pc = vec!();

        while current_pc >= stext as usize
            && current_pc <= etext as usize
            && current_fp as usize != 0
        {

            trace_pc.push(current_pc - size_of::<usize>());
            #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
            {
                current_fp = *(current_fp as *const usize).offset(-2);
                // raw address 0x803ba000 appeared in the backtrace and I don't know why, traced into bootloading phase?
                if current_fp < sstack as usize {
                    break;
                }
                current_pc = *(current_fp as *const usize).offset(-1);
            }
        }
        return (trace_pc.len()-1) as i64;
    }
}
