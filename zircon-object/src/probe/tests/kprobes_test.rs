// WARNING: riscv only!
use super::kprobes::{register_kprobe, register_kprobe_with_symbol};
use core::slice::from_raw_parts;
use core::arch::global_asm;
use alloc::sync::Arc;
use super::{KProbeArgs, TrapFrame};
use crate::symbol::{symbol_table_with};

#[no_mangle]
pub extern "C" fn kprobes_test_ok(i: usize) {
    info!("[Kprobes test] {} OK", i);
}

extern "C" {
    fn kprobes_test_fn_count(); // *i32
    fn kprobes_test_fns(); // *u64
    fn kprobes_test_probe_points(); // *u64
}

fn test_pre_handler(tf: &mut TrapFrame, _data: usize) -> isize {
    let pc = tf.sepc;
    symbol_table_with(|table| {
        let (name, addr) = table.find_symbol(pc).unwrap_or(("unknown", 0));
        warn!("[KPROBE_PRE_HANDLER] entering fn {}, addr = {:#x}, pc = {:#x}", name, addr, pc);
    });
    0
}

fn test_post_handler(_tf: &mut TrapFrame, _data: usize) -> isize {
    warn!("[KPROBE_POST_HANDLER] post handler invoked");
    0
}

pub fn run_kprobes_tests() {
    info!("running kprobes tests");
    unsafe {
        let nr_tests = *(kprobes_test_fn_count as *const i32) as usize;
        let test_fns = from_raw_parts(kprobes_test_fns as *const fn(usize), nr_tests);
        let probes = from_raw_parts(kprobes_test_probe_points as *const usize, nr_tests);

        for (i, &f) in test_fns.iter().enumerate() {
            register_kprobe(probes[i], KProbeArgs {
                pre_handler: Arc::new(test_pre_handler),
                post_handler: Some(Arc::new(test_post_handler)),
                user_data: 0,
            });
            f(0);
        }
    }
    info!("kprobes tests finished");
    register_kprobe_with_symbol("linux_syscall::file::dir::<impl linux_syscall::Syscall>::sys_mkdirat",
     KProbeArgs {
        pre_handler: Arc::new(test_pre_handler),
        post_handler: Some(Arc::new(test_post_handler)),
        user_data: 0,
    });
    panic!("kprobes test finished");
}

global_asm!(include_str!("test.S"));
