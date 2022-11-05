use crate::context::TrapReason;
use crate::thread::{get_current_thread, set_current_thread};
use crate::IpiReason;
use alloc::vec::Vec;
use riscv::register::scause;
use trapframe::TrapFrame;
pub(super) const SUPERVISOR_TIMER_INT_VEC: usize = 5; // scause::Interrupt::SupervisorTimer

pub(super) fn super_timer() {
    super::timer::timer_set_next();
    crate::timer::timer_tick();
    //发生外界中断时，epc的指令还没有执行，故无需修改epc到下一条
}

pub(super) fn super_soft() {
    #[allow(deprecated)]
    sbi_rt::legacy::clear_ipi();
    let reasons: Vec<IpiReason> = crate::interrupt::ipi_reason()
        .iter()
        .map(|x| IpiReason::from(*x))
        .collect();
    debug!("Interrupt::SupervisorSoft, reason = {:?}", reasons);
}

extern "C" {
    fn kprobes_breakpoint_handler(tf: &mut TrapFrame);
}

#[no_mangle]
pub extern "C" fn trap_handler(tf: &mut TrapFrame) {
    let scause = scause::read();
    trace!("kernel trap happened: {:?}", TrapReason::from(scause));
    trace!(
        "sepc = 0x{:x} pgtoken = 0x{:x}",
        tf.sepc,
        crate::vm::current_vmtoken()
    );
    match TrapReason::from(scause) {
        TrapReason::SoftwareBreakpoint => unsafe{ kprobes_breakpoint_handler(tf) },
        TrapReason::PageFault(vaddr, flags) => crate::KHANDLER.handle_page_fault(vaddr, flags),
        TrapReason::Interrupt(vector) => {
            crate::interrupt::handle_irq(vector);
            if vector == SUPERVISOR_TIMER_INT_VEC {
                let current_thread = get_current_thread();
                set_current_thread(None);
                executor::handle_timeout();
                set_current_thread(current_thread);
            }
        }
        other => panic!("Undefined trap: {:x?} {:#x?}", other, tf),
    }
}
