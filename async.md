How to Run
=====================
0. setup environment. see <https://livingshade.github.io/ebpf-doc/zcore/> for detail. NOTE: download clang-**12** at <https://github.com/llvm/llvm-project/releases/tag/llvmorg-12.0.1>
1. install `rustfilt` and `grep`
2. cd zCore && cargo clean
3. cargo other-test --arch=riscv64
4. rm async.log
5. cargo qemu --arch=riscv64 | tee >(sed $'s/\033[[][^A-Za-z]*[A-Za-z]//g' > async.log)
6. python3 dump.py > dumped_data.txt




How it works
======================
A. [host C program + system] probe at those patterns, both entry and exit (they are all patters of function names)
    1. `"_<async_std..task..builder..SupportTaskLocals<F> as core..future..future..Future>::poll::_{{closure}}"`
    2. `"_<core..future..from_generator..GenFuture<T> as core..future..future..Future>::poll"`
    3. `".*::_\{\{closure\}\}"`
    4. `".*as core..future..future..Future>::poll"`

B. [bpf program] when such functions entered/exited, collect timestamp(like 408.532238273), function depth and thread id

C. [bpf program] output a record file called dumped_data.txt like this
reading {thread id}.dat
timestamp   {thread id}: [entry/exit] {function name}(function address) depth: {depth}

example of such record file:
reading 5257.dat
408.532238273   5257: [entry] std::rt::lang_start::_{{closure}}(636a04ffabb5) depth: 0
408.532242401   5257: [entry] once_cell::imp::initialize_or_wait::_{{closure}}(636a05068c15) depth: 1
408.532243204   5257: [exit ] once_cell::imp::initialize_or_wait::_{{closure}}(636a05068c15) depth: 1

D. [tool from the paper] post-process, see paper