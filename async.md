How to Run
=====================
0. git clone https://github.com/chenzhiy2001/zCore

1. setup environment.

	- cd zCore
	- see <https://livingshade.github.io/ebpf-doc/zcore/> dependencies part for detail. 

	NOTE: download clang-**12** at <https://github.com/llvm/llvm-project/releases/tag/llvmorg-12.0.1>

2. install `rustfilt` and `grep`

3. cd zCore && cargo clean

4. cargo other-test --arch=riscv64

5. rm async.log

6. cargo qemu --arch=riscv64 | tee >(sed $'s/\033[[][^A-Za-z]*[A-Za-z]//g' > async.log)

7. python3 dump.py

8. put  output.json  into https://ui.perfetto.dev/ to get the flame graph

	NOTE: If encounter symbol table related problem during the reproduction process, you can refer to [this student's reproduction log](https://github.com/Irissssaa/code-debug_Asynchronous-trace/discussions/10)





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


FAQ
=============
```
Python Exception <class 'gdb.error'>: That operation is not available on integers of more than 8 bytes.
Error occurred in Python: That operation is not available on integers of more than 8 bytes.
```
It's a GDB bug fixed recently. See https://github.com/pwndbg/pwndbg/issues/2080. 

Download the patch at https://sourceware.org/git/?p=binutils-gdb.git;a=patch;h=6eb63917ce17236f0189e8d7ff4b60e24741770b

Then in riscv-gnu-toolchain/gdb, do `git apply <your_patch_file>`

If the patch failed, you need to update GDB to the newest version.

If you obtain GDB from `riscv-collab/riscv-gnu-toolchain` and failed updating submodules using `sudo git submodule update --remote`, you have to DELETE LOCAL REPO and do this
```
 # you must delete the original repo 
 rm -rf riscv-gnu-toolchain/
 git clone https://github.com/riscv-collab/riscv-gnu-toolchain
 cd riscv-gnu-toolchain/
 sed -i '/shallow = true/d' .gitmodules
 sed -i 's/--depth 1//g' Makefile.in
 ./configure --prefix=/opt/riscv
 sudo make
 sudo git submodule update --remote
 ./configure --prefix=/opt/riscv
 sudo make
```
this painful process is caused by a bug of riscv toolchain repo. see https://github.com/riscv-collab/riscv-gnu-toolchain/issues/1669

If cloning the `riscv-collab/riscv-gnu-toolchain` repo become slow when using a proxy, try TUN mode instead of system proxy/PAC mode and use nodes in the United States (where gcc source code repo is located).
