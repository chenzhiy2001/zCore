tmux new-session -d "cargo qemu --arch riscv64 --gdb 1234"
sleep 30s
tmux split-window -h "riscv64-unknown-elf-gdb -ex 'file ./target/riscv64/release/zcore' -ex 'set arch riscv:rv64' -ex 'target remote localhost:1234'"
tmux -2 attach-session -d