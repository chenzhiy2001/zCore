
set -x
set -e

cur=$(pwd)

if ! command -v clang-12 &> /dev/null
then
    echo "clang-12 could not be found"
    exit -1
fi

pushd ./linux-syscall/test/ebpf/kern

make

popd 

# very dirty work...

cp -r "./linux-syscall/test/ebpf/kern/map.o" "./rootfs/riscv64/bin/" 
cp -r "./linux-syscall/test/ebpf/kern/context.o" "./rootfs/riscv64/bin/" 
cp -r "./linux-syscall/test/ebpf/kern/time1.o" "./rootfs/riscv64/bin/" 
cp -r "./linux-syscall/test/ebpf/kern/async-fn-context.o" "./rootfs/riscv64/bin/" 
cp -r "./linux-syscall/test/ebpf/kern/time2.o" "./rootfs/riscv64/bin/" 

exit 0