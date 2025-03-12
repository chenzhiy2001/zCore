%.o: %.c
	clang-12 -target bpf -g -O1 -c -o $@ $<

all: context.o map.o time1.o async-fn-context.o
