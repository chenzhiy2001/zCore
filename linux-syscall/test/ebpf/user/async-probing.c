#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <syscall.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <string.h>
#include "bpf.h"

int main() {

    struct stat stat;
    int fd = open("./async-fn-context.o", O_RDONLY);
    if (fd < 0) {
        printf("open kern prog failed!\n");
        return -1;
    }

    fstat(fd, &stat);
    uint64_t prog_size = stat.st_size;
    printf("file size = %ld\n", prog_size);

    // it seems like mmap with file mapping is not working
    // only use it as a way to allocate memory
    // todo try directly map file in zCore
    long ret = (long) mmap(NULL, prog_size, 3, 32, -1, 0);
    // cprintf("mmap returns %p\n", p);
    if (ret <= 0) {
        printf("mmap failed! ret = %ld\n", ret);
        close(fd);
        return 0;
    }

    unsigned *p = (unsigned *) ret;
    read(fd, p, prog_size);
    //printf("ELF content: %x %x %x %x\n", p[0], p[1], p[2], p[3]);

    struct bpf_map_fd_entry map_array[] = {
    }; // empty
    int bpf_fd = bpf_prog_load_ex(p, prog_size, map_array, 0);
    printf("load ex: %x\n", bpf_fd);

    //const char *target = "kprobe:_RNvMNtNtCs6EJUG5qC0e6_5rcore7syscall4procNtB4_7Syscall8sys_fork";

    FILE *sym_file = fopen("../zcore-async-fn.sym", "r");
    if (!sym_file) {
        printf("failed to open symbol file!\n");
        close(fd);
        return -1;
    }

    char target[256];
    while (fgets(target, sizeof(target), sym_file)) {
        // Remove newline character if present
        target[strcspn(target, "\n")] = 0;
        // Ignore first 19 characters of each line
        char *actual_target = target + 19;
        uint32_t str_len = strlen(actual_target);
        printf("target: %s len: %d\n", actual_target, str_len);

        char fn_entry[256];
        char fn_exit[256];
        snprintf(fn_entry, sizeof(fn_entry), "kretprobe@entry$%s", actual_target);
        snprintf(fn_exit, sizeof(fn_exit), "kretprobe@exit$%s", actual_target);

        printf("attach kretprobe@entry: %d\n", bpf_prog_attach(fn_entry, strlen(fn_entry), bpf_fd));
        printf("attach kretprobe@exit: %d\n", bpf_prog_attach(fn_exit, strlen(fn_exit), bpf_fd));
    }

    printf("all attached, exit without closing files\n");

    // fclose(sym_file);
    
    // close(fd);

    // printf("busy loop");
    // while (1) {
        // printf("try open");
        // int context = open("./context.o", O_RDONLY);
        // sleep(1);
    // }
    return 0;
}
