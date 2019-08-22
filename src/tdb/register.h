#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

enum x86_64_register {
    x86_64_rax,
    x86_64_rbx,
    x86_64_rcx,
    x86_64_rdx,
    x86_64_rdi,
    x86_64_rsi,
    x86_64_rbp,
    x86_64_rsp,
    x86_64_r8,
    x86_64_r9,
    x86_64_r10,
    x86_64_r11,
    x86_64_r12,
    x86_64_r13,
    x86_64_r14,
    x86_64_r15,
    x86_64_rip,
    x86_64_eflags,
    x86_64_cs,
    x86_64_orig_rax,
    x86_64_fs_base,
    x86_64_gs_base,
    x86_64_fs,
    x86_64_gs,
    x86_64_ss,
    x86_64_ds,
    x86_64_es,
    X86_64_REGISTER_COUNT,
    x86_64_unknown
};

const char* tdb_get_name_from_register(enum x86_64_register reg);
enum x86_64_register tdb_get_register_from_name(const char* name);

bool tdb_set_register_value(pid_t pid, enum x86_64_register r, uint64_t value);
uint64_t tdb_get_register_value(pid_t pid, enum x86_64_register r, bool* success);

uint64_t tdb_get_register_value_from_dwarf_register(pid_t pid, int dwarf_reg, bool* success);
void tdb_dump_registers(pid_t pid);
