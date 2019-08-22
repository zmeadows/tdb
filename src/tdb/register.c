#include "register.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>

struct x86_64_register_descriptor {
    enum x86_64_register reg;
    int dwarf_reg;
    char name[16];
};

static const struct x86_64_register_descriptor g_tdb_register_descriptors[X86_64_REGISTER_COUNT] = {
    {.reg = x86_64_r15, .dwarf_reg = 15, .name = "r15"},
    {.reg = x86_64_r14, .dwarf_reg = 14, .name = "r14"},
    {.reg = x86_64_r13, .dwarf_reg = 13, .name = "r13"},
    {.reg = x86_64_r12, .dwarf_reg = 12, .name = "r12"},
    {.reg = x86_64_rbp, .dwarf_reg = 6, .name = "rbp"},
    {.reg = x86_64_rbx, .dwarf_reg = 3, .name = "rbx"},
    {.reg = x86_64_r11, .dwarf_reg = 11, .name = "r11"},
    {.reg = x86_64_r10, .dwarf_reg = 10, .name = "r10"},
    {.reg = x86_64_r9, .dwarf_reg = 9, .name = "r9"},
    {.reg = x86_64_r8, .dwarf_reg = 8, .name = "r8"},
    {.reg = x86_64_rax, .dwarf_reg = 0, .name = "rax"},
    {.reg = x86_64_rcx, .dwarf_reg = 2, .name = "rcx"},
    {.reg = x86_64_rdx, .dwarf_reg = 1, .name = "rdx"},
    {.reg = x86_64_rsi, .dwarf_reg = 4, .name = "rsi"},
    {.reg = x86_64_rdi, .dwarf_reg = 5, .name = "rdi"},
    {.reg = x86_64_orig_rax, .dwarf_reg = -1, .name = "orig_rax"},
    {.reg = x86_64_rip, .dwarf_reg = -1, .name = "rip"},
    {.reg = x86_64_cs, .dwarf_reg = 51, .name = "cs"},
    {.reg = x86_64_eflags, .dwarf_reg = 49, .name = "eflags"},
    {.reg = x86_64_rsp, .dwarf_reg = 7, .name = "rsp"},
    {.reg = x86_64_ss, .dwarf_reg = 52, .name = "ss"},
    {.reg = x86_64_fs_base, .dwarf_reg = 58, .name = "fs_base"},
    {.reg = x86_64_gs_base, .dwarf_reg = 59, .name = "gs_base"},
    {.reg = x86_64_ds, .dwarf_reg = 53, .name = "ds"},
    {.reg = x86_64_es, .dwarf_reg = 50, .name = "es"},
    {.reg = x86_64_fs, .dwarf_reg = 54, .name = "fs"},
    {.reg = x86_64_gs, .dwarf_reg = 55, .name = "gs"},
};

const char* tdb_get_name_from_register(enum x86_64_register reg)
{
    for (size_t i = 0; i < X86_64_REGISTER_COUNT; i++) {
        const struct x86_64_register_descriptor* desc = &g_tdb_register_descriptors[i];
        if (desc->reg == reg) {
            return desc->name;
        }
    }

    return NULL;
}

enum x86_64_register tdb_get_register_from_name(const char* name)
{
    for (size_t i = 0; i < X86_64_REGISTER_COUNT; i++) {
        const struct x86_64_register_descriptor* desc = &g_tdb_register_descriptors[i];
        if (!strcmp(name, desc->name)) {
            return desc->reg;
        }
    }

    return x86_64_unknown;
}

bool tdb_set_register_value(pid_t pid, enum x86_64_register r, uint64_t value)
{
    struct user_regs_struct uregs;
    errno = 0;
    ptrace(PTRACE_GETREGS, pid, NULL, &uregs);

    if (errno != 0) {
        fprintf(stderr,
                "tdb_set_register_value: failed to get register data.\n"
                "REASON: %s\n",
                strerror(errno));
        return false;
    }

    switch (r) {
        case x86_64_rax:
            uregs.rax = value;
            break;
        case x86_64_rbx:
            uregs.rbx = value;
            break;
        case x86_64_rcx:
            uregs.rcx = value;
            break;
        case x86_64_rdx:
            uregs.rdx = value;
            break;
        case x86_64_rdi:
            uregs.rdi = value;
            break;
        case x86_64_rsi:
            uregs.rsi = value;
            break;
        case x86_64_rbp:
            uregs.rbp = value;
            break;
        case x86_64_rsp:
            uregs.rsp = value;
            break;
        case x86_64_r8:
            uregs.r8 = value;
            break;
        case x86_64_r9:
            uregs.r9 = value;
            break;
        case x86_64_r10:
            uregs.r10 = value;
            break;
        case x86_64_r11:
            uregs.r11 = value;
            break;
        case x86_64_r12:
            uregs.r12 = value;
            break;
        case x86_64_r13:
            uregs.r13 = value;
            break;
        case x86_64_r14:
            uregs.r14 = value;
            break;
        case x86_64_r15:
            uregs.r15 = value;
            break;
        case x86_64_rip:
            uregs.rip = value;
            break;
        case x86_64_eflags:
            uregs.eflags = value;
            break;
        case x86_64_cs:
            uregs.cs = value;
            break;
        case x86_64_orig_rax:
            uregs.orig_rax = value;
            break;
        case x86_64_fs_base:
            uregs.fs_base = value;
            break;
        case x86_64_gs_base:
            uregs.gs_base = value;
            break;
        case x86_64_fs:
            uregs.fs = value;
            break;
        case x86_64_gs:
            uregs.gs = value;
            break;
        case x86_64_ss:
            uregs.ss = value;
            break;
        case x86_64_ds:
            uregs.ds = value;
            break;
        case x86_64_es:
            uregs.es = value;
            break;
        default:
            return false;
            break;
    };

    errno = 0;
    ptrace(PTRACE_SETREGS, pid, NULL, &uregs);

    if (errno != 0) {
        fprintf(stderr,
                "tdb_set_register_value: failed to set register data.\n"
                "REASON: %s\n",
                strerror(errno));
        return false;
    }

    return true;
}

uint64_t tdb_get_register_value(pid_t pid, enum x86_64_register r, bool* success)
{
    struct user_regs_struct uregs;
    errno = 0;
    ptrace(PTRACE_GETREGS, pid, NULL, &uregs);

    if (errno != 0) {
        fprintf(stderr, "Failed to get register data: %s\n", strerror(errno));
        *success = false;
        return 0;
    }

    *success = true;
    uint64_t register_content = 0;
    switch (r) {
        case x86_64_rax:
            register_content = uregs.rax;
            break;
        case x86_64_rbx:
            register_content = uregs.rbx;
            break;
        case x86_64_rcx:
            register_content = uregs.rcx;
            break;
        case x86_64_rdx:
            register_content = uregs.rdx;
            break;
        case x86_64_rdi:
            register_content = uregs.rdi;
            break;
        case x86_64_rsi:
            register_content = uregs.rsi;
            break;
        case x86_64_rbp:
            register_content = uregs.rbp;
            break;
        case x86_64_rsp:
            register_content = uregs.rsp;
            break;
        case x86_64_r8:
            register_content = uregs.r8;
            break;
        case x86_64_r9:
            register_content = uregs.r9;
            break;
        case x86_64_r10:
            register_content = uregs.r10;
            break;
        case x86_64_r11:
            register_content = uregs.r11;
            break;
        case x86_64_r12:
            register_content = uregs.r12;
            break;
        case x86_64_r13:
            register_content = uregs.r13;
            break;
        case x86_64_r14:
            register_content = uregs.r14;
            break;
        case x86_64_r15:
            register_content = uregs.r15;
            break;
        case x86_64_rip:
            register_content = uregs.rip;
            break;
        case x86_64_eflags:
            register_content = uregs.eflags;
            break;
        case x86_64_cs:
            register_content = uregs.cs;
            break;
        case x86_64_orig_rax:
            register_content = uregs.orig_rax;
            break;
        case x86_64_fs_base:
            register_content = uregs.fs_base;
            break;
        case x86_64_gs_base:
            register_content = uregs.gs_base;
            break;
        case x86_64_fs:
            register_content = uregs.fs;
            break;
        case x86_64_gs:
            register_content = uregs.gs;
            break;
        case x86_64_ss:
            register_content = uregs.ss;
            break;
        case x86_64_ds:
            register_content = uregs.ds;
            break;
        case x86_64_es:
            register_content = uregs.es;
            break;
        default:
            *success = false;
            break;
    };

    return register_content;
}

uint64_t tdb_get_register_value_from_dwarf_register(pid_t pid, int dwarf_reg, bool* success)
{
    for (size_t i = 0; i < X86_64_REGISTER_COUNT; i++) {
        const struct x86_64_register_descriptor* desc = &g_tdb_register_descriptors[i];
        if (desc->dwarf_reg == dwarf_reg) {
            return tdb_get_register_value(pid, desc->reg, success);
        }
    }

    *success = false;
    return 0;
}

void tdb_dump_registers(pid_t pid)
{
    for (size_t i = 0; i < X86_64_REGISTER_COUNT; i++) {
        const struct x86_64_register_descriptor* desc = &g_tdb_register_descriptors[i];

        bool success;
        uint64_t reg_val = tdb_get_register_value(pid, desc->reg, &success);
        if (success) {
            printf("%s\t\t 0x%zx\n", desc->name, reg_val);
        }
        else {
            printf("%s\t\t ERROR\n", desc->name);
        }
    }
}
