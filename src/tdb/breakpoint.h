#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

struct tdb_breakpoint {
    pid_t pid;
    uintptr_t address;
    bool enabled;
    uint8_t saved_data;
};

void tdb_breakpoint_init(struct tdb_breakpoint* bp, pid_t pid, uintptr_t address);
bool tdb_breakpoint_enable(struct tdb_breakpoint* bp);
void tdb_breakpoint_disable(struct tdb_breakpoint* bp);

