#include "breakpoint.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>

#include "tdb/utility.h"

static const uint64_t BOTTOM_BYTE = 0xffULL;
static const uint64_t NOT_BOTTOM_BYTE = ~0xffULL;

void tdb_breakpoint_init(struct tdb_breakpoint* bp, pid_t pid, uintptr_t address)
{
    bp->pid = pid;
    bp->address = address;
    bp->enabled = false;
    bp->saved_data = 0;
}

bool tdb_breakpoint_enable(struct tdb_breakpoint* bp)
{
    bool read_success;
    uint64_t udata = tdb_read_memory(bp->pid, bp->address, &read_success);
    if (!read_success) {
        fprintf(stderr, "Failed to read memory when enabling breakpoint.\n");
        return false;
    }

    bp->saved_data = (uint8_t)(udata & BOTTOM_BYTE);

    uint64_t int3 = 0xcc;
    uint64_t data_with_int3 = ((udata & NOT_BOTTOM_BYTE) | int3);

    bool write_success;
    tdb_write_memory(bp->pid, bp->address, data_with_int3, &write_success);
    if (!write_success) {
        fprintf(stderr, "Failed to write memory when enabling breakpoint.\n");
        return false;
    }

    bp->enabled = true;

    return true;
}

void tdb_breakpoint_disable(struct tdb_breakpoint* bp)
{
    // TODO: log attempts to disable un-enabled breakpoints
    if (bp->enabled) {
        bool read_success;
        uint64_t udata = tdb_read_memory(bp->pid, bp->address, &read_success);
        if (!read_success) {
            fprintf(stderr, "Failed to read memory when disabling breakpoint.\n");
            return;
        }

        uint64_t restored_data = ((udata & NOT_BOTTOM_BYTE) | bp->saved_data);

        bool write_success;
        tdb_write_memory(bp->pid, bp->address, restored_data, &write_success);
        if (!write_success) {
            fprintf(stderr, "Failed to write memory when disabling breakpoint.\n");
            return;
        }

        bp->enabled = false;
    }
}
