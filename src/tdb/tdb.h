#pragma once

#include <linux/limits.h>

#include "tdb/breakpoint.h"
#include "tdb/register.h"

#ifndef TDB_BREAKPOINTS_ALLOWED
#define TDB_BREAKPOINTS_ALLOWED 1024
#endif

struct tdb_context {
    pid_t pid;
    char target_path[PATH_MAX];
    uint64_t stack_addr;

    struct tdb_breakpoint breakpoints[TDB_BREAKPOINTS_ALLOWED];
    size_t breakpoint_count;
};

void tdb_context_init(struct tdb_context* context, pid_t _pid, const char* _target_path);
void tdb_context_free(struct tdb_context* context);
void tdb_run(struct tdb_context* context);

