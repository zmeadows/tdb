#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

uint64_t tdb_read_memory(pid_t pid, uintptr_t addr, bool* success);
void tdb_write_memory(pid_t pid, uintptr_t addr, uint64_t value, bool* success);
