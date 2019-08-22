#include "utility.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>
#include <time.h>

uint64_t tdb_read_memory(pid_t pid, uintptr_t address, bool* success)
{
    errno = 0;
    uint64_t data = ptrace(PTRACE_PEEKDATA, pid, address, NULL);
    *success = errno == 0;
    if (!success) {
	fprintf(stderr,
		"Failed to peek instruction data at address: 0x%" PRIXPTR
		".\n"
		"\tReason: %s\n",
		address, strerror(errno));
    }
    return data;
}

void tdb_write_memory(pid_t pid, uintptr_t address, uint64_t value, bool* success)
{
    errno = 0;
    ptrace(PTRACE_POKEDATA, pid, address, value);
    *success = errno == 0;
}

int msleep(long msec)
{
    struct timespec ts;
    int res;

    if (msec < 0) {
	errno = EINVAL;
	return -1;
    }

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do {
	res = nanosleep(&ts, &ts);
    } while (res && errno == EINTR);

    return res;
}
