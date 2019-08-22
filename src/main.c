#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>

#include "tdb/tdb.h"

int main(int argc, char** argv)
{
    if (argc < 2) {
        fprintf(stderr, "Executable name not specified.\n");
        return EXIT_FAILURE;
    }

    pid_t pid = fork();

    char* target_path = argv[1];

    if (pid == 0) {  // in child process, execute program to be debugged
        int64_t ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        if (ret == -1) {
            fprintf(stderr, "Failed to initiate ptrace on debugee.\n");
            return EXIT_FAILURE;
        }

        // TODO: use execve?
        execl(target_path, target_path, NULL);
    }
    else if (pid >= 1) {  // in parent process, execute debugger
        printf("pid = %d\n", pid);
        struct tdb_context context;
        tdb_context_init(&context, pid, target_path);
        tdb_run(&context);
        tdb_context_free(&context);
    }
    else {  // fork() failed
        fprintf(stderr, "Failed to fork process to begin debugging: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    printf("\n");

    return 0;
}
