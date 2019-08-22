#include "tdb/tdb.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "linenoise.h"

#include "tdb/utility.h"

#define DEBUG true
// #define DEBUG false

// TODO: use
// https://stackoverflow.com/questions/8884335/print-the-file-name-line-number-and-function-name-of-a-calling-function-c-pro
#define debug_print(fmt, ...)                         \
    do {                                              \
        if (DEBUG) fprintf(stderr, fmt, __VA_ARGS__); \
    } while (0)

static bool is_one_of(const char* str, const char* items[], size_t item_count)
{
    for (size_t i = 0; i < item_count; i++) {
        if (!strcmp(str, items[i])) {
            return true;
        }
    }

    return false;
}

void tdb_context_init(struct tdb_context* context, pid_t _pid, const char* _target_path)
{
    context->pid = _pid;
    strcpy(context->target_path, _target_path);
    context->breakpoint_count = 0;
    context->stack_addr = 0;

    {  // attempt to grab stack address from /proc/pid/maps file
        msleep(250);

        char maps_path[128];
        sprintf(maps_path, "/proc/%d/maps", _pid);

        FILE* maps_file;
        if ((maps_file = fopen(maps_path, "r")) == NULL) {
            printf("couldn't find maps file!\n");
        }

        char* line_buffer = NULL;
        size_t line_buffer_size = 0;
        ssize_t line_length;

        while ((line_length = getline(&line_buffer, &line_buffer_size, maps_file)) != -1) {
            if (strstr(line_buffer, "[stack]") != NULL) {
                char* stack_addr_str = strtok(line_buffer, "-");
                uint64_t stack_addr = strtoull(stack_addr_str, NULL, 16);
                printf("stack address = 0x%zx\n", stack_addr);
                context->stack_addr = stack_addr;
                break;
            }
        }

        free(line_buffer);
        fclose(maps_file);
    }  // finish grabbing stack address
}

void tdb_context_free(struct tdb_context* context)
{
    context->pid = -1;
    context->target_path[0] = '\0';
    context->breakpoint_count = 0;
}

static void tdb_set_breakpoint_at_address(struct tdb_context* context, uintptr_t address_offset)
{
    const uintptr_t actual_address = context->stack_addr + address_offset;

    for (size_t i = 0; i < context->breakpoint_count; i++) {
        struct tdb_breakpoint* bp = &context->breakpoints[i];
        if (bp->pid == context->pid && bp->address == actual_address) {
            fprintf(stderr, "breakpoint already exists at address %zx\n", address_offset);
            return;
        }
    }

    if (context->breakpoint_count == TDB_BREAKPOINTS_ALLOWED) {
        fprintf(stderr,
                "breakpoint capacity overflowed, consider redefining "
                "TDB_BREAKPOINTS_ALLOWED");
        return;
    }

    struct tdb_breakpoint new_breakpoint;
    tdb_breakpoint_init(&new_breakpoint, context->pid, actual_address);
    bool success = tdb_breakpoint_enable(&new_breakpoint);

    if (success) {
        context->breakpoints[context->breakpoint_count] = new_breakpoint;
        context->breakpoint_count++;
    }
    else {
        fprintf(stderr, "breakpoint not enabled at address %zx\n", address_offset);
    }
}

static uint64_t tdb_get_pc(struct tdb_context* context)
{
    bool success;
    uint64_t value = tdb_get_register_value(context->pid, x86_64_rip, &success);

    if (!success) {
        fprintf(stderr, "failed to get program counter (PC).\n");
        return 0;
    }

    return value;
}

static bool tdb_set_pc(struct tdb_context* context, uint64_t value)
{
    bool success = tdb_set_register_value(context->pid, x86_64_rip, value);

    if (!success) {
        fprintf(stderr, "failed to set program counter (PC).\n");
        return false;
    }

    return true;
}

static void tdb_wait_for_signal(struct tdb_context* context)
{
    int wait_status;
    waitpid(context->pid, &wait_status, 0);
    // TODO: check wait status
}

static void tdb_step_over_breakpoint(struct tdb_context* context)
{
    // if the breakpoint has been hit, the PC will now hold the address
    // of the program instruction immediately after the breakpoint, so subtract 1.
    uint64_t maybe_breakpoint_addr = tdb_get_pc(context) - 1;

    for (size_t i = 0; i < context->breakpoint_count; i++) {
        struct tdb_breakpoint* bp = &context->breakpoints[i];
        if (bp->address == maybe_breakpoint_addr && bp->enabled) {
            tdb_set_pc(context, maybe_breakpoint_addr);

            tdb_breakpoint_disable(bp);
            ptrace(PTRACE_SINGLESTEP, context->pid, NULL, NULL);
            tdb_wait_for_signal(context);
            tdb_breakpoint_enable(bp);

            break;
        }
    }
}

static void tdb_handle_continue_command(struct tdb_context* context)
{
    tdb_step_over_breakpoint(context);
    ptrace(PTRACE_CONT, context->pid, NULL, NULL);
    tdb_wait_for_signal(context);
}

static void tdb_handle_register_command(struct tdb_context* context, char** args, size_t arg_count)
{
    if (arg_count == 1) {
        if (!strcmp("dump", args[0])) {
            tdb_dump_registers(context->pid);
        }
        else {
            printf("invalid register argument: %s\n", args[0]);
        }
    }
    else if (arg_count == 2) {
        if (!strcmp("read", args[0])) {
            enum x86_64_register reg = tdb_get_register_from_name(args[1]);

            if (reg == x86_64_unknown) {
                printf("unknown x86_64 register: %s\n", args[1]);
            }
            else {
                bool success;
                uint64_t value = tdb_get_register_value(context->pid, reg, &success);
                if (success) {
                    printf("0x%zx\n", value);
                }
                else {
                    printf("error retrieving register value from memory\n");
                }
            }
        }
        else if (!strcmp("write", args[0])) {
        }
        else {
            printf("invalid register arguments: %s %s\n", args[0], args[1]);
        }
    }
    else {
        printf("invalid register command\n");
    }
}

static void tdb_handle_memory_command(struct tdb_context* context, char** args, size_t arg_count)
{
    if (arg_count != 2 && arg_count != 3) {
        printf("invalid memory command\n");
        return;
    }

    uint64_t address_offset = strtoull(args[1], NULL, 16);
    if (address_offset == 0) {
        printf("Invalid address: %s\n", args[1]);
        return;
    }

    if (!strcmp(args[0], "read")) {
        if (arg_count != 2) {
            printf("invalid memory read command\n");
            return;
        }

        bool read_success;
        uint64_t data = tdb_read_memory(context->pid, context->stack_addr + address_offset, &read_success);
        if (!read_success) {
            printf("Failed to read memory at address: 0x%zx\n", address_offset);
            return;
        }
        printf("0x%zx\n", data);
    }
    else if (!strcmp(args[0], "write")) {
        if (arg_count != 3) {
            printf("invalid memory write command\n");
            return;
        }

        uint64_t value = strtoull(args[2], NULL, 16);

        bool write_success;
        tdb_write_memory(context->pid, context->stack_addr + address_offset, value, &write_success);
        if (!write_success) {
            printf("Failed to write memory at address: 0x%zx\n", address_offset);
            return;
        }
    }
    else {
        printf("invalid memory command.\n");
    }
}

static void tdb_handle_break_command(struct tdb_context* context, char** args, size_t arg_count)
{
    if (arg_count == 1) {
        uint64_t address = strtoull(args[0], NULL, 16);
        debug_print("address given: %ld (0x%zx)\n", address, address);
        if (address != 0) {
            tdb_set_breakpoint_at_address(context, address);
        }
        else {
            fprintf(stderr, "invalid address: %s\n", args[0]);
        }
    }
    else {
        printf("invalid breakpoint command.\n");
    }
}

static void tdb_handle_command(struct tdb_context* context, char* line)
{
    // duplicate the line, because linenoise doesn't like it when we modify it directly
    char* line_copy = strdup(line);

    size_t line_length = strlen(line_copy);

    // skip over any initial white space
    size_t start_index = 0;
    for (size_t i = 0; i < line_length; i++) {
        if (line_copy[i] == ' ') {
            start_index = i;
            break;
        }
    }

    // count words
    size_t arg_count = 0;
    {
        bool scanning_word = true;
        for (size_t i = start_index; i < line_length; i++) {
            if (line_copy[i] == ' ') {
                scanning_word = false;
            }
            else if (!scanning_word) {
                arg_count++;
                scanning_word = true;
            }
        }
    }

    char* command = strtok(line_copy, " ");
    char** args = (char**)malloc(arg_count * sizeof(char*));

    debug_print("command: %s\n", command);
    debug_print("arg_count: %ld\n", arg_count);

    {  // split the remaining arguments in the line on spaces
        int arg_index = 0;
        char* token;
        while ((token = strtok(NULL, " ")) != NULL) {
            args[arg_index] = token;
            debug_print("arg %d: %s\n", arg_index, token);
            arg_index++;
        }
    }

    const char* CONTINUE_CMDS[] = {"continue", "c", "cont"};
    const char* BREAK_CMDS[] = {"breakpoint", "break", "b", "bp"};
    const char* REGISTER_CMDS[] = {"register", "r", "reg"};
    const char* MEMORY_CMDS[] = {"memory", "m", "mem"};

#define __TDB_USER_COMMAND_IS_ONE_OF(X) is_one_of(command, X, sizeof(X) / sizeof(char*))

    // now dispatch on the main command
    if (__TDB_USER_COMMAND_IS_ONE_OF(CONTINUE_CMDS)) {
        tdb_handle_continue_command(context);
    }
    else if (__TDB_USER_COMMAND_IS_ONE_OF(BREAK_CMDS)) {
        tdb_handle_break_command(context, args, arg_count);
    }
    else if (__TDB_USER_COMMAND_IS_ONE_OF(REGISTER_CMDS)) {
        tdb_handle_register_command(context, args, arg_count);
    }
    else if (__TDB_USER_COMMAND_IS_ONE_OF(MEMORY_CMDS)) {
        tdb_handle_memory_command(context, args, arg_count);
    }
    else {
        // TODO: add 'help' command/message
        fprintf(stderr, "Unknown command\n");
    }

    free(args);
    free(line_copy);
}

void tdb_run(struct tdb_context* context)
{
    int wait_status;
    waitpid(context->pid, &wait_status, 0);

    char* line = NULL;

    while ((line = linenoise("tdb> "))) {
        if (strcmp(line, "") && strcmp(line, "\0")) {
            tdb_handle_command(context, line);
            linenoiseHistoryAdd(line);
            linenoiseFree(line);
        }
    }
}
