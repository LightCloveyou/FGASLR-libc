#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#define NSLOT     16
#define LINE_LEN  128
#define ORW_LEN   38
#define KEYLEN    (3 + ORW_LEN)
#define KEY_PFX   "sk-"

static void setup(void)
{
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

static void banner(void)
{
    puts("=========================================");
    puts("          stkcalc  --  8-byte slots      ");
    puts("=========================================");
    puts(" 1) set <idx> <value>   slot[idx] = val  ");
    puts(" 2) get <idx>           print slot[idx]  ");
    puts(" 3) add <dst> <src>     dst = dst + src  ");
    puts(" 4) sub <dst> <src>     dst = dst - src  ");
    puts(" 5) mul <dst> <src>     dst = dst * src  ");
    puts(" 6) div <dst> <src>     dst = dst / src  ");
    puts(" 7) dump                list all slots   ");
    puts(" 8) peek <addr>         read 4 bytes (x1)");
    puts(" 9) setg <g0|g1> <v>    global slot = v   ");
    puts("10) getg <g0|g1>        print global     ");
    puts(" 0) exit                                 ");
    puts("-----------------------------------------");
}

static int read_line(char *buf, size_t len)
{
    size_t n;

    if (fgets(buf, (int)len, stdin) == NULL) {
        buf[0] = '\0';
        return 0;
    }

    n = strlen(buf);
    if (n > 0 && buf[n - 1] == '\n') {
        buf[--n] = '\0';
        if (n > 0 && buf[n - 1] == '\r')
            buf[--n] = '\0';
        return 1;
    }

    if (!feof(stdin)) {
        int ch;

        while ((ch = getchar()) != EOF && ch != '\n')
            ;
    }

    return 1;
}

static int parse_index(const char *s, long long *out)
{
    char *end;
    long long v;

    if (s == NULL || *s == '\0')
        return -1;

    errno = 0;
    v = strtoll(s, &end, 0);
    if (errno != 0 || end == s || *end != '\0')
        return -1;

    *out = v;
    return 0;
}

static int parse_value(const char *s, uint64_t *out)
{
    char *end;
    unsigned long long v;

    if (s == NULL || *s == '\0')
        return -1;

    errno = 0;
    v = strtoull(s, &end, 0);
    if (errno != 0 || end == s || *end != '\0')
        return -1;

    *out = (uint64_t)v;
    return 0;
}

static uint64_t *slot_at(uint64_t *slots, long long idx)
{
    if (idx >= (long long)NSLOT || (idx + 1) < 0)
        return NULL;

    return &slots[idx];
}

static uint64_t gslot[2];

static uint64_t *global_ptr(const char *name)
{
    if (name == NULL)
        return NULL;

    if (!strcmp(name, "g0"))
        return &gslot[0];

    if (!strcmp(name, "g1"))
        return &gslot[1];

    return NULL;
}

static uint64_t *operand_ptr(const char *s, uint64_t *slots)
{
    uint64_t *g = global_ptr(s);
    long long idx;

    if (g != NULL)
        return g;

    if (parse_index(s, &idx) < 0)
        return NULL;

    return slot_at(slots, idx);
}

static void do_dump(const uint64_t *slots)
{
    int i;

    for (i = 0; i < NSLOT; i++)
        printf("slot[%2d] = 0x%016llx\n", i, (unsigned long long)slots[i]);
}

static int do_peek(uint64_t addr)
{
    static int used;
    uint32_t v;

    if (used) {
        return 1;
    }
    used = 1;

    v = *(volatile uint32_t *)(uintptr_t)addr;
    printf("[0x%016llx] = 0x%08x (%u)\n",
           (unsigned long long)addr, (unsigned)v, (unsigned)v);
    return 0;
}

__attribute__((noinline))
static void calc_loop(uint64_t *slots)
{
    char line[LINE_LEN];
    char *save, *cmd, *arg1, *arg2;
    long long dst;
    uint64_t val, addr;
    uint64_t *a, *b;

    for (;;) {
        fputs("calc> ", stdout);
        if (!read_line(line, sizeof(line)))
            break;

        if (line[0] == '\0')
            continue;

        save = NULL;
        cmd  = strtok_r(line, " \t", &save);
        if (cmd == NULL)
            continue;
        arg1 = strtok_r(NULL, " \t", &save);
        arg2 = strtok_r(NULL, " \t", &save);

        if (!strcmp(cmd, "0") || !strcmp(cmd, "exit")) {
            break;
        }

        if (!strcmp(cmd, "1") || !strcmp(cmd, "set")) {
            if (parse_index(arg1, &dst) < 0 || parse_value(arg2, &val) < 0) {
                puts("usage: set <idx> <value>");
                continue;
            }

            a = slot_at(slots, dst);
            if (a == NULL) {
                printf("!! slot %lld does not exist\n", dst);
                continue;
            }

            *a = val;
            printf("slot[%lld] = 0x%016llx\n",
                   dst, (unsigned long long)val);
        } else if (!strcmp(cmd, "2") || !strcmp(cmd, "get")) {
            if (parse_index(arg1, &dst) < 0) {
                puts("usage: get <idx>");
                continue;
            }

            a = slot_at(slots, dst);
            if (a == NULL) {
                printf("!! slot %lld does not exist\n", dst);
                continue;
            }

            printf("slot[%lld] = %llu (0x%016llx)\n",
                   dst, (unsigned long long)*a, (unsigned long long)*a);
        } else if (!strcmp(cmd, "3") || !strcmp(cmd, "add") ||
                   !strcmp(cmd, "4") || !strcmp(cmd, "sub") ||
                   !strcmp(cmd, "5") || !strcmp(cmd, "mul") ||
                   !strcmp(cmd, "6") || !strcmp(cmd, "div")) {
            a = operand_ptr(arg1, slots);
            b = operand_ptr(arg2, slots);
            if (a == NULL || b == NULL) {
                printf("usage: %s <dst> <src>\n", cmd);
                continue;
            }

            if (!strcmp(cmd, "3") || !strcmp(cmd, "add")) {
                *a += *b;
            } else if (!strcmp(cmd, "4") || !strcmp(cmd, "sub")) {
                *a -= *b;
            } else if (!strcmp(cmd, "5") || !strcmp(cmd, "mul")) {
                *a *= *b;
            } else {
                if (*b == 0) {
                    puts("!! division by zero");
                    continue;
                }
                *a /= *b;
            }

            printf("%s = 0x%016llx\n", arg1, (unsigned long long)*a);
        } else if (!strcmp(cmd, "7") || !strcmp(cmd, "dump")) {
            do_dump(slots);
        } else if (!strcmp(cmd, "8") || !strcmp(cmd, "peek")) {
            if (parse_value(arg1, &addr) < 0) {
                puts("usage: peek <addr>");
                continue;
            }

            int valid = do_peek(addr);
            if (valid == 1) {
                return;
            }
        } else if (!strcmp(cmd, "9") || !strcmp(cmd, "setg")) {
            a = global_ptr(arg1);
            if (a == NULL || parse_value(arg2, &val) < 0) {
                puts("usage: setg <g0|g1> <value>");
                continue;
            }

            *a = val;
            printf("%s = 0x%016llx\n", arg1, (unsigned long long)val);
        } else if (!strcmp(cmd, "10") || !strcmp(cmd, "getg")) {
            a = global_ptr(arg1);
            if (a == NULL) {
                puts("usage: getg <g0|g1>");
                continue;
            }

            printf("%s = %llu (0x%016llx)\n", arg1,
                   (unsigned long long)*a, (unsigned long long)*a);
        } else {
            puts("?? unknown command");
        }
    }
}

static char api_key[KEYLEN];

static int read_exact(void *buf, size_t len)
{
    char *p = buf;
    size_t got = 0;

    while (got < len) {
        ssize_t n = read(STDIN_FILENO, p + got, len - got);

        if (n <= 0)
            return -1;
        got += (size_t)n;
    }

    return 0;
}

static int check_api_key(void)
{
    fputs("api key: ", stdout);

    if (read_exact(api_key, sizeof(api_key)) < 0)
        return -1;

    if (memcmp(api_key, KEY_PFX, 3) != 0)
        return -1;

    return 0;
}

static int install_seccomp(void)
{
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
                 (uint32_t)offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_execveat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len    = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0)
        return -1;

    return 0;
}

int main(void)
{
    uint64_t slot[NSLOT];

    setup();

    if (check_api_key() != 0) {
        puts("invalid api key");
        return 1;
    }

    if (install_seccomp() != 0) {
        perror("seccomp");
        return 1;
    }

    printf("puts @ %p\n", (void *)&puts);

    memset(slot, 0, sizeof(slot));

    banner();
    calc_loop(slot);

    puts("bye");
    return 0;
}
