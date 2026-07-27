/* main.c — the `vxworker` command-line front end.
 *
 * This binary is the host-side entry point vxnode shells out to, and doubles as
 * the integration seam for the other two engines: `vxworker encode-task` emits a
 * byte-exact ABI frame that `ion run` and `iron run` consume. */
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "vx_cgroup.h"
#include "vx_error.h"
#include "vx_ipc.h"
#include "vx_log.h"
#include "vx_sandbox.h"
#include "vx_signal.h"
#include "vx_task.h"

#define VXWORKER_VERSION "1.0.0"

static void usage(void) {
    fputs("vxworker " VXWORKER_VERSION " — VxCloud C11 system ABI and isolation layer\n"
          "\n"
          "usage: vxworker <command> [options]\n"
          "\n"
          "commands:\n"
          "  abi                        print the frozen ABI v1 layout\n"
          "  probe                      report kernel isolation capabilities\n"
          "  run [opts] -- <argv...>    execute a command inside a sandbox\n"
          "  encode-task [opts]         write an ABI task frame to stdout\n"
          "  decode-task [file]         validate and describe an ABI task frame\n"
          "  ring <sub> [opts]          shared-memory ring: create|push|pop|info|unlink\n"
          "  selftest                   run built-in consistency checks\n"
          "  version                    print the version\n"
          "\n"
          "run options:\n"
          "  --task-id N        task identifier (default 1)\n"
          "  --tenant S         tenant slug (default \"default\")\n"
          "  --mem MB           memory.max in MiB, 0 = unlimited (default 64)\n"
          "  --cpu US           cpu.max quota in microseconds (default 50000)\n"
          "  --pids N           pids.max (default 64)\n"
          "  --timeout MS       wall-clock kill deadline (default 30000)\n"
          "  --host-uid N       host uid that namespace uid 0 maps to (default 65534)\n"
          "  --no-net           share the host network namespace\n"
          "  --no-userns        do not create a user namespace\n"
          "  --no-pidns         do not create a pid namespace\n"
          "  --no-proc          do not mount a fresh /proc\n"
          "  --hostname S       hostname inside the UTS namespace\n"
          "  --seccomp M        syscall filter: off|audit|errno|kill (default errno)\n"
          "  --deny-ptrace      forbid ptrace/process_vm_* (breaks gdb and ASan)\n"
          "  --allow-nsops      permit setns/unshare in the guest\n"
          "\n"
          "encode-task options:\n"
          "  --task-id N  --tenant S  --engine ion|iron  --mem MB  --cpu US\n"
          "  --payload S        inline payload bytes\n"
          "\n"
          "ring options:\n"
          "  --name S  --slots N  --slot-bytes N  --payload S\n"
          "\n"
          "environment:\n"
          "  VX_LOG=silent|error|warn|info|debug|trace\n",
          stderr);
}

/* ------------------------------------------------------------------------- */

static int cmd_abi(void) {
    printf("abi_version      %u\n", VX_ABI_VERSION);
    printf("magic            0x%08x\n", VX_MAGIC_HEADER);
    printf("task_header_size %u\n", VX_TASK_HEADER_SIZE);
    printf("result_header_size %u\n", VX_RESULT_HEADER_SIZE);
    printf("tenant_id_len    %u\n", VX_TENANT_ID_LEN);
    printf("max_payload_len  %u\n", VX_MAX_PAYLOAD_LEN);
    printf("engines          ion=0x%02x iron=0x%02x\n", ENGINE_ION, ENGINE_IRON);
    printf("\ntask header field layout (packed, little-endian):\n");
    printf("  %-18s %6s %5s\n", "field", "offset", "size");
    printf("  %-18s %6d %5zu\n", "magic", 0, sizeof(uint32_t));
    printf("  %-18s %6d %5zu\n", "task_id", 4, sizeof(uint64_t));
    printf("  %-18s %6d %5d\n", "tenant_id", 12, VX_TENANT_ID_LEN);
    printf("  %-18s %6d %5zu\n", "engine", 76, sizeof(uint8_t));
    printf("  %-18s %6d %5zu\n", "memory_limit_mb", 77, sizeof(uint32_t));
    printf("  %-18s %6d %5zu\n", "cpu_quota_us", 81, sizeof(uint32_t));
    printf("  %-18s %6d %5zu\n", "payload_len", 85, sizeof(uint64_t));
    printf("  %-18s %6d %5s\n", "payload[]", 93, "var");
    return 0;
}

static const char *yn(bool v) {
    return v ? "yes" : "no";
}

static int cmd_probe(void) {
    vx_sandbox_caps_t caps;
    vx_status_t st = vx_sandbox_probe(&caps);
    if (st != VX_OK) {
        fprintf(stderr, "probe failed: %s\n", vx_status_str(st));
        return 1;
    }

    printf("namespaces:\n");
    printf("  CLONE_NEWUSER    %s\n", yn(caps.userns));
    printf("  CLONE_NEWPID     %s\n", yn(caps.pidns));
    printf("  CLONE_NEWNET     %s\n", yn(caps.netns));
    printf("  CLONE_NEWIPC     %s\n", yn(caps.ipcns));
    printf("  CLONE_NEWNS      %s\n", yn(caps.mountns));
    printf("  CLONE_NEWUTS     %s\n", yn(caps.utsns));
    printf("  CLONE_NEWCGROUP  %s\n", yn(caps.cgroupns));
    printf("  max_user_ns      %ld\n", caps.max_user_ns);
    printf("cgroups:\n");
    printf("  cgroup v2        %s\n", yn(caps.cgroup_v2));
    printf("  memory           %s\n", yn(caps.cgroup_memory));
    printf("  cpu              %s\n", yn(caps.cgroup_cpu));
    printf("  pids             %s\n", yn(caps.cgroup_pids));
    printf("  cgroup.kill      %s\n", yn(caps.cgroup_kill));
    if (caps.cgroup_v2) {
        char ctrls[256];
        if (vx_cgroup_controllers(NULL, ctrls, sizeof(ctrls)) == VX_OK)
            printf("  controllers      %s\n", ctrls);
    }
    printf("facilities:\n");
    printf("  pidfd_open       %s\n", yn(caps.pidfd));
    printf("  signalfd         %s\n", yn(caps.signalfd));
    printf("  seccomp-bpf      %s\n", yn(caps.seccomp));
    printf("  RET_KILL_PROCESS %s%s\n", yn(caps.seccomp_kill),
           caps.seccomp_kill ? "" : "  (kill mode would stop only the calling thread)");
    printf("  euid             %lld\n", (long long)geteuid());

    vx_seccomp_policy_t pol;
    vx_seccomp_policy_init(&pol);
    const char *denied[96];
    size_t n = vx_seccomp_denied_list(&pol, denied, sizeof(denied) / sizeof(denied[0]));
    printf("seccomp policy (default): %s, %zu syscalls denied\n", vx_seccomp_mode_name(pol.mode),
           n);
    for (size_t i = 0; i < n && i < sizeof(denied) / sizeof(denied[0]); i++) {
        printf("%s%s", i % 6 == 0 ? "  " : " ", denied[i]);
        if (i % 6 == 5 || i + 1 == n) printf("\n");
    }

    bool ready = caps.userns && caps.pidns && caps.cgroup_v2 && caps.cgroup_memory;
    printf("\nverdict: %s\n",
           ready ? "full isolation available" : "DEGRADED — some isolation unavailable");
    return ready ? 0 : 2;
}

/* ------------------------------------------------------------------------- */

typedef struct {
    uint64_t task_id;
    const char *tenant;
    const char *engine;
    const char *payload;
    const char *hostname;
    const char *name;
    uint32_t mem;
    uint32_t cpu;
    uint32_t pids;
    uint32_t timeout;
    uint32_t slots;
    uint32_t slot_bytes;
    long host_uid;
    bool no_net;
    bool no_userns;
    bool no_pidns;
    bool no_proc;
    const char *seccomp;
    bool deny_ptrace;
    bool allow_nsops;
} opts_t;

enum {
    OPT_TASK_ID = 1000,
    OPT_TENANT,
    OPT_ENGINE,
    OPT_MEM,
    OPT_CPU,
    OPT_PIDS,
    OPT_TIMEOUT,
    OPT_HOST_UID,
    OPT_NO_NET,
    OPT_NO_USERNS,
    OPT_NO_PIDNS,
    OPT_NO_PROC,
    OPT_HOSTNAME,
    OPT_PAYLOAD,
    OPT_NAME,
    OPT_SLOTS,
    OPT_SLOT_BYTES,
    OPT_SECCOMP,
    OPT_DENY_PTRACE,
    OPT_ALLOW_NSOPS
};

static const struct option long_opts[] = {{"task-id", required_argument, NULL, OPT_TASK_ID},
                                          {"tenant", required_argument, NULL, OPT_TENANT},
                                          {"engine", required_argument, NULL, OPT_ENGINE},
                                          {"mem", required_argument, NULL, OPT_MEM},
                                          {"cpu", required_argument, NULL, OPT_CPU},
                                          {"pids", required_argument, NULL, OPT_PIDS},
                                          {"timeout", required_argument, NULL, OPT_TIMEOUT},
                                          {"host-uid", required_argument, NULL, OPT_HOST_UID},
                                          {"no-net", no_argument, NULL, OPT_NO_NET},
                                          {"no-userns", no_argument, NULL, OPT_NO_USERNS},
                                          {"no-pidns", no_argument, NULL, OPT_NO_PIDNS},
                                          {"no-proc", no_argument, NULL, OPT_NO_PROC},
                                          {"hostname", required_argument, NULL, OPT_HOSTNAME},
                                          {"payload", required_argument, NULL, OPT_PAYLOAD},
                                          {"name", required_argument, NULL, OPT_NAME},
                                          {"slots", required_argument, NULL, OPT_SLOTS},
                                          {"slot-bytes", required_argument, NULL, OPT_SLOT_BYTES},
                                          {"seccomp", required_argument, NULL, OPT_SECCOMP},
                                          {"deny-ptrace", no_argument, NULL, OPT_DENY_PTRACE},
                                          {"allow-nsops", no_argument, NULL, OPT_ALLOW_NSOPS},
                                          {"help", no_argument, NULL, 'h'},
                                          {NULL, 0, NULL, 0}};

static void opts_init(opts_t *o) {
    memset(o, 0, sizeof(*o));
    o->task_id = 1;
    o->tenant = "default";
    o->engine = "ion";
    o->name = "default";
    o->mem = 64;
    o->cpu = 50000;
    o->pids = 64;
    o->timeout = 30000;
    o->host_uid = -1;
}

/* Returns the index of the first non-option argument, or -1 on error. */
static int parse_opts(int argc, char **argv, opts_t *o) {
    optind = 1;
    for (;;) {
        int c = getopt_long(argc, argv, "h", long_opts, NULL);
        if (c == -1) break;
        switch (c) {
        case OPT_TASK_ID:
            o->task_id = strtoull(optarg, NULL, 10);
            break;
        case OPT_TENANT:
            o->tenant = optarg;
            break;
        case OPT_ENGINE:
            o->engine = optarg;
            break;
        case OPT_MEM:
            o->mem = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case OPT_CPU:
            o->cpu = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case OPT_PIDS:
            o->pids = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case OPT_TIMEOUT:
            o->timeout = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case OPT_HOST_UID:
            o->host_uid = strtol(optarg, NULL, 10);
            break;
        case OPT_NO_NET:
            o->no_net = true;
            break;
        case OPT_NO_USERNS:
            o->no_userns = true;
            break;
        case OPT_NO_PIDNS:
            o->no_pidns = true;
            break;
        case OPT_NO_PROC:
            o->no_proc = true;
            break;
        case OPT_SECCOMP:
            o->seccomp = optarg;
            break;
        case OPT_DENY_PTRACE:
            o->deny_ptrace = true;
            break;
        case OPT_ALLOW_NSOPS:
            o->allow_nsops = true;
            break;
        case OPT_HOSTNAME:
            o->hostname = optarg;
            break;
        case OPT_PAYLOAD:
            o->payload = optarg;
            break;
        case OPT_NAME:
            o->name = optarg;
            break;
        case OPT_SLOTS:
            o->slots = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case OPT_SLOT_BYTES:
            o->slot_bytes = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        case 'h':
            usage();
            return -1;
        default:
            usage();
            return -1;
        }
    }
    return optind;
}

static int cmd_run(int argc, char **argv) {
    opts_t o;
    opts_init(&o);
    int rest = parse_opts(argc, argv, &o);
    if (rest < 0) return 2;
    if (rest >= argc) {
        fprintf(stderr, "vxworker run: no command given (use -- <argv...>)\n");
        return 2;
    }

    vx_sandbox_spec_t spec;
    vx_sandbox_spec_init(&spec);
    spec.task_id = o.task_id;
    spec.tenant_id = o.tenant;
    spec.memory_limit_mb = o.mem;
    spec.cpu_quota_us = o.cpu;
    spec.pids_max = o.pids;
    spec.timeout_ms = o.timeout;
    spec.argv = &argv[rest];
    if (o.no_net) {
        spec.new_net = false;
        spec.loopback_up = false;
    }
    if (o.no_userns) spec.new_user = false;
    if (o.no_pidns) spec.new_pid = false;
    if (o.no_proc) spec.mount_proc = false;
    if (o.hostname != NULL) spec.hostname = o.hostname;
    if (o.seccomp != NULL) {
        if (vx_seccomp_mode_parse(o.seccomp, &spec.seccomp.mode) != VX_OK) {
            fprintf(stderr, "unknown --seccomp mode \"%s\" (want off|audit|errno|kill)\n",
                    o.seccomp);
            return 2;
        }
    }
    if (o.deny_ptrace) spec.seccomp.allow_ptrace = false;
    if (o.allow_nsops) spec.seccomp.deny_namespace_calls = false;
    if (o.host_uid >= 0) {
        spec.host_uid = (uid_t)o.host_uid;
        spec.host_gid = (gid_t)o.host_uid;
    }

    vx_signal_install();

    vx_sandbox_t sb;
    vx_status_t st = vx_sandbox_spawn(&sb, &spec);
    if (st != VX_OK) {
        fprintf(stderr, "spawn failed: %s (%s)\n", vx_status_name(st), vx_status_str(st));
        return 1;
    }

    vx_sandbox_result_t res;
    st = vx_sandbox_wait(&sb, spec.timeout_ms, &res);
    if (st != VX_OK) {
        fprintf(stderr, "wait failed: %s\n", vx_status_str(st));
        vx_sandbox_destroy(&sb);
        return 1;
    }

    fprintf(stderr,
            "state=%s exit=%d signal=%d duration_us=%llu mem_peak=%llu cpu_us=%llu oom=%llu\n",
            vx_state_str(res.state), res.exit_code, res.term_signal,
            (unsigned long long)res.duration_us, (unsigned long long)res.usage.memory_peak,
            (unsigned long long)res.usage.cpu_usage_us, (unsigned long long)res.usage.oom_kill);

    vx_sandbox_destroy(&sb);
    vx_signal_uninstall();
    return res.exit_code;
}

static int cmd_encode_task(int argc, char **argv) {
    opts_t o;
    opts_init(&o);
    if (parse_opts(argc, argv, &o) < 0) return 2;

    vx_engine_type_t engine = ENGINE_ION;
    if (strcmp(o.engine, "iron") == 0)
        engine = ENGINE_IRON;
    else if (strcmp(o.engine, "ion") != 0) {
        fprintf(stderr, "unknown engine \"%s\" (want ion|iron)\n", o.engine);
        return 2;
    }

    size_t plen = o.payload != NULL ? strlen(o.payload) : 0;
    size_t cap = VX_TASK_HEADER_SIZE + plen;
    unsigned char *buf = malloc(cap);
    if (buf == NULL) return 1;

    long n = vx_task_encode(buf, cap, o.task_id, o.tenant, engine, o.mem, o.cpu, o.payload, plen);
    if (n < 0) {
        fprintf(stderr, "encode failed: %s\n", vx_status_str((int)n));
        free(buf);
        return 1;
    }
    if (isatty(STDOUT_FILENO)) {
        fprintf(stderr, "refusing to write %ld binary bytes to a terminal; redirect stdout\n", n);
        free(buf);
        return 2;
    }
    size_t written = fwrite(buf, 1, (size_t)n, stdout);
    free(buf);
    if (written != (size_t)n) return 1;
    fprintf(stderr, "wrote %ld bytes (%u header + %zu payload)\n", n, VX_TASK_HEADER_SIZE, plen);
    return 0;
}

static int cmd_decode_task(int argc, char **argv) {
    FILE *in = stdin;
    if (argc > 1 && argv[1][0] != '-') {
        in = fopen(argv[1], "rb");
        if (in == NULL) {
            fprintf(stderr, "cannot open %s: %s\n", argv[1], strerror(errno));
            return 1;
        }
    }

    unsigned char buf[VX_TASK_HEADER_SIZE + 4096];
    size_t n = fread(buf, 1, sizeof(buf), in);
    if (in != stdin) fclose(in);

    const vx_task_header_t *hdr = NULL;
    vx_status_t st = vx_task_decode(buf, n, &hdr);
    if (st != VX_OK) {
        fprintf(stderr, "invalid task frame: %s (%s)\n", vx_status_name(st), vx_status_str(st));
        return 1;
    }
    char desc[256];
    vx_task_describe(hdr, desc, sizeof(desc));
    printf("%s\n", desc);
    if (hdr->payload_len > 0) {
        printf("payload: %.*s\n", (int)hdr->payload_len, (const char *)hdr->payload);
    }
    return 0;
}

static int cmd_ring(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "vxworker ring: need a subcommand (create|push|pop|info|unlink)\n");
        return 2;
    }
    const char *sub = argv[1];

    opts_t o;
    opts_init(&o);
    if (parse_opts(argc, argv, &o) < 0) return 2;

    if (strcmp(sub, "create") == 0) {
        vx_ring_t *r = NULL;
        vx_status_t st = vx_ring_create(&r, o.name, o.slots, o.slot_bytes);
        if (st != VX_OK) {
            fprintf(stderr, "ring create failed: %s\n", vx_status_str(st));
            return 1;
        }
        vx_ring_stats_t s;
        vx_ring_stats(r, &s);
        printf("created /vxring.%s: %u slots x %u bytes (%llu bytes mapped, lock_free=%s)\n",
               o.name, s.slot_count, s.slot_bytes, (unsigned long long)s.map_bytes,
               yn(s.lock_free));
        vx_ring_close(r);
        return 0;
    }
    if (strcmp(sub, "unlink") == 0) {
        vx_status_t st = vx_ring_unlink(o.name);
        printf("%s /vxring.%s\n", st == VX_OK ? "unlinked" : "failed to unlink", o.name);
        return st == VX_OK ? 0 : 1;
    }

    vx_ring_t *r = NULL;
    vx_status_t st = vx_ring_open(&r, o.name, strcmp(sub, "info") == 0);
    if (st != VX_OK) {
        fprintf(stderr, "ring open failed: %s (create it first?)\n", vx_status_str(st));
        return 1;
    }

    int rc = 0;
    if (strcmp(sub, "push") == 0) {
        const char *msg = o.payload != NULL ? o.payload : "ping";
        st = vx_ring_push(r, msg, (uint32_t)strlen(msg));
        printf("push %s: %s\n", msg, vx_status_name(st));
        rc = st == VX_OK ? 0 : 1;
    } else if (strcmp(sub, "pop") == 0) {
        unsigned char buf[VX_RING_SLOT_BYTES_DEFAULT];
        uint32_t len = 0;
        st = vx_ring_pop(r, buf, sizeof(buf), &len);
        if (st == VX_OK)
            printf("pop %u bytes: %.*s\n", len, (int)len, (const char *)buf);
        else
            printf("pop: %s\n", vx_status_name(st));
        rc = st == VX_OK ? 0 : 1;
    } else if (strcmp(sub, "info") == 0) {
        vx_ring_stats_t s;
        vx_ring_stats(r, &s);
        printf("slots       %u\n", s.slot_count);
        printf("slot_bytes  %u\n", s.slot_bytes);
        printf("mapped      %llu\n", (unsigned long long)s.map_bytes);
        printf("produced    %llu\n", (unsigned long long)s.produced);
        printf("consumed    %llu\n", (unsigned long long)s.consumed);
        printf("depth       %llu\n", (unsigned long long)s.depth);
        printf("push_full   %llu\n", (unsigned long long)s.push_full);
        printf("lock_free   %s\n", yn(s.lock_free));
    } else {
        fprintf(stderr, "unknown ring subcommand \"%s\"\n", sub);
        rc = 2;
    }
    vx_ring_close(r);
    return rc;
}

static int cmd_selftest(void) {
    int fails = 0;
    printf("vxworker selftest\n");

    /* ABI roundtrip */
    unsigned char buf[VX_TASK_HEADER_SIZE + 16];
    long n = vx_task_encode(buf, sizeof(buf), 42, "acme", ENGINE_IRON, 128, 25000, "hello", 5);
    const vx_task_header_t *hdr = NULL;
    if (n != VX_TASK_HEADER_SIZE + 5 || vx_task_decode(buf, (size_t)n, &hdr) != VX_OK) {
        printf("  FAIL abi roundtrip\n");
        fails++;
    } else if (hdr->task_id != 42 || hdr->engine != ENGINE_IRON || hdr->payload_len != 5) {
        printf("  FAIL abi field values\n");
        fails++;
    } else {
        printf("  ok   abi roundtrip (%ld bytes)\n", n);
    }

    /* Bad magic must be rejected */
    buf[0] ^= 0xFF;
    if (vx_task_decode(buf, (size_t)n, &hdr) != VX_ERR_BAD_MAGIC) {
        printf("  FAIL bad magic not rejected\n");
        fails++;
    } else {
        printf("  ok   bad magic rejected\n");
    }

    /* Ring roundtrip */
    vx_ring_unlink("selftest");
    vx_ring_t *r = NULL;
    if (vx_ring_create(&r, "selftest", 8, 256) != VX_OK) {
        printf("  FAIL ring create\n");
        fails++;
    } else {
        vx_status_t st = vx_ring_push(r, "abc", 3);
        unsigned char out[256];
        uint32_t len = 0;
        vx_status_t st2 = vx_ring_pop(r, out, sizeof(out), &len);
        if (st != VX_OK || st2 != VX_OK || len != 3 || memcmp(out, "abc", 3) != 0) {
            printf("  FAIL ring roundtrip\n");
            fails++;
        } else {
            printf("  ok   ring roundtrip\n");
        }
        if (vx_ring_pop(r, out, sizeof(out), &len) != VX_ERR_RING_EMPTY) {
            printf("  FAIL empty ring not reported\n");
            fails++;
        } else {
            printf("  ok   empty ring reported\n");
        }
        vx_ring_close(r);
        vx_ring_unlink("selftest");
    }

    /* Capability probe should not error out */
    vx_sandbox_caps_t caps;
    if (vx_sandbox_probe(&caps) != VX_OK) {
        printf("  FAIL capability probe\n");
        fails++;
    } else {
        printf("  ok   capability probe (userns=%s cgroup2=%s)\n", yn(caps.userns),
               yn(caps.cgroup_v2));
    }

    printf("%s\n", fails == 0 ? "selftest PASSED" : "selftest FAILED");
    return fails == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
    vx_log_init_from_env();

    if (argc < 2) {
        usage();
        return 2;
    }
    const char *cmd = argv[1];

    if (strcmp(cmd, "abi") == 0) return cmd_abi();
    if (strcmp(cmd, "probe") == 0) return cmd_probe();
    if (strcmp(cmd, "run") == 0) return cmd_run(argc - 1, argv + 1);
    if (strcmp(cmd, "encode-task") == 0) return cmd_encode_task(argc - 1, argv + 1);
    if (strcmp(cmd, "decode-task") == 0) return cmd_decode_task(argc - 1, argv + 1);
    if (strcmp(cmd, "ring") == 0) return cmd_ring(argc - 1, argv + 1);
    if (strcmp(cmd, "selftest") == 0) return cmd_selftest();
    if (strcmp(cmd, "version") == 0 || strcmp(cmd, "--version") == 0) {
        printf("vxworker %s (ABI v%u)\n", VXWORKER_VERSION, VX_ABI_VERSION);
        return 0;
    }
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        usage();
        return 0;
    }

    fprintf(stderr, "unknown command \"%s\"\n\n", cmd);
    usage();
    return 2;
}
