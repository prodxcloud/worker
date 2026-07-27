# prodxcloud/worker — pure C11 system ABI and isolation layer.
#
# No external dependencies: libc and the Linux kernel only.  Builds with gcc or
# clang; the sandbox tests need root (or CAP_SYS_ADMIN) and a cgroup2 mount, and
# skip themselves cleanly when they do not have it.

CC      ?= cc
AR      ?= ar
PREFIX  ?= /usr/local

# -D_GNU_SOURCE for CLONE_*, execvpe, pipe2, signalfd.
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -D_GNU_SOURCE -Iinclude
CFLAGS  += -Wall -Wextra -Wpedantic -Werror -Wshadow -Wconversion -Wsign-conversion \
           -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes -Wpointer-arith \
           -Wwrite-strings -Wvla
CFLAGS  += -fno-common -fstack-protector-strong -D_FORTIFY_SOURCE=2
LDFLAGS ?=
LDLIBS  += -pthread

# The sandbox is Linux-specific by construction; fail loudly elsewhere.
UNAME_S := $(shell uname -s)
ifneq ($(UNAME_S),Linux)
$(error prodxcloud/worker targets Linux only (namespaces + cgroups v2); got $(UNAME_S))
endif

# Each configuration gets its own directory.  Sharing one meant a sanitizer
# build left instrumented object files behind, and the next plain `make` failed
# to link with undefined __asan_* symbols — a confusing failure a long way from
# its cause.
BUILD   ?= build
LIB     := $(BUILD)/libvxworker.a
BIN     := $(BUILD)/vxworker

LIB_SRCS := src/vx_error.c src/vx_log.c src/vx_task.c src/vx_ipc.c src/vx_cgroup.c \
            src/vx_signal.c src/vx_seccomp.c src/vx_sandbox.c
LIB_OBJS := $(LIB_SRCS:src/%.c=$(BUILD)/%.o)

TEST_SRCS := $(wildcard tests/test_*.c)
TEST_BINS := $(TEST_SRCS:tests/%.c=$(BUILD)/%)

BENCH_SRCS := $(wildcard bench/bench_*.c)
BENCH_BINS := $(BENCH_SRCS:bench/%.c=$(BUILD)/%)

.PHONY: all clean test check bench install uninstall format asan tsan help

all: $(LIB) $(BIN)

$(BUILD):
	@mkdir -p $(BUILD)

$(BUILD)/%.o: src/%.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB): $(LIB_OBJS)
	$(AR) rcs $@ $^

$(BIN): $(BUILD)/main.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIB) $(LDLIBS)

$(BUILD)/test_%: tests/test_%.c $(LIB) | $(BUILD)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIB) $(LDLIBS)

$(BUILD)/bench_%: bench/bench_%.c $(LIB) | $(BUILD)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIB) $(LDLIBS)

test: $(TEST_BINS)
	@bash tests/run_tests.sh $(TEST_BINS)

check: all test

bench: $(BENCH_BINS)
	@for b in $(BENCH_BINS); do echo "== $$b"; $$b || exit 1; done

# ASan and UBSan together catch the whole class of bug this codebase is exposed
# to: raw pointer arithmetic into an mmap'd region and packed-struct reads.
#
# Recursive make with its own BUILD dir, so an instrumented build never leaves
# objects behind that a later plain build would try to link.
asan:
	@$(MAKE) --no-print-directory BUILD=build-asan \
	    CFLAGS="$(CFLAGS) -fsanitize=address,undefined -fno-omit-frame-pointer -O1" \
	    LDFLAGS="$(LDFLAGS) -fsanitize=address,undefined" run-tests

# TSan validates the ring's memory ordering under real contention.  See
# tests/run_tsan.sh for why the runner distinguishes a race report from TSan's
# environment-dependent teardown abort.
tsan:
	@$(MAKE) --no-print-directory BUILD=build-tsan \
	    CFLAGS="$(CFLAGS) -fsanitize=thread -fno-omit-frame-pointer -O1" \
	    LDFLAGS="$(LDFLAGS) -fsanitize=thread" run-tsan

.PHONY: run-tests run-tsan
run-tests: $(TEST_BINS)
	@bash tests/run_tests.sh $(TEST_BINS)

run-tsan: $(BUILD)/test_ipc
	@bash tests/run_tsan.sh $(BUILD)/test_ipc

install: all
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/lib $(DESTDIR)$(PREFIX)/include/vx
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/
	install -m 0644 $(LIB) $(DESTDIR)$(PREFIX)/lib/
	install -m 0644 include/*.h $(DESTDIR)$(PREFIX)/include/vx/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/vxworker $(DESTDIR)$(PREFIX)/lib/libvxworker.a
	rm -rf $(DESTDIR)$(PREFIX)/include/vx

format:
	clang-format -i include/*.h src/*.c tests/*.c bench/*.c

clean:
	rm -rf build build-asan build-tsan

help:
	@echo "targets: all test check bench asan tsan install format clean"
