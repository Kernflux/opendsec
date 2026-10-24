// uffdwp: does userfaultfd async write protection (UFFD_FEATURE_WP_ASYNC +
// PAGEMAP_SCAN) work for what a Firecracker VM's memory is (spec §19.14)?
// Build with gcc -O2 -o uffdwp uffdwp.c; results are in the spec.
//
//   uffdwp file PATH MB   MAP_PRIVATE mapping of a file (restored VMs)
//   uffdwp anon MB [nowp] anonymous THP memory (cold-booted VMs)
//
// Env UMODE=1 creates the uffd with UFFD_USER_MODE_ONLY (unprivileged).
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <linux/userfaultfd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define PG 4096UL

static double now(void) {
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec + t.tv_nsec / 1e9;
}

static void die(const char *m) {
	fprintf(stderr, "FAIL %s: %s\n", m, strerror(errno));
	exit(1);
}

static int uffd_open(void) {
	int flags = O_CLOEXEC | O_NONBLOCK;
	if (getenv("UMODE")) flags |= UFFD_USER_MODE_ONLY;
	int fd = syscall(__NR_userfaultfd, flags);
	if (fd < 0) die("userfaultfd");
	struct uffdio_api api = {.api = UFFD_API, .features = UFFD_FEATURE_WP_ASYNC | UFFD_FEATURE_WP_UNPOPULATED};
	if (ioctl(fd, UFFDIO_API, &api)) die("UFFDIO_API");
	printf("uffd: user_mode_only=%d features ok (wp_async=%d)\n", getenv("UMODE") != NULL,
	       !!(api.features & UFFD_FEATURE_WP_ASYNC));
	return fd;
}

static void wp_register(int fd, char *p, size_t len) {
	struct uffdio_register r = {.range = {.start = (uintptr_t)p, .len = len}, .mode = UFFDIO_REGISTER_MODE_WP};
	if (ioctl(fd, UFFDIO_REGISTER, &r)) die("UFFDIO_REGISTER(WP)");
	struct uffdio_writeprotect w = {.range = {.start = (uintptr_t)p, .len = len}, .mode = UFFDIO_WRITEPROTECT_MODE_WP};
	if (ioctl(fd, UFFDIO_WRITEPROTECT, &w)) die("UFFDIO_WRITEPROTECT");
}

// scan returns the written pages (and write-protects them again); ranges
// and the largest range are reported.
static long scan(int pm, char *p, size_t len, char *mark, int quiet) {
	static struct page_region vec[1 << 16];
	long pages = 0, ranges = 0, maxr = 0;
	uint64_t start = (uintptr_t)p, end = start + len;
	while (start < end) {
		struct pm_scan_arg a = {.size = sizeof a, .flags = PM_SCAN_WP_MATCHING | PM_SCAN_CHECK_WPASYNC,
					.start = start, .end = end, .vec = (uintptr_t)vec, .vec_len = 1 << 16,
					.category_mask = PAGE_IS_WRITTEN, .return_mask = PAGE_IS_WRITTEN};
		long n = ioctl(pm, PAGEMAP_SCAN, &a);
		if (n < 0) die("PAGEMAP_SCAN");
		for (long i = 0; i < n; i++) {
			long np = (vec[i].end - vec[i].start) / PG;
			pages += np, ranges++;
			if (np > maxr) maxr = np;
			if (mark)
				for (uint64_t q = vec[i].start; q < vec[i].end; q += PG) mark[(q - (uintptr_t)p) / PG] = 1;
		}
		start = a.walk_end;
		if (n == 0 && a.walk_end >= end) break;
	}
	if (!quiet) printf("  scan: %ld pages written in %ld ranges (largest %ld pages)\n", pages, ranges, maxr);
	return pages;
}

static void smaps(char *p, const char *label) {
	FILE *f = fopen("/proc/self/smaps", "r");
	char line[256];
	int in = 0;
	char want[32];
	snprintf(want, sizeof want, "%lx-", (unsigned long)p);
	printf("  smaps %s:", label);
	while (fgets(line, sizeof line, f)) {
		if (strchr(line, '-') && strchr(line, ' ') && strchr(line, '-') < strchr(line, ' ')) in = !strncmp(line, want, strlen(want));
		else if (in && (!strncmp(line, "Rss:", 4) || !strncmp(line, "Shared_Clean:", 13) || !strncmp(line, "Private_Clean:", 14) ||
				!strncmp(line, "Private_Dirty:", 14) || !strncmp(line, "AnonHugePages:", 14))) {
			line[strcspn(line, "\n")] = 0;
			char k[32]; long v;
			sscanf(line, "%31s %ld", k, &v);
			printf(" %s%ldMB", k, v >> 10);
		}
	}
	printf("\n");
	fclose(f);
}

static int check(const char *what, char *got, char *want, size_t n) {
	long miss = 0, extra = 0;
	for (size_t i = 0; i < n; i++) {
		if (want[i] && !got[i]) miss++;
		if (!want[i] && got[i]) extra++;
	}
	printf("  %s: %s (missed %ld, extra %ld)\n", what, miss || extra ? "MISMATCH" : "exact", miss, extra);
	return miss == 0;
}

static int file_mode(const char *path, size_t mb) {
	size_t len = mb << 20, n = len / PG;
	int fd = open(path, O_RDONLY);
	if (fd < 0) die("open");
	char *p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED) die("mmap");
	volatile unsigned long sum = 0;
	if (getenv("PREREAD")) {  // populate (read-only) before protecting
		for (size_t i = 0; i < n; i++) sum += p[i * PG];
		smaps(p, "read before protect");
	}
	if (getenv("NOWP")) {
		for (size_t i = 0; i < n; i++) sum += p[i * PG];
		smaps(p, "no WP, read all");
		return 0;
	}
	int u = uffd_open();
	wp_register(u, p, len);
	printf("file %s: %zu MB MAP_PRIVATE, registered for WP: ok\n", path, mb);
	int pm = open("/proc/self/pagemap", O_RDONLY);
	if (pm < 0) die("pagemap");
	for (size_t i = 0; i < n; i++) sum += p[i * PG];  // read everything
	smaps(p, "protected, read all");
	char *want = calloc(n, 1), *got = calloc(n, 1);
	for (size_t i = 0; i < n; i += 97) p[i * PG + 5] ^= 1, want[i] = 1;  // user writes
	// Kernel writes into the mapping (as KVM's or a device's): pread.
	int rfd = open(path, O_RDONLY);
	for (size_t i = 50; i < n; i += 1000) {
		if (pread(rfd, p + i * PG, PG, 0) != (ssize_t)PG) die("pread into mapping");
		want[i] = 1;
	}
	smaps(p, "after reading all, writing some");
	scan(pm, p, len, got, 0);
	int ok = check("round 1 (user + kernel writes)", got, want, n);
	memset(want, 0, n), memset(got, 0, n);
	for (size_t i = 3; i < n; i += 211) p[i * PG] ^= 1, want[i] = 1;
	scan(pm, p, len, got, 0);
	ok &= check("round 2 (after re-protect)", got, want, n);
	printf("sum %lu\n", sum);
	if (getenv("HOLD")) {  // keep the mapping for a second process to share
		sleep(atoi(getenv("HOLD")));
		smaps(p, "at the end");
	}
	return ok ? 0 : 2;
}

static int anon_mode(size_t mb, int wp) {
	size_t len = mb << 20, n = len / PG;
	char *raw = mmap(NULL, len + (2 << 20), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (raw == MAP_FAILED) die("mmap");
	char *p = (char *)(((uintptr_t)raw + (2 << 20) - 1) & ~((uintptr_t)(2 << 20) - 1));
	madvise(p, len, MADV_HUGEPAGE);
	for (size_t i = 0; i < n; i++) p[i * PG] = 1;  // populate (as a guest that touched it)
	printf("anon %zu MB wp=%d\n", mb, wp);
	smaps(p, "populated");
	int pm = open("/proc/self/pagemap", O_RDONLY), u = -1;
	if (wp) {
		u = uffd_open();
		wp_register(u, p, len);
		smaps(p, "protected");
	}
	double t = now();
	for (size_t i = 0; i < n; i++) p[i * PG] = 2;  // first write after protect
	printf("  first write, every page: %.0f ms\n", (now() - t) * 1e3);
	t = now();
	for (size_t i = 0; i < n; i++) p[i * PG] = 3;
	printf("  rewrite, every page: %.0f ms\n", (now() - t) * 1e3);
	smaps(p, "written");
	if (wp) {
		scan(pm, p, len, NULL, 0);
		// One byte in one 2 MB region: how much is reported?
		p[(2 << 20) * 3 + 100] = 9;
		long k = scan(pm, p, len, NULL, 1);
		printf("  one byte written -> %ld pages reported (%s)\n", k, k == 1 ? "4K precise" : "coarse");
		t = now();
		for (size_t i = 0; i < n; i++) p[i * PG] = 4;
		printf("  write after re-protect, every page: %.0f ms\n", (now() - t) * 1e3);
		smaps(p, "after re-protect and write");
	}
	// A random 8-byte workload over everything (TLB sensitive).
	t = now();
	uint64_t x = 88172645463325252ULL;
	for (long i = 0; i < 20000000; i++) {
		x ^= x << 13, x ^= x >> 7, x ^= x << 17;
		((volatile uint64_t *)p)[x % (len / 8)] += 1;
	}
	printf("  random 8-byte rw: %.1f Mops/s\n", 20.0 / (now() - t));
	return 0;
}

int main(int argc, char **argv) {
	if (argc >= 4 && !strcmp(argv[1], "file")) return file_mode(argv[2], atol(argv[3]));
	if (argc >= 3 && !strcmp(argv[1], "anon")) return anon_mode(atol(argv[2]), !(argc > 3 && !strcmp(argv[3], "nowp")));
	fprintf(stderr, "usage: uffdwp file PATH MB | uffdwp anon MB [nowp]\n");
	return 1;
}
