// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/syscall.h>

#include <bpf/libbpf.h>

#include "contxray.h"
#include "contxray.skel.h"

#include "res/syscall_tbl.h"

char logo[] = " \n \
   _____            _  __   _______              \n \
  / ____|          | | \\ \\ / /  __ \\             \n \
 | |     ___  _ __ | |_ \\ V /| |__) |__ _ _   _  \n \
 | |    / _ \\| '_ \\| __| > < |  _  // _` | | | | \n \
 | |___| (_) | | | | |_ / . \\| | \\ \\ (_| | |_| | \n \
  \\_____\\___/|_| |_|\\__/_/ \\_\\_|  \\_\\__,_|\\__, | \n \
                                           __/ | \n \
                                          |___/  \n ";

struct contxray_bpf *skel;

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

const char *argp_program_version = "contxray 0.1";
const char *argp_program_bug_address = "<i@barryx.cn>";
const char argp_program_doc[] = " ";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_syscall_count_map(const struct bpf_map *map){
	struct syscall_key_t *cur_key = NULL;
	struct syscall_key_t next_key;
	int ret = 0;
	while(ret == 0){
		ret = bpf_map__get_next_key(map, &cur_key,&next_key, sizeof(struct syscall_key_t));
		if(ret != 0) break;
		int value;
		printf("%s,%s",next_key.cid,syscall_trans_to_name(x86_64,next_key.id));
		bpf_map__lookup_and_delete_elem(map, &next_key, sizeof(struct syscall_key_t), &value,sizeof(u32), 0);
		printf(":%u\n",value);
		cur_key = &next_key;
		
	}
	return 0;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	
	return 0;
}

int main(int argc, char **argv)
{
	printf("%s\nLoading...",logo);
	struct ring_buffer *rb = NULL;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = contxray_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	

	/* Load & verify BPF programs */
	err = contxray_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = contxray_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
 
	printf("Done\nContXRay is Running now\n");

	/* Process events */
	
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}

		handle_syscall_count_map(skel->maps.syscall_count_map);
		fflush(stdout);
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	contxray_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}