/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __CONTXRAY_H
#define __CONTXRAY_H

#define u8 unsigned char
#define u16 unsigned short
#define u32 unsigned int
#define u64 unsigned long long

#define CONTAINER_ID_LEN 32
#define CONTAINER_ID_SHORT_LEN 4
#define CONTAINER_ID_OFFSET 6

#define ARGSIZE  128
#define TASK_COMM_LEN 16
#define TOTAL_MAX_ARGS 60
#define DEFAULT_MAXARGS 20
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

struct syscall_key_t{
    u32  id;
    char cid[CONTAINER_ID_SHORT_LEN];
};

struct common_event{
	int type;
	char cid[CONTAINER_ID_SHORT_LEN];
	pid_t pid;
	pid_t ppid;
	char comm[TASK_COMM_LEN];
};

struct exec_event {
    struct common_event common;
    int args_count;
	unsigned int args_size;
	char args[FULL_MAX_ARGS_ARR];
};

#endif