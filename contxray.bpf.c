// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "contxray.h"

#include "maps.bpf.h"
#include "cont.bpf.h"
#include "syscall.bpf.h"
#include "exec.bpf.h"


SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	return handle_sys_enter(ctx);
}


SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_exit_execve(struct trace_event_raw_sys_enter* ctx)
{
	return handle_sys_enter_execve(ctx);
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";