// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "maps.bpf.h"

#include "contxray.h"

#define CHECKLEVEL(task) if(!get_level(task)) return 0

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, struct syscall_key_t);
	__type(value, u32);
} syscall_count_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");


static int get_cont_id(struct task_struct *task, char *cid){
    struct kernfs_node  *knode;
    knode = BPF_CORE_READ(task,cgroups,subsys[0],cgroup,kn);
    if(knode != NULL) {
        char *long_cid;
        long_cid = (char *)BPF_CORE_READ(knode,name);
        int err = bpf_probe_read(cid,CONTAINER_ID_SHORT_LEN,long_cid+CONTAINER_ID_OFFSET+1);
        if(err)
            return err;
        cid[CONTAINER_ID_SHORT_LEN] = 0;
    }
    else
        return 0;
    return 1;
}

static int get_level(struct task_struct *task){
    int level = BPF_CORE_READ(task,nsproxy,pid_ns_for_children,level);
    return level;
}

SEC("tp/raw_syscalls/sys_enter")
int handle_exec(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct syscall_key_t key = {.id = ctx->id};
    CHECKLEVEL(task);
    if(!get_cont_id(task,key.cid)) return 0;
    u32 zero = 0;
    u32 *value;
    value = bpf_map_lookup_or_try_init(&syscall_count_map,&key,&zero);
    if(!value) return 0;
    (*value)++;
    bpf_printk("%s,%u:%u",key.cid,key.id,*value);
    return 0;
}
