// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright (c) 2020 Anton Protopopov
#ifndef __MAPS_BPF_H
#define __MAPS_BPF_H

#include <bpf/bpf_helpers.h>
#include <asm-generic/errno.h>

static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init)
{
	void *val;
	long err;
	val = bpf_map_lookup_elem(map, key);
	if (val)
		return val;
	err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
	if (err && err != -EEXIST)
		return 0;
	return bpf_map_lookup_elem(map, key);
}

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

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

#endif /* __MAPS_BPF_H */