#ifndef __CSYSCALL_H
#define __CSYSCALL_H

#include "res/syscall_tbl.h"

static inline int handle_syscall_count_map(const struct bpf_map *map){
	struct syscall_key_t *cur_key = NULL;
	struct syscall_key_t next_key;
	int ret = 0;
	while(ret == 0){
		ret = bpf_map__get_next_key(map, &cur_key,&next_key, sizeof(struct syscall_key_t));
		if(ret != 0) break;
		int value;
		printf("[syscall]cid:%s,%s",next_key.cid,syscall_trans_to_name(x86_64,next_key.id));
		bpf_map__lookup_and_delete_elem(map, &next_key, sizeof(struct syscall_key_t), &value,sizeof(u32), 0);
		printf(":%u\n",value);
		cur_key = &next_key;
		
	}
	return 0;
}

#endif