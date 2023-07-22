#ifndef __SYSCALL_BPF_H
#define __SYSCALL_BPF_H

static __always_inline int 
handle_sys_enter(struct trace_event_raw_sys_enter *ctx){
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct syscall_key_t key = {.id = ctx->id};
    CHECKLEVEL(task);
    CHECKCG;
    if(!get_cont_id(task,key.cid)) return 0;
    u32 zero = 0;
    u32 *value;
    value = bpf_map_lookup_or_try_init(&syscall_count_map,&key,&zero);
    if(!value) return 0;
    (*value)++;
    bpf_printk("%s,%u:%u",key.cid,key.id,*value);
    return 0;
}

#endif