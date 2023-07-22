#ifndef __EXEC_BPF_H
#define __EXEC_BPF_H

const volatile int max_args = DEFAULT_MAXARGS;

static __always_inline int 
handle_sys_enter_execve(struct trace_event_raw_sys_enter* ctx){
    u64 id;
	pid_t pid, tgid;
	
	struct task_struct *task  = (struct task_struct*)bpf_get_current_task();
	const char **args = (const char **)(ctx->args[1]);
	const char *argp;

	id = bpf_get_current_pid_tgid();
	pid = (pid_t)id;
	tgid = id >> 32;

    CHECKLEVEL(task);
    CHECKCG;

    struct exec_event *event;
    event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	event->common.pid = tgid;
	event->common.ppid = (pid_t)BPF_CORE_READ(task, real_parent, tgid);
	event->args_count = 0;
	event->args_size = 0;
    bpf_get_current_comm(&event->common.comm, TASK_COMM_LEN);

	unsigned int ret = bpf_probe_read_user_str(event->args, ARGSIZE, (const char*)ctx->args[0]);
	if (ret <= ARGSIZE) {
		event->args_size += ret;
	} else {
		/* write an empty string */
		event->args[0] = '\0';
		event->args_size++;
	}

	event->args_count++;
	#pragma unroll
	for (int i = 1; i < TOTAL_MAX_ARGS && i < max_args; i++) {
		bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
		if (!argp)
			return 0;

		if (event->args_size > LAST_ARG)
			return 0;

		ret = bpf_probe_read_user_str(&event->args[event->args_size], ARGSIZE, argp);
		if (ret > ARGSIZE)
			return 0;

		event->args_count++;
		event->args_size += ret;
	}
	/* try to read one more argument to check if there is one */
	bpf_probe_read_user(&argp, sizeof(argp), &args[max_args]);
	if (!argp)
		return 0;

	/* pointer to max_args+1 isn't null, asume we have more arguments */
	event->args_count++;

    bpf_ringbuf_submit(event, 0);
	return 0;
}


#endif