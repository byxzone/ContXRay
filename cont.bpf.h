#ifndef __CONT_BPF_H
#define __CONT_BPF_H

#define CHECKLEVEL(task) if(!get_level(task) && !filter_cg) return 0;
#define CHECKCG if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0)) return 0;

const int filter_cg = 0;

static __always_inline int 
get_cont_id(struct task_struct *task, char *cid){
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

static __always_inline int 
get_level(struct task_struct *task){
    int level = BPF_CORE_READ(task,nsproxy,pid_ns_for_children,level);
    return level;
}

#endif