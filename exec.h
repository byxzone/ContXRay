#ifndef __EXEC_H
#define __EXEC_H

#include <bpf/libbpf.h>

#include "contxray.h"
#include "contxray.skel.h"

static inline int handle_exec_event(struct exec_event *data){
    printf("[exec]args:%s\n",data->args);
    return 0;
}

#endif