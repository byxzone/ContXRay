#ifndef __COMMON_H
#define __COMMON_H

#include <argp.h>
#include <bpf/libbpf.h>

const char logo[] = " \n \
   _____            _  __   _______              \n \
  / ____|          | | \\ \\ / /  __ \\             \n \
 | |     ___  _ __ | |_ \\ V /| |__) |__ _ _   _  \n \
 | |    / _ \\| '_ \\| __| > < |  _  // _` | | | | \n \
 | |___| (_) | | | | |_ / . \\| | \\ \\ (_| | |_| | \n \
  \\_____\\___/|_| |_|\\__/_/ \\_\\_|  \\_\\__,_|\\__, | \n \
                                           __/ | \n \
                                          |___/  \n ";


const char *argp_program_version = "contxray 0.1";
const char *argp_program_bug_address = "<i@barryx.cn>";
const char argp_program_doc[] = " ";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "time", 't', "TIME-SEC", 0, "Max Running Time(0 for infinite)" },
	{},
};

static volatile bool exiting = false;

static struct env {
	bool verbose;
	long min_duration_ms;
} env;


#endif
