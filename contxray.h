/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef _CONTXRAY_H
#define _CONTXRAY_H

#define u8 unsigned char
#define u16 unsigned short
#define u32 unsigned int
#define u64 unsigned long long

#define CONTAINER_ID_LEN 32
#define CONTAINER_ID_SHORT_LEN 4
#define CONTAINER_ID_OFFSET 6

struct syscall_key_t{
    u32  id;
    char cid[CONTAINER_ID_SHORT_LEN];
};

#endif