// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// dev_t is defined in vmlinux.h and the sizeof(dev_t) == 4.
const volatile dev_t value = 0;

SEC("raw_tp/sched_process_exit")
int handle_tp(void *ctx)
{
	bpf_printk("BPF triggered and print value %d.\n", value);
	return 0;
}
