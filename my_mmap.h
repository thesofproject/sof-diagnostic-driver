/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
 *
 *  This file is provided under a dual BSD/GPLv2 license.  When using or
 *  redistributing this file, you may do so under either license.
 *
 *  Copyright(c) 2019 Intel Corporation. All rights reserved.
 *
 *  Author: Marcin Zielinski <marcinx.zielinski@linux.intel.com>
 */

#ifndef MY_MMAP_H
#define MY_MMAP_H

#include <linux/fs.h>
#include <linux/mm.h>

/**
 * describe_retval() - Informs about an operation's failure/success.
 * @status: operation's real return value
 * @ok_val: expected operation's return value
 * @op: operation's name/description
 */
static inline void describe_retval(long status, long ok_val, const char *op)
{
	if (status != ok_val) {
		pr_crit("[SOF] %s failed", op);
		return;
	}

	pr_info("[SOF] %s succeeded", op);
}

/**
 * simple_remap_mmap() - Thin wrapper of kernel's :c:func:`remap_pfn_range`.
 * @filp: unused
 * @vma: see :c:type:`vm_area_struct`.
 *
 * Return: 0 on success, negative value on error.
 */
int simple_remap_mmap(struct file *filp, struct vm_area_struct *vma);

#endif /* MY_MMAP_H */
