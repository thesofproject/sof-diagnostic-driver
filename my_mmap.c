// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
//
//   This file is provided under a dual BSD/GPLv2 license.  When using or
//   redistributing this file, you may do so under either license.
//
//   Copyright(c) 2019 Intel Corporation. All rights reserved.
//
//   Author: Marcin Zielinski <marcinx.zielinski@linux.intel.com>
//

#include "my_mmap.h"

int simple_remap_mmap(struct file *filp, struct vm_area_struct *vma)
{
	int ret;
	unsigned long size = vma->vm_end - vma->vm_start;

	pr_info("[SOF] (re)mapping memory to user space; start address = %lu, physical address = %lu, size = %lu",
			vma->vm_start, vma->vm_pgoff, size);
	ret = remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff, size,
			PAGE_SHARED);
	describe_retval(ret, 0, "(re)mapping file");
	return ret;
}
