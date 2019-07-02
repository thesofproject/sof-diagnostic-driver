/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
 *
 *  This file is provided under a dual BSD/GPLv2 license.  When using or
 *  redistributing this file, you may do so under either license.
 *
 *  Copyright(c) 2019 Intel Corporation. All rights reserved.
 *
 *  Author: Marcin Zielinski <marcinx.zielinski@linux.intel.com>
 */

#ifndef DRIVER_H
#define DRIVER_H

#include "ioctl.h"

#include <linux/build_bug.h>
#include <linux/cdev.h>
#include <linux/pci.h>
#include <linux/uaccess.h>

static_assert (PCIBIOS_SUCCESSFUL == 0);

/**
 * enum pci_device_id_e - Kind of the diagnostic device.
 * @DIAG_START: enum start marker
 * @DIAG_HDA: HDA device
 * @DIAG_DSP: DSP device
 * @DIAG_COUNT: enum end/count marker
 */
enum diag_dev_kind_t {
	DIAG_START,

	DIAG_HDA = DIAG_START,
	DIAG_DSP,

	DIAG_COUNT
};

/**
 * MAX_ALLOC_MAPS - Max allocations that can be performed on the driver.
 */
#define MAX_ALLOC_MAPS 16

/**
 * struct diag_mem_map_t - Map of allocations performed on the driver.
 * @kernel_virt_addr: kernel virtual memory address
 * @physical: physical address
 */
struct diag_mem_map_t {
	void *kernel_virt_addr;
	phys_addr_t physical;
} __packed;

/**
 * struct diag_dev_inst_t - Driver instance corresponding to an opened device.
 * @bar: PCI Base Address Register
 * @mcdev: character device
 */
struct diag_dev_inst_t {
	struct diag_hda_bar_t bar;
	struct cdev mcdev;
} __packed;

/**
 * struct diag_driver_t - Diagnostic driver's global instance.
 * @dev_id: PCI device id
 * @devices:	array of open devices, one per kind;
 *				see :c:type:`diag_dev_kind_t`
 * @dev_num: device's system-wide number
 * @cls: device's system-wide class
 * @alloc_desc: array of descriptors of the memory allocations
				performed on the driver
 */
struct diag_driver_t {
	unsigned int dev_id;
	struct diag_dev_inst_t devices[DIAG_COUNT];
	dev_t dev_num;
	struct class *cls;
	struct diag_mem_map_t alloc_desc[MAX_ALLOC_MAPS];
} __packed;

/**
 * copy_to_user_and_check() - Kernel to user data copy and status check.
 * @to: user's buffer to copy the data to
 * @from: kernel's buffer to copy the data from
 * @n: count of the bytes to copy
 * @on_err: value to be returned on error
 *
 * Return: 0 on success, see :c:data:`on_err` on error.
 */
static __always_inline long __must_check copy_to_user_and_check(
	void __user *to, const void *from, uint32_t n, int on_err)
{
	long ret = (long)copy_to_user(to, from, (unsigned long)n);

	return (ret == 0) ? ret : on_err;
}

/**
 * copy_from_user_and_check() - User to kernel data copy and status check.
 * @to: kernel's buffer to copy the data to
 * @from: user's buffer to copy the data from
 * @n: count of the bytes to copy
 * @on_err: value to be returned on error
 *
 * Return: 0 on success, see :c:data:`on_err` on error.
 */
static __always_inline long __must_check copy_from_user_and_check(
	void *to, const void __user *from, uint32_t n, int on_err)
{
	long ret = (long)copy_from_user(to, from, (unsigned long)n);

	return (ret <= 0) ? ret : on_err;
}

#endif /* DRIVER_H */
