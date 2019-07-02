/* SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
 *
 *  This file is provided under a dual BSD/GPLv2 license.  When using or
 *  redistributing this file, you may do so under either license.
 *
 *  Copyright(c) 2019 Intel Corporation. All rights reserved.
 *
 *  Author: Marcin Zielinski <marcinx.zielinski@linux.intel.com>
 */

#ifndef IOCTL_H
#define IOCTL_H

#include <linux/types.h>
#include <linux/uaccess.h>

/**
 * enum diag_drv_ioctl_e - Supported IOCTLs.
 * @CMD_OPEN_DEVICE: open device
 * @CMD_ALLOC_MEMORY: allocate memory
 * @CMD_FREE_MEMORY: free memory
 * @HDABUSTEST_READ_PCICONF: read PCI config
 * @HDABUSTEST_WRITE_PCICONF: write PCI config
 */
enum diag_drv_ioctl_e {
	CMD_OPEN_DEVICE = 0x047,
	CMD_ALLOC_MEMORY = 0x03A,
	CMD_FREE_MEMORY = 0x03B,
	HDABUSTEST_READ_PCICONF = 0x101,
	HDABUSTEST_WRITE_PCICONF = 0x102
};

/**
 * struct diag_hda_bar_t - PCI Base Address Register's descriptor.
 * @base_physical: physical base memory address
 * @base_virtual: virtual base memory pointer
 * @size: size of the memory occupied by the BAR
 */
struct diag_hda_bar_t {
	phys_addr_t base_physical;
	void *base_virtual;
	uint32_t size;
} __packed;

/**
 * struct diag_hda_bus_test_t - HDA memory allocation descriptor.
 * @dma_phys_addr: DMA physical address
 * @dma_virt_addr: DMA virtual address
 * @size: size of the memory allocated
 */
struct diag_hda_bus_test_t {
	phys_addr_t dma_phys_addr;
	phys_addr_t dma_virt_addr;
	uint32_t size;
} __packed;

/**
 * struct diag_dev_handle_t - Opened device's handle.
 * @hda_bar: HDA device's PCI BAR
 * @dsp_bar: DSP device's PCI BAR
 */
struct diag_dev_handle_t {
	struct diag_hda_bar_t hda_bar;
	struct diag_hda_bar_t dsp_bar;
} __packed;

/**
 * struct diag_pci_conf_t - PCI configuration exchange data.
 * @offset: configuration operation's start offset
 * @length: configuration data's length
 * @buffer: configuration data; so-called zero length array in C90
 */
struct diag_pci_conf_t {
	int32_t offset;
	uint32_t length;
	uint8_t buffer[0];
} __packed;

#endif /* IOCTL_H */
