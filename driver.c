// SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
//
//  This file is provided under a dual BSD/GPLv2 license.  When using or
//  redistributing this file, you may do so under either license.
//
//  Copyright(c) 2019 Intel Corporation. All rights reserved.
//
//  Author: Marcin Zielinski <marcinx.zielinski@linux.intel.com>
//

#include "driver.h"
#include "ioctl.h"
#include "my_mmap.h"

#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <uapi/linux/fs.h>

/**
 * DRIVER_NAME - Diagnostic device driver's name.
 */
#define DRIVER_NAME "sof_diag_driver"

/**
 * enum pci_device_id_e - Supported chipset IDs.
 * @PCI_DEVICE_AUDIO_BXT: Broxton
 * @PCI_DEVICE_AUDIO_ICL: Ice Lake
 * @PCI_DEVICE_AUDIO_APL: Apollo Lake
 * @PCI_DEVICE_AUDIO_CNL: Cannon Lake
 * @PCI_DEVICE_AUDIO_CFL: Coffee Lake
 * @PCI_DEVICE_AUDIO_TGL: Tiger Lake
 */
enum pci_device_id_e {
	PCI_DEVICE_AUDIO_BXT = 0x1C20,
	PCI_DEVICE_AUDIO_ICL = 0x35C8,
	PCI_DEVICE_AUDIO_APL = 0x5A98,
	PCI_DEVICE_AUDIO_CNL = 0x9DC8,
	PCI_DEVICE_AUDIO_CFL = 0xA348,
	PCI_DEVICE_AUDIO_TGL = 0xA0C8,
};

/**
 * device_ids[] - Supported chipset IDs in an iterable form.
 */
static const unsigned int device_ids[] = {
	PCI_DEVICE_AUDIO_BXT,
	PCI_DEVICE_AUDIO_ICL,
	PCI_DEVICE_AUDIO_APL,
	PCI_DEVICE_AUDIO_CNL,
	PCI_DEVICE_AUDIO_CFL,
	PCI_DEVICE_AUDIO_TGL,
};

/**
 * driver - Driver global instance.
 */
static struct diag_driver_t driver;

/**
 * diag_open() - Opens a device.
 * @inode: pointer to device's file inode
 * @filp: pointer to device's file representation; pointee is output parameter
 *
 * Does nothing yet actually needed for kernel's bookkeeping.
 *
 * Return: Always 0.
 */
static int diag_open(struct inode *inode, struct file *filp)
{
	struct diag_dev_inst_t *dev = container_of(inode->i_cdev,
			struct diag_dev_inst_t, mcdev);

	filp->private_data = dev;
	pr_info("[SOF] device opened");
	return 0;
}

/**
 * diag_close() - Closes a device.
 * @inode: pointer to device's file inode
 * @filp: pointer to device's file representation; pointee is output parameter
 *
 * Does nothing yet actually needed for kernel's bookkeeping.
 *
 * Return: Always 0.
 */
static int diag_close(struct inode *inode, struct file *filp)
{
	pr_info("[SOF] device closed");
	return 0;
}

/**
 * get_drv_dev() - Gets the PCI descriptor for a device.
 * @device_id: device ID
 *
 * Return: PCI descriptor pointer if found, NULL if not found.
 */
static inline struct pci_dev *get_drv_dev(unsigned int device_id)
{
	const unsigned int PCI_VENDOR = 0x8086;

	return pci_get_device(PCI_VENDOR, device_id, NULL);
}

/**
 * pci_wconf32_chk() - Writes a PCI config 32-bit chunk and checks the result.
 * @dev: pointer to PCI device's descriptor
 * @where: position of a config chunk
 * @val: config chunk's value
 *
 * Return: PCI operation status. See :c:macro:`PCIBIOS_SUCCESSFUL`.
 */
static inline int __must_check pci_wconf32_chk(const struct pci_dev *dev,
	int where, uint32_t val)
{
	int ret;

	dev_info(&dev->dev, "writing PCI config (DWORD): config position = %d, value = 0x%x",
		where, val);

	ret = pci_write_config_dword(dev, where, val);
	if (ret)
		ret = pcibios_err_to_errno(ret);

	describe_retval(ret, PCIBIOS_SUCCESSFUL, "writing PCI config");
	return ret;
}

/**
 * pci_wconf16_chk() - Writes a PCI config 16-bit chunk and checks the result.
 * @dev: pointer to PCI device's descriptor
 * @where: position of a config chunk
 * @val: config chunk's value
 *
 * Return: PCI operation status. See :c:macro:`PCIBIOS_SUCCESSFUL`.
 */
static inline int __must_check pci_wconf16_chk(const struct pci_dev *dev,
	int where, uint16_t val)
{
	int ret;

	dev_info(&dev->dev, "writing PCI config (WORD): config position = %d, value = 0x%x",
		where, val);

	ret = pci_write_config_word(dev, where, val);
	if (ret)
		ret = pcibios_err_to_errno(ret);

	describe_retval(ret, PCIBIOS_SUCCESSFUL, "writing PCI config");
	return ret;
}

/**
 * pci_rconf_chk() - Reads a PCI config 8-bit chunk and checks the result.
 * @dev: pointer to PCI device's descriptor
 * @where: position of a config chunk
 * @val: pointer to config chunk's value; pointee is output parameter
 *
 * Return: PCI operation status. See :c:macro:`PCIBIOS_SUCCESSFUL`.
 */
static inline int __must_check pci_rconf_chk(const struct pci_dev *dev,
	int where, uint8_t *val)
{
	int ret;

	dev_info(&dev->dev, "getting PCI config for device: config position = %d",
		where);

	ret = pci_read_config_byte(dev, where, val);
	if (ret)
		ret = pcibios_err_to_errno(ret);
	else
		dev_info(&dev->dev, "got PCI config byte = 0x%x", *val);

	describe_retval(ret, PCIBIOS_SUCCESSFUL, "reading PCI config");
	return ret;
}

/**
 * handle_open_device() - Handles a device open IOCTL.
 * @addr:	pointer data supplied by the user interpeted as a device handle;
 *			see :c:type:`diag_dev_handle_t`
 *
 * Return: 0 on success, positive value on error.
 */
static long handle_open_device(void *addr)
{
	long ret = 0;
	struct diag_dev_handle_t *open_dev = (struct diag_dev_handle_t *)addr;

	pr_info("[SOF] got open device request; device handle = %p", open_dev);
	ret = copy_to_user_and_check(&open_dev->dsp_bar,
		&driver.devices[DIAG_DSP].bar,
		(uint32_t)sizeof(open_dev->dsp_bar), -EINVAL);
	if (ret) {
		pr_err("[SOF] unable to copy DSP device data to user");
		goto final;
	}

	ret = copy_to_user_and_check(&open_dev->hda_bar,
		&driver.devices[DIAG_HDA].bar,
		(uint32_t)sizeof(open_dev->hda_bar), -EINVAL);
	if (ret) {
		pr_err("[SOF] unable to copy HDA device data to user");
		goto final;
	}

final:
	describe_retval(ret, 0, "opening device");
	return ret;
}

/**
 * handle_alloc_memory() - Handles a memory allocation IOCTL.
 * @addr:	pointer to data supplied by the user interpeted as an HDA memory
 *			allocation descriptor; see :c:type:`diag_hda_bus_test_t`
 *
 * Return:	0 on success, positive value on user <-> kernel copy error,
 *			-ENOMEM on allocation or mapping error.
 */
static long handle_alloc_memory(void *addr)
{
	long ret = 0;
	void *ptr = NULL;
	const struct diag_mem_map_t *alloc_desc_end =
		&driver.alloc_desc[MAX_ALLOC_MAPS];
	struct diag_hda_bus_test_t mem_struct;
	struct diag_mem_map_t *desc = NULL;

	pr_info("[SOF] got memory allocation request");

	ret = copy_from_user_and_check(&mem_struct, addr,
		(uint32_t)sizeof(mem_struct), -EINVAL);
	if (ret) {
		pr_err("[SOF] unable to copy HDA bus descriptor from user");
		goto final;
	}

	ptr = kzalloc((size_t)mem_struct.size, GFP_HIGHUSER);
	if (!ptr) {
		ret = -ENOMEM;
		goto final;
	}

	mem_struct.dma_phys_addr = virt_to_phys(ptr);
	pr_info("[SOF] allocated memory at %p which corresponds to physical address = %p; size = %u",
		ptr, (void *)mem_struct.dma_phys_addr, mem_struct.size);

	for (desc = driver.alloc_desc; desc < alloc_desc_end; ++desc) {
		if (desc->physical != 0)
			continue;

		desc->kernel_virt_addr = ptr;
		desc->physical = mem_struct.dma_phys_addr;
		break;
	}

	if (desc == alloc_desc_end) {
		pr_err("[SOF] number of memory maps is at its limit");
		ret = -ENOMEM;
		goto dealloc;
	}

	ret = copy_to_user_and_check(addr, &mem_struct,
		(uint32_t)sizeof(mem_struct), -EINVAL);
	if (ret) {
		pr_err("[SOF] unable to copy bus descriptor to user");
		goto dealloc;
	}

	goto final;

dealloc:
	kfree(ptr);
	pr_info("[SOF] freed memory at %p", ptr);

final:
	describe_retval(ret, 0, "allocating memory");
	return ret;
}

/**
 * handle_free_memory() - Handles a memory free IOCTL.
 * @addr:	pointer to data supplied by the user interpeted as an HDA memory
 *			allocation descriptor; see :c:type:`diag_hda_bus_test_t`
 *
 * Return: 0 on success, -EINVAL on error.
 */
static long handle_free_memory(void *addr)
{
	long ret = 0;
	phys_addr_t address_to_free = 0;
	struct diag_hda_bus_test_t mem_struct;
	void *virtual_address_to_free = NULL;
	struct diag_mem_map_t *alloc_desc_end = NULL;
	struct diag_mem_map_t *desc = NULL;

	pr_info("[SOF] got memory free request");

	ret = copy_from_user_and_check(&mem_struct, addr,
			(uint32_t)sizeof(mem_struct), -EINVAL);
	if (ret) {
		pr_err("[SOF] unable to copy bus descriptor from user");
		goto final;
	}

	address_to_free = mem_struct.dma_phys_addr;
	alloc_desc_end = &driver.alloc_desc[MAX_ALLOC_MAPS];
	for (desc = driver.alloc_desc; desc < alloc_desc_end; ++desc) {
		if (desc->physical != address_to_free)
			continue;

		virtual_address_to_free = desc->kernel_virt_addr;
		desc->physical = 0;
		desc->kernel_virt_addr = NULL;
		break;
	}

	if (!virtual_address_to_free) {
		ret = -EINVAL;
		pr_err("[SOF] requested physical address = %p doesn't represent any allocation",
			(void *)address_to_free);
		goto final;
	}

	kfree(virtual_address_to_free);
	pr_info("[SOF] freed virtual memory at %p", virtual_address_to_free);

final:
	describe_retval(ret, PCIBIOS_SUCCESSFUL, "freeing memory");
	return ret;
}

#define DATA_BUF_SZ 0x100

/**
 * handle_hdabustest_read_pciconf() - Handles a PCI config read IOCTL.
 *
 * @addr:	pointer to data supplied by the user interpeted as a PCI config;
 *			see :c:type:`diag_pci_conf_t`
 *
 * Return: 0 on success, negative value on error.
 */
static long handle_hdabustest_read_pciconf(void *addr)
{
	long ret = 0;
	struct diag_pci_conf_t pci_struct_local;
	struct pci_dev *pci_dev = get_drv_dev(driver.dev_id);
	struct diag_pci_conf_t *pci_struct;
	uint8_t data[DATA_BUF_SZ];
	uint32_t ii;

	dev_info(&pci_dev->dev, "got HDA bus read request");
	if (!pci_dev) {
		dev_crit(&pci_dev->dev, "unable to get PCI device");
		ret = -ENODEV;
		goto final;
	}

	ret = copy_from_user_and_check(&pci_struct_local, addr,
			(uint32_t)sizeof(pci_struct_local), -EINVAL);
	if (ret) {
		dev_err(&pci_dev->dev, "unable to copy PCI config header from user");
		goto final;
	}

	dev_info(&pci_dev->dev, "offset = %d, length = %u",
			pci_struct_local.offset, pci_struct_local.length);

	for (ii = 0, ret = PCIBIOS_SUCCESSFUL;
			ii < pci_struct_local.length && ret == 0;
			++ii) {
		ret = pci_rconf_chk(pci_dev, pci_struct_local.offset + ii,
					&data[ii]);
		if (ret) {
			dev_crit(&pci_dev->dev, "reading PCI config data failed at chunk #%u",
				ii);
			goto put_dev;
		}

		dev_info(&pci_dev->dev, "read PCI config data chunk #%u, value = %u",
				ii, data[ii]);
	}

put_dev:
	pci_dev_put(pci_dev);

	pci_struct = (struct diag_pci_conf_t *)addr;
	ret = copy_to_user_and_check(pci_struct->buffer, data,
			pci_struct_local.length, -EINVAL);
	if (ret) {
		pr_crit("[SOF] unable to copy PCI config header to user");
		goto final;
	}

final:
	describe_retval(ret, PCIBIOS_SUCCESSFUL, "reading HDA bus");
	return ret;
}

/**
 * is_PCI_config_sane() - Checks if a PCI config's size is a multiple of DWORD.
 * @cfg: pointer to PCI config
 *
 *	This is only a shallow check, i.e. it proves that the config isn't
 *	corrupted in an obvious way.
 *
 * Return: 0 on success, -EINVAL on error.
 */
inline long is_PCI_config_sane(const struct diag_pci_conf_t *cfg)
{
	if (cfg->length % sizeof(uint32_t) != 0) {
		pr_err("[SOF] PCI config's size isn't multiple of DWORD");
		return -EINVAL;
	}

	return 0;
}

/**
 * handle_hdabustest_write_pciconf() - Handles a PCI config write IOCTL.
 * @addr:	pointer to data supplied by the user interpeted as a PCI config;
 *			see :c:type:`diag_pci_conf_t`
 *
 * Return: 0 on success, negative value on error.
 */
static long handle_hdabustest_write_pciconf(void *addr)
{
	long ret = 0;
	struct diag_pci_conf_t *pci_struct;
	struct diag_pci_conf_t pci_struct_local;
	struct pci_dev *pci_dev = get_drv_dev(driver.dev_id);
	uint32_t data[DATA_BUF_SZ / sizeof(uint32_t)];
	uint32_t ii;

	pr_info("[SOF] got HDA bus write request");
	if (!pci_dev) {
		pr_crit("[SOF] unable to get PCI device");
		ret = -ENODEV;
		goto final;
	}

	ret = copy_from_user_and_check(&pci_struct_local, addr,
			(uint32_t)sizeof(pci_struct_local), -EINVAL);
	if (ret) {
		dev_err(&pci_dev->dev, "unable to copy PCI config header from user");
		goto final;
	}

	ret = is_PCI_config_sane(&pci_struct_local);
	if (ret)
		goto final;

	pci_struct = (struct diag_pci_conf_t *)addr;
	ret = copy_from_user_and_check(data, pci_struct->buffer,
			pci_struct_local.length, -EINVAL);
	if (ret) {
		dev_err(&pci_dev->dev, "unable to copy PCI config header from user");
		goto final;
	}

	for (ii = 0; ii < pci_struct_local.length / 4; ++ii) {
		ret = pci_wconf32_chk(pci_dev, pci_struct_local.offset + ii,
					data[ii]);
		if (ret) {
			dev_crit(&pci_dev->dev, "writing PCI config data failed at chunk #%u",
				ii);
			goto put_dev;
		}

		dev_info(&pci_dev->dev, "wrote PCI config data chunk #%u, value = %u",
				ii, data[ii]);
	}

put_dev:
	pci_dev_put(pci_dev);

final:
	describe_retval(ret, PCIBIOS_SUCCESSFUL, "writing PCI config");
	return ret;
}

/**
 * ioctl_handler() - Handles an IOCTL.
 * @f: unused
 * @cmd: IOCTL number
 * @arg:	IOCTL argument - always a memory address or pointer; input and
 *			output parameter
 *
 * Return: 0 on success, negative value on error.
 */
static long ioctl_handler(struct file *f, unsigned int cmd, unsigned long arg)
{
	void *addr = (void *)arg;

	pr_info("[SOF] got IOCTL #0x%x", cmd);

	if (!addr) {
		pr_err("[SOF] requested memory address is NULL");
		return -EINVAL;
	}

	switch ((int)cmd) {
	case CMD_OPEN_DEVICE:
		return handle_open_device(addr);

	case CMD_ALLOC_MEMORY:
		return handle_alloc_memory(addr);

	case CMD_FREE_MEMORY:
		return handle_free_memory(addr);

	case HDABUSTEST_READ_PCICONF:
		return handle_hdabustest_read_pciconf(addr);

	case HDABUSTEST_WRITE_PCICONF:
		return handle_hdabustest_write_pciconf(addr);

	default:
		pr_err("[SOF] bad request number");
		return -EBADRQC;
	}
}

/**
 * diag_llseek() - Handles a file seek request.
 * @filp: pointer to device's file representation; input and output parameter
 * @offset: seek operation's offset
 * @whence: seek operation's waypoint; see :c:macro:`SEEK_SET`
 *
 * Return: new position in file on success, -EINVAL on error.
 */
static loff_t diag_llseek(struct file *filp, loff_t offset, int whence)
{
	const loff_t maxpos =
		(const loff_t)((struct diag_dev_inst_t *)
		filp->private_data)->bar.size;
	loff_t newpos;

	pr_info("[SOF] got file seek request");

	switch (whence) {
	case SEEK_SET:
		newpos = offset;
		break;

	case SEEK_CUR:
		newpos = filp->f_pos + offset;
		break;

	case SEEK_END:
		newpos = maxpos + offset;
		break;

	default:
		return -EINVAL;
	}

	if (newpos < 0 || newpos > maxpos) {
		pr_err("[SOF] bad file position = %lld", newpos);
		pr_err("[SOF] setting file position failed");
		return -EINVAL;
	}

	filp->f_pos = newpos;
	pr_info("[SOF] file position set to %lld", newpos);
	pr_info("[SOF] setting file position succeeded");
	return newpos;
}

/**
 * diag_read() - Handles a file read request.
 * @filp: pointer to device's file representation
 * @buffer: buffer to put the read data to
 * @length: length of data to read
 * @offset: pointer to position inside the file; pointee is output parameter
 *
 * Return:	0 on success, positive value on user <-> kernel copy error,
 *			negative value on error.
 */
static ssize_t diag_read(struct file *filp, char *buffer, size_t length,
	loff_t *offset)
{
	struct diag_hda_bar_t bar =
		((struct diag_dev_inst_t *)filp->private_data)->bar;
	resource_size_t map_offset =
		(resource_size_t)(bar.base_physical + *offset);
	ssize_t data_left_to_read = (ssize_t)bar.size - *offset;
	ssize_t size_to_read = min_t(ssize_t, data_left_to_read, length);
	void *io_mem = NULL;
	void *temp_buffer = vmalloc(size_to_read);

	pr_info("[SOF] got file read request");

	if (!temp_buffer) {
		pr_err("[SOF] unable to allocate virtual memory of size = %zd",
			size_to_read);
		size_to_read = -ENOMEM;
		goto final;
	}

	io_mem = ioremap(map_offset, size_to_read);
	if (!io_mem) {
		pr_crit("[SOF] unable to map PCI bus memory; offset = %lu, size = %zd",
			(unsigned long)map_offset, size_to_read);
		size_to_read = -EINVAL;
		goto buffer_free;
	}

	pr_info("[SOF] mapped PCI bus memory; offset = %lu, size = %zd",
		(unsigned long)map_offset, size_to_read);

	memcpy_fromio(temp_buffer, io_mem, size_to_read);
	size_to_read = copy_to_user_and_check(buffer, temp_buffer,
			(uint32_t)size_to_read, -EFAULT);
	if (size_to_read) {
		pr_crit("[SOF] unable to copy data to user");
		goto unmap_mem;
	}

	*offset += size_to_read;

unmap_mem:
	iounmap(io_mem);
	pr_info("[SOF] unmapped PCI bus memory from address = %p", io_mem);

buffer_free:
	vfree(temp_buffer);
	pr_info("[SOF] freed virtual memory from address = %p", temp_buffer);

final:
	describe_retval(size_to_read, 0, "reading file");
	return size_to_read;
}

/**
 * diag_write() - Handles a file write request.
 * @filp: pointer to device's file representation
 * @buffer: pointer to buffer to take the data from
 * @length: length of the data to take
 * @offset: position inside the file; pointee is output parameter
 *
 * Return:	0 on success, positive value on user <-> kernel copy error,
 *			negative value on error.
 */
static ssize_t diag_write(struct file *filp, const char *buffer, size_t length,
	loff_t *offset)
{
	struct diag_hda_bar_t bar =
		((struct diag_dev_inst_t *)filp->private_data)->bar;
	resource_size_t map_offset =
		(resource_size_t)(bar.base_physical + *offset);
	const ssize_t space_left = (ssize_t)bar.size - *offset;
	ssize_t size_to_write = min_t(ssize_t, space_left, length);
	void *io_mem = NULL;
	void *temp_buffer = NULL;

	pr_info("[SOF] got file write request");

	io_mem = ioremap(map_offset, (unsigned long)size_to_write);
	if (!io_mem) {
		pr_crit("[SOF] unable to map PCI bus memory; offset = %lu, size = %zd",
			(unsigned long)map_offset, size_to_write);
		size_to_write = -EINVAL;
		goto final;
	}

	temp_buffer = vmalloc((unsigned long)size_to_write);
	if (!temp_buffer) {
		size_to_write = -ENOMEM;
		goto unmap_mem;
	}

	size_to_write = copy_from_user_and_check(temp_buffer, buffer,
			(uint32_t)size_to_write, -EIO);
	if (size_to_write) {
		pr_crit("[SOF] unable to copy data from user");
		goto buffer_free;
	}

	memcpy_toio(io_mem, temp_buffer, (size_t)size_to_write);
	*offset += size_to_write;

buffer_free:
	vfree(temp_buffer);
	pr_info("[SOF] freed virtual memory from address = %p", temp_buffer);

unmap_mem:
	iounmap(io_mem);
	pr_info("[SOF] unmapped PCI bus memory from address = %p", io_mem);

final:
	describe_retval(size_to_write, 0, "writing file");
	return size_to_write;
}

/**
 * fops - File operations fulfilled by the driver.
 */
static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.open = diag_open,
	.unlocked_ioctl = ioctl_handler,
	.mmap = simple_remap_mmap,
	.release = diag_close,
	.read = diag_read,
	.write = diag_write,
	.llseek = diag_llseek
};

/**
 * get_device_id() - Gets the current SOF PCI device's ID.
 * @id: pointer to device's ID; pointee is output parameter
 *
 * Return: device's ID on success, -ENODEV on error.
 */
static unsigned int get_device_id(unsigned int *id)
{
	const unsigned int u_err_code = (const unsigned int)-ENODEV;
	size_t ii;

	*id = u_err_code;
	for (ii = 0; ii < ARRAY_SIZE(device_ids); ++ii) {
		struct pci_dev *pci_dev = get_drv_dev(device_ids[ii]);

		if (!pci_dev)
			continue;

		*id = device_ids[ii];
		pci_dev_put(pci_dev);
		break;
	}

	if (*id == u_err_code)
		pr_crit("[SOF] no SOF audio PCI device recognized in system");

	return *id;
}

/**
 * fill_bar() - Fills a piece of the driver's global information about
 *				the Base Address Register.
 * @kind: kind of SOF device; see :c:type:`diag_dev_kind_t`
 * @base_physical: device's base physical address
 * @size: size of the device's memory
 */
static inline void fill_bar(enum diag_dev_kind_t kind,
	phys_addr_t base_physical, size_t size)
{
	driver.devices[kind].bar.base_physical = base_physical;
	driver.devices[kind].bar.size = size;
}

/**
 * get_pci_addr() - Fills a piece of the driver's global information about the
 *					current SOF device's PCI address.
 *
 * Return: on success, -ENODEV on error.
 */
static inline int get_pci_addr(void)
{
	/*	each of these 64-bit Base Addresses consists of two 32-bit
	 *	halves (see the device's programming reference)
	 */
	const off_t BA_HDA = 0, BA_DSP = 4;
	struct pci_dev *dev = get_drv_dev(driver.dev_id);

	if (!dev) {
		pr_crit("[SOF] unable to get PCI device with ID = %u",
			driver.dev_id);
		return -ENODEV;
	}

	fill_bar(DIAG_HDA, pci_resource_start(dev, BA_HDA),
		pci_resource_len(dev, BA_HDA));
	fill_bar(DIAG_DSP, pci_resource_start(dev, BA_DSP),
		pci_resource_len(dev, BA_DSP));

	pci_dev_put(dev);
	return 0;
}

/**
 * setup_cdev() - Sets the character device up.
 * @dev: pointer to character device; pointee is output parameter
 * @major: device's major number
 * @minor: device's minor number
 *
 * Return: 0 on success, negative value on error.
 */
static int setup_cdev(struct cdev *dev, int major, int minor)
{
	cdev_init(dev, &fops);
	dev->owner = THIS_MODULE;
	dev->ops = &fops;
	return cdev_add(dev, MKDEV(major, minor), 1);
}

/**
 * setup_cdev_drv() - Sets the character device's driver up.
 * @dev_kind: kind of the diagnostic device; see :c:type:`diag_dev_kind_t`
 *
 * Return: 0 on success, negative value on error.
 */
static inline int setup_cdev_drv(enum diag_dev_kind_t dev_kind)
{
	if (dev_kind < DIAG_START || dev_kind >= DIAG_COUNT) {
		pr_err("[SOF] invalid device kind = %d", dev_kind);
		return -EINVAL;
	}

	return setup_cdev(&driver.devices[dev_kind].mcdev,
		MAJOR(driver.dev_num), MINOR(driver.dev_num) + dev_kind);
}

/**
 * release_cdev_drv() - Releases the character device's driver.
 * @dev_kind: kind of the diagnostic device; see :c:type:`diag_dev_kind_t`.
 */
static inline void release_cdev_drv(enum diag_dev_kind_t dev_kind)
{
	pr_notice("[SOF] releasing character device %s",
		(dev_kind == DIAG_HDA) ? "HDA" : "DSP");
	cdev_del(&driver.devices[dev_kind].mcdev);
}

/**
 * create_dev_drv() - Creates the diagnostic device and registers it with sysfs.
 * @dev_kind: kind of the diagnostic device; see :c:type:`diag_dev_kind_t`
 * @name: diagnostic device's name
 *
 * Return:	device pointer on success, error pointer on error;
 *			see :c:function:`ERR_PTR`.
 */
static inline struct device *create_dev_drv(enum diag_dev_kind_t dev_kind,
	const char *name)
{
	return device_create(driver.cls, NULL,
		driver.devices[dev_kind].mcdev.dev, NULL, name);
}

/**
 * destroy_dev_drv() -	Destroys the diagnostic device and unregisters it from
 *						sysfs.
 * @dev_kind: kind of the diagnostic device; @see diag_dev_kind_t.
 */
static inline void destroy_dev_drv(enum diag_dev_kind_t dev_kind)
{
	pr_notice("[SOF] destroying %s device",
		(dev_kind == DIAG_HDA) ? "HDA" : "DSP");
	device_destroy(driver.cls, driver.devices[dev_kind].mcdev.dev);
}

/**
 * err_ptr_to_code() - Casts the error pointer to error code.
 * @ptr: error pointer; see :c:function:`ERR_PTR`
 *
 * Return: error code.
 */
int err_ptr_to_code(const void *ptr)
{
	return (int)(long)ptr;
}

/**
 * diagdev_init() - Driver's entry point.
 *
 * Return: 0 on success, non-zero on error.
 */
int diagdev_init(void)
{
	int ret = 0;
	struct pci_dev *pci_dev;

	pr_info("[SOF] driver entry");

	ret = alloc_chrdev_region(&driver.dev_num, 0, 1, DRIVER_NAME);
	if (ret != 0) {
		pr_crit("[SOF] unable to allocate character device region");
		goto final;
	}

	ret = get_device_id(&driver.dev_id);
	if (ret < 0) {
		pr_crit("[SOF] unable to get device ID");
		goto release_chrdev_region;
	}

	pci_dev = get_drv_dev(driver.dev_id);
	if (!pci_dev) {
		pr_crit("[SOF] unable to get PCI device");
		ret = -ENODEV;
		goto release_chrdev_region;
	}

	ret = get_pci_addr();
	if (ret < 0) {
		dev_crit(&pci_dev->dev, "unable to get PCI address");
		goto release_chrdev_region;
	}

	driver.cls = class_create(THIS_MODULE, "diag");
	if (IS_ERR(driver.cls)) {
		dev_crit(&pci_dev->dev, "unable to create driver class");
		ret = err_ptr_to_code(driver.cls);
		goto release_chrdev_region;
	}

	ret = setup_cdev_drv(DIAG_HDA);
	if (ret != 0) {
		dev_crit(&pci_dev->dev, "unable to add HDA device to system");
		goto destroy_class;
	}

	ret = setup_cdev_drv(DIAG_DSP);
	if (ret != 0) {
		dev_crit(&pci_dev->dev, "unable to add DSP device to system");
		goto release_cdev_hda;
	}

	if (IS_ERR(create_dev_drv(DIAG_HDA, "hda"))) {
		ret = err_ptr_to_code(driver.cls);
		dev_crit(&pci_dev->dev, "unable to create HDA device and/or register it in system");
		goto release_cdev_dsp;
	}

	if (IS_ERR(create_dev_drv(DIAG_DSP, "dsp"))) {
		ret = err_ptr_to_code(driver.cls);
		dev_crit(&pci_dev->dev, "unable to create DSP device and/or register it in system");
		goto destroy_dev_hda;
	}

	ret = pci_wconf16_chk(pci_dev, PCI_COMMAND,
		PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER);
	pci_dev_put(pci_dev);
	if (ret == 0)
		goto final;

/* destroy_dev_dsp: */
	destroy_dev_drv(DIAG_DSP);
	pr_notice("[SOF] DSP device destroyed");

destroy_dev_hda:
	destroy_dev_drv(DIAG_HDA);
	pr_notice("[SOF] HDA device destroyed");

release_cdev_dsp:
	release_cdev_drv(DIAG_DSP);
	pr_notice("[SOF] DSP character device released");

release_cdev_hda:
	release_cdev_drv(DIAG_HDA);
	pr_notice("[SOF] HDA character device released");

destroy_class:
	pr_notice("[SOF] destroying driver class = %p", driver.cls);
	class_destroy(driver.cls);
	pr_info("[SOF] driver class destroyed");

release_chrdev_region:
	pr_notice("[SOF] unregistering character device region; device number = 0x%x",
		driver.dev_num);
	unregister_chrdev_region(driver.dev_num, 1);
	pr_info("[SOF] character device region unregistered");

final:
	pr_info("[SOF] driver entry returning with code: %d", ret);
	return ret;
}

/**
 * diagdev_exit() - Driver's exit point.
 */
void diagdev_exit(void)
{
	pr_info("[SOF] begin of driver exit");

	destroy_dev_drv(DIAG_DSP);
	release_cdev_drv(DIAG_DSP);
	destroy_dev_drv(DIAG_HDA);
	release_cdev_drv(DIAG_HDA);
	class_destroy(driver.cls);
	unregister_chrdev_region(driver.dev_num, 1);

	pr_info("[SOF] end of driver exit");
}

MODULE_AUTHOR("Intel");
MODULE_DESCRIPTION("Diagnostic HDA Driver");
MODULE_LICENSE("GPL");

module_init(diagdev_init);
module_exit(diagdev_exit);
