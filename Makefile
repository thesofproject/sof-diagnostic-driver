# SPDX-License-Identifier: (GPL-2.0 OR BSD-3-Clause)
#
# This file is provided under a dual BSD/GPLv2 license.  When using or
# redistributing this file, you may do so under either license.
#
# Copyright(c) 2019 Intel Corporation. All rights reserved.
#
# Author: Marcin Zielinski <marcinx.zielinski@linux.intel.com>
#

KDIR ?= /lib/modules/$(shell uname -r)/build
TARGET = diag_driver
driver_module := $(TARGET).ko

obj-m := $(TARGET).o
$(TARGET)-objs := driver.o my_mmap.o

default: driver

driver:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(BUILD_DIR) clean

uninstall:
	-sudo rm $(KDIR)/$(driver_module)
	-sudo rmmod $(TARGET)

install: driver
	sudo cp $(driver_module) $(KDIR)
	sudo insmod $(KDIR)/$(driver_module)
