# SPDX-License-Identifier: GPL-2.0
obj-$(CONFIG_NET_DSA_MV88E6XXX) += mv88e6xxx.o
mv88e6xxx-objs := chip.o
mv88e6xxx-objs += devlink.o
mv88e6xxx-objs += global1.o
mv88e6xxx-objs += global1_atu.o
mv88e6xxx-objs += global1_vtu.o
mv88e6xxx-$(CONFIG_NET_DSA_MV88E6XXX_GLOBAL2) += global2.o
mv88e6xxx-$(CONFIG_NET_DSA_MV88E6XXX_GLOBAL2) += global2_avb.o
mv88e6xxx-$(CONFIG_NET_DSA_MV88E6XXX_GLOBAL2) += global2_scratch.o
mv88e6xxx-$(CONFIG_NET_DSA_MV88E6XXX_PTP) += hwtstamp.o
mv88e6xxx-objs += phy.o
mv88e6xxx-objs += port.o
mv88e6xxx-objs += port_hidden.o
mv88e6xxx-$(CONFIG_NET_DSA_MV88E6XXX_PTP) += ptp.o
mv88e6xxx-objs += serdes.o
mv88e6xxx-objs += smi.o
mv88e6xxx-objs += trace.o

# for tracing framework to find trace.h
CFLAGS_trace.o := -I$(src)
