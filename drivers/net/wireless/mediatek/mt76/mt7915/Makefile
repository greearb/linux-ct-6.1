# SPDX-License-Identifier: ISC
EXTRA_CFLAGS += -DCONFIG_MTK_VENDOR
obj-$(CONFIG_MT7915E) += mt7915e.o

mt7915e-y := pci.o init.o dma.o eeprom.o main.o mcu.o mac.o \
	     debugfs.o mmio.o mtk_debugfs.o mtk_mcu.o vendor.o

mt7915e-$(CONFIG_NL80211_TESTMODE) += testmode.o
mt7915e-$(CONFIG_MT7986_WMAC) += soc.o