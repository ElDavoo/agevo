obj-${CONFIG_RIPDRV} += ripdrv.o

ripdrv-y := main.o rip2lib.o target/linux/platform.o flashrip_drv.o rip_proc.o
ccflags-y += -I$(src)/include -I$(src)/target/linux/include/

ifneq ($(CONFIG_RIP_ON_UBI),)
ripdrv-y += target/linux/ubi.o
else
ripdrv-y += target/linux/mtd.o
endif

ifneq ($(CONFIG_RIPDRV_CRYPTO_SUPPORT),)
ccflags-y += -DCONFIG_RIPDRV_CRYPTO_SUPPORT
ripdrv-y += crypto.o target/linux/crypto_api.o target/linux/crypto_lx.o
endif

ifneq ($(CONFIG_RIPDRV_EXPOSE_PRIVATES),)
ccflags-y += -DCONFIG_RIPDRV_EXPOSE_PRIVATES
endif

ifneq ($(CONFIG_RIPDRV_ANVIL),)
ccflags-y += -DCONFIG_RIPDRV_ANVIL
endif

ifneq ($(CONFIG_ARM),)
ccflags-y += -DCONFIG_ARM
endif

ccflags-y += -Wall -Werror

clean:
	rm -f core *.o *.a *.s *~

