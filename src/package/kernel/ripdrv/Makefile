#
# Copyright (c) 2012 Technicolor
# All Rights Reserved
#
# This program contains proprietary information which is a trade
# secret of TECHNICOLOR and/or its affiliates and also is protected as
# an unpublished work under applicable Copyright laws. Recipient is
# to retain this program in confidence and is not permitted to use or
# make copies thereof other than as permitted in a written agreement
# with TECHNICOLOR, UNLESS OTHERWISE EXPRESSLY ALLOWED BY APPLICABLE LAWS.
#
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=ripdrv
PKG_VERSION:=2014.01
PKG_SOURCE_URL:=git@gitolite-openwrt:/openwrt/pkg/rip.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=3dd44fa87b9de8d353b51e221a9fb031a17e62fa
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz
PKG_BUILD_DEPENDS:=ripdrv/host

include $(INCLUDE_DIR)/package.mk
include $(INCLUDE_DIR)/host-build.mk

define KernelPackage/ripdrv
  SUBMENU:=Technicolor specific kernel modules
  TITLE:=RIP driver (Remote Inventory Prom)
  DEPENDS:=@(TARGET_brcm63xx_tch||TARGET_brcm63xx_arm_tch||TARGET_brcm68xx_tch||TARGET_comcerto2000||TARGET_ar71xx_GANTV||TARGET_ar71xx_GANTW||TARGET_puma_arm)
  FILES:=$(PKG_BUILD_DIR)/ripdrv.ko
  KCONFIG:=
  MAINTAINER:=Technicolor <linuxgw@technicolor.com>
  AUTOLOAD:=$(call AutoLoad,49,ripdrv)
endef

define KernelPackage/ripdrv/description
 Kernel module that provides access to the eRIPv2 on Technicolor gateways.
endef

define KernelPackage/ripdrv-crypto
  SUBMENU:=Technicolor specific kernel modules
  TITLE:=RIP driver with crypto support
  DEPENDS:=@(TARGET_brcm63xx_tch||TARGET_brcm68xx_tch||TARGET_comcerto2000||TARGET_ar71xx_GANTV||TARGET_ar71xx_GANTW||TARGET_puma_arm) +kmod-tommath +kmod-tomcrypt
  FILES:=$(PKG_BUILD_DIR)/ripdrv.ko
  KCONFIG:=
  MAINTAINER:=Technicolor <linuxgw@technicolor.com>
  AUTOLOAD:=$(call AutoLoad,49,ripdrv)
endef

define KernelPackage/ripdrv-crypto/description
 Kernel module that provides access to the eRIPv2 on Technicolor gateways with encrypted parameters.
endef

define KernelPackage/ripdrv-crypto/config
	config RIPDRV_EXPOSE_PRIVATES
		bool "Expose private data (e.g. client cert) in procfs"
		default n
		depends on PACKAGE_kmod-ripdrv-crypto

		help
			Expose private data (e.g. client cert) in procfs. Normally this should not be done
			as this is a security risk! Private data should be protected with SPF.

	config RIPDRV_ANVIL
		bool
endef

ifneq ($(CONFIG_TARGET_brcm68xx_tch),)
  PKG_EXTRA_CFLAGS += \
	-DSET_GPON_SERIAL_NUM
endif

ifneq ($(CONFIG_TARGET_comcerto2000)$(CONFIG_TARGET_brcm63xx_tch)$(CONFIG_TARGET_brcm63xx_arm_tch)$(CONFIG_TARGET_brcm68xx_tch),)
  PKG_EXTRA_CFLAGS += \
	-DSET_MAC_ADDRESS
endif

EXTRA_KCONFIG:= \
       CONFIG_RIPDRV=m

ifneq ($(CONFIG_PACKAGE_kmod-ripdrv-crypto),)
EXTRA_KCONFIG += \
	CONFIG_RIPDRV_CRYPTO_SUPPORT=y
PKG_EXTRA_CFLAGS += \
	-DCONFIG_RIPDRV_CRYPTO_SUPPORT \
	-DDEBUG
endif

ifneq ($(CONFIG_RIPDRV_EXPOSE_PRIVATES),)
EXTRA_KCONFIG += \
	CONFIG_RIPDRV_EXPOSE_PRIVATES=y
PKG_EXTRA_CFLAGS += \
	-DCONFIG_RIPDRV_EXPOSE_PRIVATES
endif

ifneq ($(CONFIG_RIPDRV_ANVIL),)
EXTRA_KCONFIG += \
	CONFIG_RIPDRV_ANVIL=y
PKG_EXTRA_CFLAGS += \
	-DCONFIG_RIPDRV_ANVIL
endif

MAKE_OPTS:= \
	ARCH="$(LINUX_KARCH)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	SUBDIRS="$(PKG_BUILD_DIR)" \
	EXTRA_CFLAGS="$(PKG_EXTRA_CFLAGS)" \
	$(EXTRA_KCONFIG)

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(MAKE_OPTS) \
		modules
endef

define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR)/usr/include
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/include/*.h $(STAGING_DIR)/usr/include
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/target/linux/include/*.h $(STAGING_DIR)/usr/include
endef

define KernelPackage/ripdrv/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/*.sh $(1)/usr/sbin/
endef

define KernelPackage/ripdrv-crypto/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) ./files/*.sh $(1)/usr/sbin/
endef

$(eval $(call KernelPackage,ripdrv))
$(eval $(call KernelPackage,ripdrv-crypto))

define Host/Configure
	(cd $(HOST_BUILD_DIR); \
		CFLAGS="$(HOST_CFLAGS) $(EXTRA_CFLAGS)" \
		CXXFLAGS="$(HOST_CFLAGS) $(EXTRA_CFLAGS)" \
		LDFLAGS="$(HOST_LDFLAGS) $(EXTRA_LDFLAGS)" \
		cmake \
			-DCMAKE_INSTALL_PREFIX=$(STAGING_DIR_HOST) \
	)
endef

$(eval $(call HostBuild))
