#
#
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=libtommath
PKG_VERSION:=0.42.0
PKG_SOURCE_URL:=http://libtom.org/files
PKG_SOURCE:=ltm-$(PKG_VERSION).tar.bz2
PKG_MD5SUM:=7380da904b020301be7045cb3a89039b

include $(INCLUDE_DIR)/package.mk


define KernelPackage/tommath
  SUBMENU:=Cryptographic API modules
  TITLE:=Tommath
  DEPENDS:=
  FILES:=$(PKG_BUILD_DIR)/tommath.ko
  KCONFIG:=
  AUTOLOAD:=$(call AutoLoad,47,tommath)
  MAINTAINER:=Technicolor <linuxgw@technicolor.com>
endef

define KernelPackage/tommath/description
 Kernel module to provide tommath math functions
endef

EXTRA_KCONFIG:= \
	CONFIG_CRYPTO_TOMMATH=m

MAKE_OPTS:= \
	ARCH="$(LINUX_KARCH)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	SUBDIRS="$(PKG_BUILD_DIR)" \
	$(EXTRA_KCONFIG)

define Build/Compile
	$(MAKE) -C "$(LINUX_DIR)" \
		$(MAKE_OPTS) \
		modules
endef

define Build/InstallDev
	$(INSTALL_DIR) $(STAGING_DIR)/usr/include
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/*.h $(STAGING_DIR)/usr/include
endef

$(eval $(call KernelPackage,tommath))
