# Makefile for OpenWrt
#
# Copyright (C) 2007 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

TOPDIR:=${CURDIR}
LC_ALL:=C
LANG:=C
export TOPDIR LC_ALL LANG

empty:=
space:= $(empty) $(empty)
$(if $(findstring $(space),$(TOPDIR)),$(error ERROR: The path to the OpenWrt directory must not include any spaces))

BCM_KF:=y
BRCMDRIVERS_DIR:=$(TOPDIR)/extern/broadcom-bsp/bcmdrivers
#BCM_USERSPACE_DIR:=$(TOPDIR)/extern/bcm_userspace
SHARED_DIR:=$(TOPDIR)/extern/broadcom-bsp/shared
INSTALL_MOD_DIR:=extra
BRCM_BOARD:=bcm963xx
BRCM_CHIP:=63138
PROFILE:=963138BGWV
RDPA_PLATFORM=dsl
VOXXXLOAD=1

#INC_BROADCOM_APPS_SHARED:=$(BCM_USERSPACE_DIR)/broadcom_apps/shared

INC_BRCMDRIVER_PUB_PATH:=$(BRCMDRIVERS_DIR)/opensource/include
INC_BRCMDRIVER_PRIV_PATH:=$(BRCMDRIVERS_DIR)/broadcom/include
INC_ADSLDRV_PATH:=$(BRCMDRIVERS_DIR)/broadcom/char/adsl/impl1
INC_ATMAPI_DRV_PATH:=$(BRCMDRIVERS_DIR)/broadcom/char/atmapi/impl1
INC_MOCACFGDRV_PATH:=$(BRCMDRIVERS_DIR)/opensource/char/moca/impl2
INC_BRCMSHARED_PUB_PATH:=$(SHARED_DIR)/opensource/include
INC_BRCMSHARED_PRIV_PATH:=$(SHARED_DIR)/broadcom/include
INC_BRCMBOARDPARMS_PATH:=$(SHARED_DIR)/opensource/boardparms
INC_FLASH_PATH:=$(SHARED_DIR)/opensource/flash
INC_SPI_PATH:=$(SHARED_DIR)/opensource/spi
INC_SPUDRV_PATH:=$(BRCMDRIVERS_DIR)/broadcom/char/spudd/impl1
INC_PWRMNGTDRV_PATH:=$(BRCMDRIVERS_DIR)/broadcom/char/pwrmngt/impl1
INC_ENETDRV_PATH:=$(BRCMDRIVERS_DIR)/opensource/net/enet/impl5
INC_EPONDRV_PATH:=$(BRCMDRIVERS_DIR)/broadcom/char/epon/impl1
INC_RDPA_PATH:=$(BRCMDRIVERS_DIR)/opensource/char/rdpa_gpl/impl1/include
INC_RDPA_MW_PATH:=$(BRCMDRIVERS_DIR)/opensource/char/rdpa_mw/impl1
INC_RDPA_DRV_PATH:=$(BRCMDRIVERS_DIR)/opensource/char/rdpa_drv/impl1
INC_RDPA_PATH_PLATFORM:=$(INC_RDPA_PATH)/$(RDPA_PLATFORM)
INC_BDMF_PATH:=$(BRCMDRIVERS_DIR)/opensource/char/bdmf/impl1
INC_UTILS_PATH:=$(SHARED_DIR)/opensource/utils
RDP_PATH:=$(SHARED_DIR)/broadcom/rdp

ADD_LINUX_INCLUDE:=-I$(BRCMDRIVERS_DIR)/broadcom/net/wl/impl22/main/src/include

export BCM_KF BRCMDRIVERS_DIR SHARED_DIR INSTALL_MOD_DIR BRCM_BOARD BRCM_CHIP PROFILE RDPA_PLATFORM VOXXXLOAD ADD_LINUX_INCLUDE
export INC_BROADCOM_APPS_SHARED INC_BRCMDRIVER_PUB_PATH INC_BRCMDRIVER_PRIV_PATH INC_ADSLDRV_PATH INC_ATMAPI_DRV_PATH INC_MOCACFGDRV_PATH INC_BRCMSHARED_PUB_PATH INC_BRCMSHARED_PRIV_PATH INC_BRCMBOARDPARMS_PATH INC_FLASH_PATH INC_UTILS_PATH INC_SPI_PATH INC_SPUDRV_PATH INC_PWRMNGTDRV_PATH INC_ENETDRV_PATH INC_EPONDRV_PATH INC_RDPA_PATH INC_RDPA_MW_PATH INC_RDPA_DRV_PATH INC_RDPA_PATH_PLATFORM INC_BDMF_PATH RDP_PATH


world:

include $(TOPDIR)/include/host.mk

ifneq ($(OPENWRT_BUILD),1)
  _SINGLE=export MAKEFLAGS=$(space);

  override OPENWRT_BUILD=1
  export OPENWRT_BUILD
  GREP_OPTIONS=
  export GREP_OPTIONS
  include $(TOPDIR)/include/debug.mk
  include $(TOPDIR)/include/depends.mk
  include $(TOPDIR)/include/toplevel.mk
else
  include rules.mk
  include $(INCLUDE_DIR)/depends.mk
  include $(INCLUDE_DIR)/subdir.mk
  include target/Makefile
  include package/Makefile
  include tools/Makefile
  include toolchain/Makefile

$(toolchain/stamp-install): $(tools/stamp-install)
$(target/stamp-compile): $(toolchain/stamp-install) $(tools/stamp-install) $(BUILD_DIR)/.prepared
$(package/stamp-compile): $(target/stamp-compile) $(package/stamp-cleanup)
$(package/stamp-install): $(package/stamp-compile)
$(target/stamp-install): $(package/stamp-compile) $(package/stamp-install)

printdb:
	@true

prepare: $(target/stamp-compile)

clean: FORCE
	rm -rf $(BUILD_DIR) $(STAGING_DIR) $(BIN_DIR) $(BUILD_LOG_DIR)

dirclean: clean
	rm -rf $(STAGING_DIR_HOST) $(TOOLCHAIN_DIR) $(BUILD_DIR_HOST) $(BUILD_DIR_TOOLCHAIN)
	rm -rf $(TMP_DIR)

ifndef DUMP_TARGET_DB
$(BUILD_DIR)/.prepared: Makefile
	@mkdir -p $$(dirname $@)
	@touch $@

tmp/.prereq_packages: .config
	unset ERROR; \
	for package in $(sort $(prereq-y) $(prereq-m)); do \
		$(_SINGLE)$(NO_TRACE_MAKE) -s -r -C package/$$package prereq || ERROR=1; \
	done; \
	if [ -n "$$ERROR" ]; then \
		echo "Package prerequisite check failed."; \
		false; \
	fi
	touch $@
endif

# check prerequisites before starting to build
prereq: $(target/stamp-prereq) tmp/.prereq_packages
	@if [ ! -f "$(INCLUDE_DIR)/site/$(ARCH)" ]; then \
		echo 'ERROR: Missing site config for architecture "$(ARCH)" !'; \
		echo '       The missing file will cause configure scripts to fail during compilation.'; \
		echo '       Please provide a "$(INCLUDE_DIR)/site/$(ARCH)" file and restart the build.'; \
		exit 1; \
	fi

prepare: .config $(tools/stamp-install) $(toolchain/stamp-install)
world: prepare $(target/stamp-compile) $(package/stamp-compile) $(package/stamp-install) $(target/stamp-install) FORCE
	$(_SINGLE)$(SUBMAKE) -r package/index

.PHONY: clean dirclean prereq prepare world package/symlinks package/symlinks-install package/symlinks-clean

endif
