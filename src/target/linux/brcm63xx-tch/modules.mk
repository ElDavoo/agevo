#
# Copyright (C) 2010 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

define KernelPackage/bcm63xx-tch-chipinfo
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom Chip Info driver
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_CHIPINFO
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/char/chipinfo/bcm9$(BRCM_CHIP)/chipinfo.ko
  AUTOLOAD:=$(call AutoLoad,50,chipinfo)
endef

$(eval $(call KernelPackage,bcm63xx-tch-chipinfo))

define KernelPackage/bcm63xx-tch-otp
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom otp
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_OTP CONFIG_BCM_OTP_IMPL=1
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/char/otp/bcm9$(BRCM_CHIP)/otp.ko
  AUTOLOAD:=$(call AutoLoad,50,otp)
endef

$(eval $(call KernelPackage,bcm63xx-tch-otp))

define KernelPackage/bcm63xx-tch-i2c-bus
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom HW I2C bus support
  DEPENDS:=@TARGET_brcm63xx_tch +kmod-i2c-core
  KCONFIG:=CONFIG_BCM_I2C_BUS CONFIG_BCM_I2C_BUS_IMPL=1
  FILES:=$(BRCMDRIVERS_DIR)/opensource/char/i2c/busses/bcm9$(BRCM_CHIP)/i2c_bcm6xxx.ko
  AUTOLOAD:=$(call AutoLoad,52,i2c_bcm6xxx)
endef

$(eval $(call KernelPackage,bcm63xx-tch-i2c-bus))

define KernelPackage/bcm63xx-tch-ingqos
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom Ingress QoS driver
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_INGQOS
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/char/ingqos/bcm9$(BRCM_CHIP)/bcm_ingqos.ko
  AUTOLOAD:=$(call AutoLoad,51,bcm_ingqos)
endef

$(eval $(call KernelPackage,bcm63xx-tch-ingqos))


define KernelPackage/bcm63xx-tch-bpm
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom BPM driver
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_BPM CONFIG_BCM_BPM_BUF_MEM_PRCNT=15
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/char/bpm/bcm9$(BRCM_CHIP)/bcm_bpm.ko
  AUTOLOAD:=$(call AutoLoad,52,bcm_bpm)
endef

$(eval $(call KernelPackage,bcm63xx-tch-bpm))

define KernelPackage/JumboFrames
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom BPM Jumbo Frames
  DEPENDS:=@TARGET_brcm63xx_tch +kmod-bcm63xx-tch-bpm
  KCONFIG:=CONFIG_BCM_BPM_BUF_MEM_PRCNT=20 CONFIG_BCM_JUMBO_FRAME=y
endef

$(eval $(call KernelPackage,JumboFrames))

define KernelPackage/bcm63xx-tch-pktflow
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom Packet Flow driver
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_PKTFLOW
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/char/pktflow/bcm9$(BRCM_CHIP)/pktflow.ko
  AUTOLOAD:=$(call AutoLoad,53,pktflow)
endef

$(eval $(call KernelPackage,bcm63xx-tch-pktflow))


define KernelPackage/bcm63xx-tch-fap
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom FAP driver
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_FAP CONFIG_BCM_FAP_LAYER2=n CONFIG_BCM_FAP_GSO=y CONFIG_BCM_FAP_GSO_LOOPBACK=y CONFIG_BCM_FAP_IPV6=y
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/char/fap/bcm9$(BRCM_CHIP)/bcmfap.ko
  AUTOLOAD:=$(call AutoLoad,54,bcmfap)
endef

$(eval $(call KernelPackage,bcm63xx-tch-fap))

define KernelPackage/bcm63xx-tch-bcmtm
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom Traffic Manager Driver
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_TM
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/net/tm/bcm9$(BRCM_CHIP)/bcmtm.ko
  AUTOLOAD:=$(call AutoLoad,54,bcmtm)
endef

$(eval $(call KernelPackage,bcm63xx-tch-bcmtm))

define KernelPackage/bcm63xx-tch-enet
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom Ethernet driver
ifdef CONFIG_TARGET_brcm63xx_tch_HG1XEWAN
  DEPENDS:=@TARGET_brcm63xx_tch +kmod-bcm63xx-tch-pktflow +kmod-bcm63xx-tch-pktrunner +kmod-bcm63xx-tch-bdmf +kmod-bcm63xx-tch-rdpa +TARGET_brcm63xx_tch:bdmf_shell +TARGET_brcm63xx_tch:swmdk
else
  DEPENDS:=@TARGET_brcm63xx_tch +kmod-bcm63xx-tch-pktflow
endif
  KCONFIG:=CONFIG_BCM_ENET
  FILES:=$(BRCMDRIVERS_DIR)/opensource/net/enet/bcm9$(BRCM_CHIP)/bcm_enet.ko
  AUTOLOAD:=$(call AutoLoad,55,bcm_enet)
endef

$(eval $(call KernelPackage,bcm63xx-tch-enet))

define KernelPackage/bcm63xx-tch-bdmf
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom BDMF driver
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_BDMF
  FILES:=$(BRCMDRIVERS_DIR)/opensource/char/bdmf/bcm9$(BRCM_CHIP)/bdmf.ko
  AUTOLOAD:=$(call AutoLoad,50,bdmf)
endef

$(eval $(call KernelPackage,bcm63xx-tch-bdmf))

define KernelPackage/bcm63xx-tch-rdpa
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom RDPA driver
  DEPENDS:=@TARGET_brcm63xx_tch +kmod-bcm63xx-tch-rdpa-gpl
  KCONFIG:=CONFIG_BCM_RDPA
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/char/rdpa/bcm9$(BRCM_CHIP)/rdpa.ko
  AUTOLOAD:=$(call AutoLoad,52,rdpa)
endef

$(eval $(call KernelPackage,bcm63xx-tch-rdpa))

define KernelPackage/bcm63xx-tch-ethoam
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom ETHOAM driver
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_TMS
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/char/tms/bcm9$(BRCM_CHIP)/nciTMSkmod.ko
endef

$(eval $(call KernelPackage,bcm63xx-tch-ethoam))

define KernelPackage/bcm63xx-tch-rdpa-mw
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom RDPA Middleware driver
  DEPENDS:=@TARGET_brcm63xx_tch +kmod-bcm63xx-tch-rdpa-gpl +kmod-bcm63xx-tch-bdmf
  KCONFIG:=CONFIG_BCM_RDPA_MW
  FILES:=$(BRCMDRIVERS_DIR)/opensource/char/rdpa_mw/bcm9$(BRCM_CHIP)/rdpa_mw.ko
  AUTOLOAD:=$(call AutoLoad,52,rdpa_mw)
endef

$(eval $(call KernelPackage,bcm63xx-tch-rdpa-mw))

define KernelPackage/bcm63xx-tch-rdpa-gpl
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom RDPA GPL driver
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_RDPA_GPL
  FILES:=$(BRCMDRIVERS_DIR)/opensource/char/rdpa_gpl/bcm9$(BRCM_CHIP)/rdpa_gpl.ko
  AUTOLOAD:=$(call AutoLoad,51,rdpa_gpl)
endef

$(eval $(call KernelPackage,bcm63xx-tch-rdpa-gpl))

define KernelPackage/bcm63xx-tch-rdpa-drv
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom RDPA driver
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_RDPA_DRV
ifneq ($(wildcard $(BRCMDRIVERS_DIR)/opensource/char/rdpa_drv/bcm9$(BRCM_CHIP)/rdpa_cmd.ko),)
  # For 4.16L.04 or higher
  FILES:=$(BRCMDRIVERS_DIR)/opensource/char/rdpa_drv/bcm9$(BRCM_CHIP)/rdpa_cmd.ko
else
ifdef CONFIG_PACKAGE_kmod-brcm-4.16L.02_voice4.16L.01
  FILES:=$(BRCMDRIVERS_DIR)/opensource/char/rdpa_drv/bcm9$(BRCM_CHIP)/rdpa_cmd_drv.ko \
         $(BRCMDRIVERS_DIR)/opensource/char/rdpa_drv/bcm9$(BRCM_CHIP)/rdpa_cmd_spdsvc.ko \
         $(BRCMDRIVERS_DIR)/opensource/char/rdpa_drv/bcm9$(BRCM_CHIP)/rdpa_cmd_tm.ko
else
  FILES:=$(BRCMDRIVERS_DIR)/opensource/char/rdpa_drv/bcm9$(BRCM_CHIP)/rdpa_cmd_drv.ko \
         $(BRCMDRIVERS_DIR)/opensource/char/rdpa_drv/bcm9$(BRCM_CHIP)/rdpa_cmd_spdsvc.ko \
         $(BRCMDRIVERS_DIR)/opensource/char/rdpa_drv/bcm9$(BRCM_CHIP)/rdpa_cmd_ds_wan_udp_filter.ko \
         $(BRCMDRIVERS_DIR)/opensource/char/rdpa_drv/bcm9$(BRCM_CHIP)/rdpa_cmd_tm.ko
endif
endif
  AUTOLOAD:=
endef

$(eval $(call KernelPackage,bcm63xx-tch-rdpa-drv))


define KernelPackage/bcm63xx-tch-pktrunner
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom Packet Runner
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_PKTRUNNER
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/char/pktrunner/bcm9$(BRCM_CHIP)/pktrunner.ko
  AUTOLOAD:=$(call AutoLoad,53,pktrunner)
endef

$(eval $(call KernelPackage,bcm63xx-tch-pktrunner))

define KernelPackage/bcm63xx-tch-vlan
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom VLAN driver
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_VLAN
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/char/vlan/bcm9$(BRCM_CHIP)/bcmvlan.ko
  AUTOLOAD:=$(call AutoLoad,56,bcmvlan)
endef

$(eval $(call KernelPackage,bcm63xx-tch-vlan))

define KernelPackage/bcm63xx-tch-wireless
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom Wireless driver
  DEPENDS:=@TARGET_brcm63xx_tch +kmod-bcm63xx-tch-enet
  DEPENDS+=+(PACKAGE_kmod-brcm-4.16L.02_voice4.16L.01):kmod-bcm63xx-tch-wireless-emf
  DEPENDS+=+(PACKAGE_kmod-brcm-4.16L.02A):kmod-bcm63xx-tch-wireless-emf
  DEPENDS+=+(PACKAGE_kmod-brcm-4.16L.03):kmod-bcm63xx-tch-wireless-emf
  DEPENDS+=+(PACKAGE_kmod-brcm-4.16L.04):kmod-bcm63xx-tch-wireless-emf
  DEPENDS+=+(PACKAGE_kmod-brcm-4.16L.05):kmod-bcm63xx-tch-wireless-emf
  KCONFIG:=CONFIG_BCM_WLAN CONFIG_BCM_WLALTBLD="ap_2nv"
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/build/wlobj-wlconfig_lx_wl_dslcpe_pci_ap_2nv-kdb/wl.ko
  AUTOLOAD:=$(call AutoLoad,57,wl)
endef

#Common nvram vars
define KernelPackage/bcm63xx-tch-wireless/install
	$(INSTALL_DIR) $(1)/etc/wlan_common
#For impl22 and higher
ifneq ($(wildcard $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/main/src/shared/bcmcmn_nvramvars.bin),)
	$(INSTALL_DATA) $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/main/src/shared/bcmcmn_nvramvars.bin $(1)/etc/wlan_common/bcmcmn_nvramvars.bin
else
#For impl18 and higher
ifneq ($(wildcard $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/build/wlobj-wlconfig_lx_wl_dslcpe_pci_ap_2nv-kdb/shared/bcmcmn_nvramvars.bin),)
	$(INSTALL_DATA) $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/build/wlobj-wlconfig_lx_wl_dslcpe_pci_ap_2nv-kdb/shared/bcmcmn_nvramvars.bin $(1)/etc/wlan_common/bcmcmn_nvramvars.bin
else
	$(INSTALL_DATA) $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/build/wlobj-wlconfig_lx_wl_dslcpe_pci_ap_2nv-kdb/shared/nvramvars_cmn.bin $(1)/etc/wlan_common/bcmcmn_nvramvars.bin
endif
endif
endef

$(eval $(call KernelPackage,bcm63xx-tch-wireless))

define KernelPackage/bcm63xx-tch-wireless-emf
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom Wireless EMF driver
  DEPENDS:=@PACKAGE_kmod-brcm-4.16L.02_voice4.16L.01||@PACKAGE_kmod-brcm-4.16L.02A||@PACKAGE_kmod-brcm-4.16L.03||@PACKAGE_kmod-brcm-4.16L.04||@PACKAGE_kmod-brcm-4.16L.05
  #For impl22 and higher
  ifneq ($(wildcard $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/main/src/emf/wlemf.ko),)
    FILES:=$(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/main/src/emf/wlemf.ko
  else
    FILES:=$(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/emf/wlemf.ko
  endif
  AUTOLOAD:=$(call AutoLoad,56,wlemf)
endef

$(eval $(call KernelPackage,bcm63xx-tch-wireless-emf))

define KernelPackage/bcm63xx-tch-wireless-wlcsm
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom Wireless WLCSM driver
  DEPENDS:=@PACKAGE_kmod-brcm-4.16L.02_voice4.16L.01||@PACKAGE_kmod-brcm-4.16L.02A||@PACKAGE_kmod-brcm-4.16L.03||@PACKAGE_kmod-brcm-4.16L.04||@PACKAGE_kmod-brcm-4.16L.05
  #For impl22 and higher
  ifneq ($(wildcard $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/main/src/wl/wlcsm_ext/wlcsm.ko),)
    FILES:=$(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/main/src/wl/wlcsm_ext/wlcsm.ko
  else 
    FILES:=$(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/wl/wlcsm_ext/wlcsm.ko
  endif 
  AUTOLOAD:=$(call AutoLoad,56,wlcsm)
endef

$(eval $(call KernelPackage,bcm63xx-tch-wireless-wlcsm))

define KernelPackage/bcm63xx-tch-wireless-dhd
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom Wireless driver (offloaded)
  DEPENDS:=@PACKAGE_kmod-brcm-4.16L.02_voice4.16L.01||@PACKAGE_kmod-brcm-4.16L.02A||@PACKAGE_kmod-brcm-4.16L.03||@PACKAGE_kmod-brcm-4.16L.04||@PACKAGE_kmod-brcm-4.16L.05 +kmod-bcm63xx-tch-enet +kmod-bcm63xx-tch-wireless-emf
  KCONFIG:=CONFIG_BCM_WLAN CONFIG_BCM_WLALTBLD="ap_2nv" CONFIG_BCM_DHD_RUNNER=y
  #For impl22 and higher
  ifneq ($(wildcard $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/build/dhdobj-dhdconfig_lx_dhd_dslcpe_pci_ap_2nv-kdb/dhd.ko),)
    FILES:=$(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/build/dhdobj-dhdconfig_lx_dhd_dslcpe_pci_ap_2nv-kdb/dhd.ko    
  else
    FILES:=$(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/dhd/build/dhdobj-dhdconfig_lx_dhd_dslcpe_pci_ap_2nv-kdb/dhd.ko
  endif
  AUTOLOAD:=$(call AutoLoad,58,dhd)
endef

#DHD firmware + common nvram vars
define KernelPackage/bcm63xx-tch-wireless-dhd/install
	$(INSTALL_DIR) $(1)/etc/wlan_common
#For impl22 and higher
ifneq ($(wildcard $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/main/src/shared/bcmcmn_nvramvars.bin),)
	$(INSTALL_DATA) $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/main/src/shared/bcmcmn_nvramvars.bin $(1)/etc/wlan_common/bcmcmn_nvramvars.bin
else
#For impl18 and higher
ifneq ($(wildcard $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/build/wlobj-wlconfig_lx_wl_dslcpe_pci_ap_2nv-kdb/shared/bcmcmn_nvramvars.bin),)
	$(INSTALL_DATA) $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/build/wlobj-wlconfig_lx_wl_dslcpe_pci_ap_2nv-kdb/shared/bcmcmn_nvramvars.bin $(1)/etc/wlan_common/bcmcmn_nvramvars.bin
else
	$(INSTALL_DATA) $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/build/wlobj-wlconfig_lx_wl_dslcpe_pci_ap_2nv-kdb/shared/nvramvars_cmn.bin $(1)/etc/wlan_common/bcmcmn_nvramvars.bin
endif
endif
	$(INSTALL_DIR) $(1)/etc/wlan_dhd
	$(INSTALL_DIR) $(1)/etc/wlan_dhd/43602a1
	$(INSTALL_DIR) $(1)/etc/wlan_dhd/mfg/43602a1
#For impl22 and higher
ifneq ($(wildcard $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/dhd/src/dongle/43602a1/rtecdc.bin),)
	#TODO: only install what is needed (43602 or 4366)
	$(INSTALL_DATA) $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/dhd/src/dongle/43602a1/rtecdc.bin $(1)/etc/wlan_dhd/43602a1
	$(INSTALL_DATA) $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/dhd/src/dongle/mfg/43602a1/rtecdc.bin $(1)/etc/wlan_dhd/mfg/43602a1
	$(INSTALL_DIR) $(1)/etc/wlan_dhd/4366b1
	$(INSTALL_DIR) $(1)/etc/wlan_dhd/mfg/4366b1
	$(INSTALL_DATA) $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/dhd/src/dongle/4366b1/rtecdc.bin $(1)/etc/wlan_dhd/4366b1
	$(INSTALL_DATA) $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/dhd/src/dongle/mfg/4366b1/rtecdc.bin $(1)/etc/wlan_dhd/mfg/4366b1
	$(INSTALL_DIR) $(1)/etc/wlan_dhd/4366c0
	$(INSTALL_DIR) $(1)/etc/wlan_dhd/mfg/4366c0
	$(INSTALL_DATA) $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/dhd/src/dongle/4366c0/rtecdc.bin $(1)/etc/wlan_dhd/4366c0
	$(INSTALL_DATA) $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/dhd/src/dongle/mfg/4366c0/rtecdc.bin $(1)/etc/wlan_dhd/mfg/4366c0
else
	$(INSTALL_DATA) $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/dhd/dongle/43602a1/rtecdc.bin $(1)/etc/wlan_dhd/43602a1
	$(INSTALL_DATA) $(BRCMDRIVERS_DIR)/broadcom/net/wl/bcm9$(BRCM_CHIP)/dhd/dongle/mfg/43602a1/rtecdc.bin $(1)/etc/wlan_dhd/mfg/43602a1
endif
endef

$(eval $(call KernelPackage,bcm63xx-tch-wireless-dhd))

define KernelPackage/bcm63xx-tch-usb
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom USB driver
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_USB
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/net/usb/bcm9$(BRCM_CHIP)/bcm_usb.ko
  AUTOLOAD:=$(call AutoLoad,57,bcm_usb)
endef

$(eval $(call KernelPackage,bcm63xx-tch-usb))

define KernelPackage/bcm63xx-tch-xtm
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom XTM Config driver
  DEPENDS:=@TARGET_brcm63xx_tch +(!PACKAGE_kmod-brcm-4.14L.04):kmod-bcm63xx-tch-xtmrtdrv
  KCONFIG:=CONFIG_BCM_XTMCFG CONFIG_ADSL_OS_OFFSET=18874368 CONFIG_ADSL_OS_RESERVED_MEM=1253376
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/char/xtmcfg/bcm9$(BRCM_CHIP)/bcmxtmcfg.ko
  AUTOLOAD:=$(call AutoLoad,59,bcmxtmcfg)
endef

$(eval $(call KernelPackage,bcm63xx-tch-xtm))

define KernelPackage/bcm63xx-tch-xtmrtdrv
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom XTM RT driver
  DEPENDS:=@TARGET_brcm63xx_tch @(!PACKAGE_kmod-brcm-4.14L.04)
  KCONFIG:=CONFIG_BCM_XTMRT
  FILES:=$(BRCMDRIVERS_DIR)/opensource/net/xtmrt/bcm9$(BRCM_CHIP)/bcmxtmrtdrv.ko
  AUTOLOAD:=$(call AutoLoad,50,bcmxtmrtdrv)
endef

$(eval $(call KernelPackage,bcm63xx-tch-xtmrtdrv))

define KernelPackage/bcm63xx-tch-wfd
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom Wireless Forwarding Driver
  DEPENDS:=@PACKAGE_kmod-brcm-4.16L.02_voice4.16L.01||@PACKAGE_kmod-brcm-4.16L.02A||@PACKAGE_kmod-brcm-4.16L.03||@PACKAGE_kmod-brcm-4.16L.04||@PACKAGE_kmod-brcm-4.16L.05
  KCONFIG:=CONFIG_BCM_WIFI_FORWARDING_DRV CONFIG_BCM_WFD_CHAIN_SUPPORT=y
  FILES:=$(BRCMDRIVERS_DIR)/opensource/net/wfd/bcm9$(BRCM_CHIP)/wfd.ko
  AUTOLOAD:=$(call AutoLoad,56,wfd)
endef

$(eval $(call KernelPackage,bcm63xx-tch-wfd))

define KernelPackage/bcm63xx-tch-adsl
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom ADSL driver
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_ADSL
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/char/adsl/bcm9$(BRCM_CHIP)/adsldd.ko
  AUTOLOAD:=$(call AutoLoad,60,adsldd)
endef

define KernelPackage/bcm63xx-tch-adsl/install
	$(INSTALL_DIR) $(1)/etc/adsl
ifneq ($(wildcard $(BRCMDRIVERS_DIR)/broadcom/char/adsl/bcm9$(BRCM_CHIP)/adsl_phy.bin),)
	$(INSTALL_DATA) $(BRCMDRIVERS_DIR)/broadcom/char/adsl/bcm9$(BRCM_CHIP)/adsl_phy.bin $(1)/etc/adsl
endif
ifneq ($(wildcard $(BRCMDRIVERS_DIR)/broadcom/char/adsl/bcm9$(BRCM_CHIP)/adsl_phy0.bin),)
	$(INSTALL_DATA) $(BRCMDRIVERS_DIR)/broadcom/char/adsl/bcm9$(BRCM_CHIP)/adsl_phy0.bin $(1)/etc/adsl
endif
ifneq ($(wildcard $(BRCMDRIVERS_DIR)/broadcom/char/adsl/bcm9$(BRCM_CHIP)/adsl_phy1.bin),)
	$(INSTALL_DATA) $(BRCMDRIVERS_DIR)/broadcom/char/adsl/bcm9$(BRCM_CHIP)/adsl_phy1.bin $(1)/etc/adsl
endif
endef

$(eval $(call KernelPackage,bcm63xx-tch-adsl))

define KernelPackage/bcm63xx-tch-pwrmngt
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom Power Management driver
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_PWRMNGT
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/char/pwrmngt/bcm9$(BRCM_CHIP)/pwrmngtd.ko
  AUTOLOAD:=$(call AutoLoad,61,pwrmngtd)
endef

$(eval $(call KernelPackage,bcm63xx-tch-pwrmngt))

define KernelPackage/bcm63xx-tch-arl
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom ARL Table Management driver
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_ARL
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/char/arl/bcm9$(BRCM_CHIP)/bcmarl.ko
  AUTOLOAD:=$(call AutoLoad,62,bcmarl)
endef

$(eval $(call KernelPackage,bcm63xx-tch-arl))

define KernelPackage/bcm63xx-tch-p8021ag
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom P8021AG driver
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_P8021AG
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/char/p8021ag/bcm9$(BRCM_CHIP)/p8021ag.ko
  AUTOLOAD:=$(call AutoLoad,63,p8021ag)
endef

$(eval $(call KernelPackage,bcm63xx-tch-p8021ag))

define KernelPackage/bcm63xx-tch-endpoint
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom Endpoint driver
  DEPENDS:=@TARGET_brcm63xx_tch 
  KCONFIG:=CONFIG_BCM_ENDPOINT
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/char/endpoint/bcm9$(BRCM_CHIP)/endpointdd.ko
  AUTOLOAD:=
endef

$(eval $(call KernelPackage,bcm63xx-tch-endpoint))

define KernelPackage/bcm63xx-tch-nfc
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom NFC i2c driver
  DEPENDS:=@TARGET_brcm63xx_tch @PACKAGE_kmod-brcm-4.16L.04||@PACKAGE_kmod-brcm-4.16L.05 +kmod-i2c-core +kmod-i2c-algo-bit
  KCONFIG:=CONFIG_BCM_NFC_I2C CONFIG_BCM_NFC_I2C_IMPL=1
  FILES:=$(BRCMDRIVERS_DIR)/opensource/char/nfc/bcm9$(BRCM_CHIP)/bcm2079x-i2c.ko
  AUTOLOAD:=$(call AutoLoad,90,bcm2079x-i2c)
endef

$(eval $(call KernelPackage,bcm63xx-tch-nfc))

define KernelPackage/bcm63xx-tch-pcmshim
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom PCM SHIM driver
  DEPENDS:=@TARGET_brcm63xx_tch 
  KCONFIG:=CONFIG_BCM_PCMSHIM
  FILES:=$(BRCMDRIVERS_DIR)/opensource/char/pcmshim/bcm9$(BRCM_CHIP)/pcmshim.ko
  AUTOLOAD:=$(call AutoLoad,99,pcmshim)
endef

$(eval $(call KernelPackage,bcm63xx-tch-pcmshim))


define KernelPackage/bcm63xx-tch-dect
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom DECT driver
  DEPENDS:=@TARGET_brcm63xx_tch 
  KCONFIG:=CONFIG_BCM_DECT
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/char/dect/bcm9$(BRCM_CHIP)/dect.ko
  AUTOLOAD:=$(call AutoLoad,99,dect)
endef

$(eval $(call KernelPackage,bcm63xx-tch-dect))


define KernelPackage/bcm63xx-tch-dectshim
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom DECTSHIM driver
  DEPENDS:=@TARGET_brcm63xx_tch 
  KCONFIG:=CONFIG_BCM_DECTSHIM
  FILES:=$(BRCMDRIVERS_DIR)/opensource/char/dectshim/bcm9$(BRCM_CHIP)/dectshim.ko
  AUTOLOAD:=$(call AutoLoad,99,dectshim)
endef

$(eval $(call KernelPackage,bcm63xx-tch-dectshim))

define KernelPackage/ipt-dyndscp-bcm63xx-tch
  SUBMENU:=Netfilter Extensions
  TITLE:=Broadcom DSCP inheritance from WAN
  DEPENDS:=@TARGET_brcm63xx_tch +kmod-ipt-conntrack
  KCONFIG:=CONFIG_NF_DYNDSCP
  FILES:=$(LINUX_DIR)/net/netfilter/nf_dyndscp.ko
  AUTOLOAD:=$(call AutoLoad,46,nf_dyndscp)
endef

$(eval $(call KernelPackage,ipt-dyndscp-bcm63xx-tch))

define KernelPackage/ipt-nathelper-rtsp-bcm63xx-tch
  SUBMENU:=Netfilter Extensions
  TITLE:=Broadcom kernel RTSP ALG
  DEPENDS:=@TARGET_brcm63xx_tch +kmod-ipt-conntrack +kmod-ipt-nat
  KCONFIG:=CONFIG_NF_CONNTRACK_RTSP CONFIG_NF_NAT_RTSP
  FILES:=$(LINUX_DIR)/net/netfilter/nf_conntrack_rtsp.ko $(LINUX_DIR)/net/ipv4/netfilter/nf_nat_rtsp.ko
  AUTOLOAD:=$(call AutoLoad,46,nf_conntrack_rtsp nf_nat_rtsp)
endef

$(eval $(call KernelPackage,ipt-nathelper-rtsp-bcm63xx-tch))

define KernelPackage/ipt-skiplog
  SUBMENU:=Netfilter Extensions
  TITLE:=Broadcom kernel xt SKIPLOG
  DEPENDS:=@TARGET_brcm63xx_tch||TARGET_brcm63xx_arm_tch
  KCONFIG:=CONFIG_NETFILTER_XT_TARGET_SKIPLOG
  FILES:=$(LINUX_DIR)/net/netfilter/xt_SKIPLOG.ko
  AUTOLOAD:=$(call AutoLoad,70,xt_SKIPLOG)
endef

$(eval $(call KernelPackage,ipt-skiplog))
define KernelPackage/bcm63xx-tch-moca
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom MoCA driver
  DEPENDS:=@TARGET_brcm63xx_tch +kmod-bcm63xx-tch-enet
  KCONFIG:=CONFIG_BCM_MoCA
  FILES:=$(BRCMDRIVERS_DIR)/opensource/char/moca/bcm9$(BRCM_CHIP)/bcmmoca.ko
  AUTOLOAD:=$(call AutoLoad,58,bcmmoca)
endef

$(eval $(call KernelPackage,bcm63xx-tch-moca))


define KernelPackage/bcm63xx-tch-dpi
  SUBMENU:=Broadcom specific kernel modules
  TITLE:=Broadcom DPI driver
  DEPENDS:=@TARGET_brcm63xx_tch @PACKAGE_kmod-brcm-4.16L.05
  KCONFIG:=CONFIG_BCM_DPI CONFIG_BRCM_DPI=y CONFIG_BCM_DPI_IMPL=1
  FILES:=$(BRCMDRIVERS_DIR)/broadcom/char/dpiengine/bcm9$(BRCM_CHIP)/tdts.ko \
         $(BRCMDRIVERS_DIR)/opensource/char/dpi/impl1/dpicore.ko
  AUTOLOAD:=
endef

$(eval $(call KernelPackage,bcm63xx-tch-dpi))

define KernelPackage/brcm-4.16L.01
  SUBMENU:=Broadcom release
  TITLE:=Broadcom release 4.16L.01
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_WLAN_IMPL=16
  PROVIDES:=brcm-release
endef

$(eval $(call KernelPackage,brcm-4.16L.01))

define KernelPackage/brcm-4.14L.04
  SUBMENU:=Broadcom release
  TITLE:=Broadcom release 4.14L.04
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_WLAN_IMPL=16
  PROVIDES:=brcm-release
endef

$(eval $(call KernelPackage,brcm-4.14L.04))

define KernelPackage/brcm-4.16L.02_voice4.16L.01
  SUBMENU:=Broadcom release
  TITLE:=Broadcom release 4.16L.02 with voice on 4.16L.01
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_WLAN_IMPL=18
  PROVIDES:=brcm-release
endef

$(eval $(call KernelPackage,brcm-4.16L.02_voice4.16L.01))


define KernelPackage/brcm-4.16L.02A
  SUBMENU:=Broadcom release
  TITLE:=Broadcom release 4.16L.02A
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_WLAN_IMPL=18
  PROVIDES:=brcm-release
endef

$(eval $(call KernelPackage,brcm-4.16L.02A))

define KernelPackage/brcm-4.16L.03
  SUBMENU:=Broadcom release
  TITLE:=Broadcom release 4.16L.03
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_WLAN_IMPL=20
  PROVIDES:=brcm-release
endef

$(eval $(call KernelPackage,brcm-4.16L.03))


define KernelPackage/brcm-4.16L.04
  SUBMENU:=Broadcom release
  TITLE:=Broadcom release 4.16L.04
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_WLAN_IMPL=22
  PROVIDES:=brcm-release
endef

$(eval $(call KernelPackage,brcm-4.16L.04))

define KernelPackage/brcm-4.16L.05
  SUBMENU:=Broadcom release
  TITLE:=Broadcom release 4.16L.05
  DEPENDS:=@TARGET_brcm63xx_tch
  KCONFIG:=CONFIG_BCM_WLAN_IMPL=22
  PROVIDES:=brcm-release
endef

$(eval $(call KernelPackage,brcm-4.16L.05))

