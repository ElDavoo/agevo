#
# Copyright (C) 2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

define Profile/963138BGWV
  NAME:=963138BGWV
#  PACKAGES:=kmod-spi-bitbang kmod-bcm63xx-spi
endef

define Profile/963138BGWV/description
  Package set compatible with 963138BGWV
endef

$(eval $(call Profile,963138BGWV))
