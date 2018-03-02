#!/bin/bash

CLEAN_DIRS=("bcmdrivers"
    "bcmdrivers/broadcom/char/adsl/impl1"
    "bcmdrivers/broadcom/char/bpm/impl1"
    "bcmdrivers/broadcom/char/chipinfo/impl1"
    "bcmdrivers/broadcom/char/dect/impl1"
    "bcmdrivers/broadcom/char/dspapp/impl1"
    "bcmdrivers/broadcom/char/endpoint/impl1"
    "bcmdrivers/broadcom/char/fap/impl1"
    "bcmdrivers/broadcom/char/gpon/impl2"
    "bcmdrivers/broadcom/char/otp/impl1"
    "bcmdrivers/broadcom/char/pktflow/impl1"
    "bcmdrivers/broadcom/char/pktrunner/impl2"
    "bcmdrivers/broadcom/char/pwrmngt/impl1"
    "bcmdrivers/broadcom/char/rdpa/impl1"
    "bcmdrivers/broadcom/char/tms/impl1"
    "bcmdrivers/broadcom/char/wlan/impl1"
    "bcmdrivers/broadcom/char/wlcsm_ext/impl1"
    "bcmdrivers/broadcom/char/xtmcfg/impl2"
    "bcmdrivers/opensource/char/bdmf/impl1"
    "bcmdrivers/opensource/char/board/bcm963xx/impl1"
    "bcmdrivers/opensource/char/bt_serial/impl1"
    "bcmdrivers/opensource/char/dectshim/impl1"
    "bcmdrivers/opensource/char/dpi/impl1"
    "bcmdrivers/opensource/char/i2c/busses/impl1"
    "bcmdrivers/opensource/char/i2c/chips/impl1"
    "bcmdrivers/opensource/char/i2s/impl1"
    "bcmdrivers/opensource/char/moca/impl2"
    "bcmdrivers/opensource/char/pcmshim/impl1"
    "bcmdrivers/opensource/char/rdpa_drv/impl1"
    "bcmdrivers/opensource/char/rdpa_gpl/impl1"
    "bcmdrivers/opensource/char/rdpa_gpl_ext/impl1"
    "bcmdrivers/opensource/char/rdpa_mw/impl1"
    "bcmdrivers/opensource/char/serial/impl1"
    "bcmdrivers/opensource/char/sim_card/impl1"
    "bcmdrivers/opensource/char/spudd/impl2"
    "bcmdrivers/opensource/char/timer/impl1"
    "bcmdrivers/opensource/char/trng/impl2"
    "bcmdrivers/opensource/net/bridge/impl1"
    "bcmdrivers/opensource/net/enet/impl5"
    "bcmdrivers/opensource/net/enet/shared"
    "bcmdrivers/opensource/net/wfd/impl1"
    "bcmdrivers/opensource/net/xtmrt/impl5"
    "shared/opensource/boardparms/bcm963xx"
    "shared/opensource/drivers"
    "shared/opensource/drv"
    "shared/opensource/drv/dpi"
    "shared/opensource/drv/mdio"
    "shared/opensource/drv/phys"
    "shared/opensource/drv/unimac"
    "shared/opensource/flash"
    "shared/opensource/pmc/impl1"
    "shared/opensource/pmc/impl2"
    "shared/opensource/rdp"
    "shared/opensource/spi"
    "shared/opensource/utils")

for d in ${CLEAN_DIRS[@]}; do
    rm -f $d/*.ko
    rm -f $d/*.o
    rm -f $d/*.mod.c
    rm -f $d/*.mod.o
    rm -f $d/.*.cmd
done
