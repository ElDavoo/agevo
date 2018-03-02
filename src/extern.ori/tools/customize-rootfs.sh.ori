#!/bin/bash

ROOTFS_DIR=$1

usage() {
  echo "usage: $0 <rootfs directory>"
}

dbg() {
  echo $1
}

if [ "x$ROOTFS_DIR" = "x" ] ; then
  usage
  exit -1
fi

if [ ! -d $ROOTFS_DIR ] ; then
  echo "$ROOTFS_DIR does not exist!"
  exit -1
fi

#copy /etc/dbus-1 to /usr/share/config/dbus-1
mkdir -p $ROOTFS_DIR/usr/share/config
#cp -af $ROOTFS_DIR/etc/dbus-1 $ROOTFS_DIR/usr/share/config/
#cp -af $ROOTFS_DIR/etc/config/glbcfg.* $ROOTFS_DIR/usr/share/config/
#cp -af $ROOTFS_DIR/etc/config/.glbcfg $ROOTFS_DIR/usr/share/config/
#cp -af $ROOTFS_DIR/etc/passwd  $ROOTFS_DIR/usr/share/config/
#cp -af $ROOTFS_DIR/etc/config/arc-middle $ROOTFS_DIR/usr/share/config/
#cp -af $ROOTFS_DIR/etc/services $ROOTFS_DIR/usr/share/services
#cp -af $ROOTFS_DIR/etc/l7-protocols $ROOTFS_DIR/usr/share/l7-protocols


# symbol link /var
rm -rf $ROOTFS_DIR/var
mkdir -p $ROOTFS_DIR/tmp/var
ln -sf ./tmp/var $ROOTFS_DIR/var

# mkdir /dev
mkdir -p $ROOTFS_DIR/dev

# mkdir /proc
mkdir -p $ROOTFS_DIR/proc

# mkdir /sys
mkdir -p $ROOTFS_DIR/sys

# clean /ramdisk_copy
rm -rf $ROOTFS_DIR/ramdisk_copy

# dbus message /usr/share/msg
mkdir -p $ROOTFS_DIR/usr/share/msg

#rm -rf $ROOTFS_DIR/www
rm -rf $ROOTFS_DIR/webs
rm -rf $ROOTFS_DIR/lib/modules/3.4.11

# --- broadcom customize ---
ROOTFS=$ROOTFS_DIR

chmod +w $ROOTFS/etc/fstab
echo -e "tmpfs\t/mnt\ttmpfs\tsize=16k\t\t0\t0" > $ROOTFS/etc/fstab
echo -e "mtd:data\t/data\tjffs2\t,\t\t0\t0" >> $ROOTFS/etc/fstab
echo -e "mtd:bootfs\t/bootfs\tjffs2\tro\t\t0\t0" >> $ROOTFS/etc/fstab
echo -e "mtd:answer_machine\t/answer_machine\tjffs2\trw\t\t0\t0" >> $ROOTFS/etc/fstab
chmod -w $ROOTFS/etc/fstab

# convert Snn*.symlink and Knn*.symlink files to real symlinks
flist=`ls ${ROOTFS}/etc/rc3.d/S*.symlink ${ROOTFS}/etc/rc3.d/K*.symlink 2> /dev/null`
for f in $flist
do
	f=$(basename $f)
	numbase=${f%.*}
	namebase=`echo $numbase | cut -c 4-`
	(cd ${ROOTFS}/etc/rc3.d; rm -f ${numbase}.symlink; ln -s ../init.d/${namebase}.sh ${numbase})
done
# Create directories as needed
mkdir $ROOTFS/mnt
mkdir $ROOTFS/data
mkdir $ROOTFS/answer_machine
# Create symbolic links
mkdir $ROOTFS/dev/misc
ln -s /var/fuse $ROOTFS/dev/misc/fuse
ln -s /var/fuse $ROOTFS/dev/fuse
ln -s /var/mtab $ROOTFS/etc/mtab
ln -s /var/log/log $ROOTFS/dev/log
ln -s /var/sysmsg $ROOTFS/etc/sysmsg
ln -s /var/passwd $ROOTFS/etc/passwd
ln -s /var/group $ROOTFS/etc/group
ln -s /var/ppp/pppmsg $ROOTFS/etc/pppmsg
ln -s /var/fyi/sys/dns $ROOTFS/etc/resolv.conf
ln -s /var/fyi/sys/gateway $ROOTFS/etc/gateway.conf
ln -s /var/udhcpd/udhcpd.conf $ROOTFS/etc/udhcpd.conf
ln -s /var/udhcpd/udhcpd.leases $ROOTFS/etc/udhcpd.leases
ln -s /var/dms.conf $ROOTFS/etc/dms.conf
ln -s /var/ipsec/ipsec.conf $ROOTFS/etc/ipsec.conf
ln -s /var/ipsec/racoon.conf $ROOTFS/etc/racoon.conf
ln -s /var/ipsec/psk.txt $ROOTFS/etc/psk.txt
ln -s /var/iproute2/rt_tables $ROOTFS/etc/iproute2/rt_tables
ln -s /var/tmp $ROOTFS/tmp
ln -s /var/samba $ROOTFS/etc/samba
ln -s /tmp/TZ $ROOTFS/etc/TZ     #System need "/etc/TZ" to store timezone, "/tmp/TZ" create by arc-ntpclient

# Update kernel directory based on kernel:
sed -i "s|^KERNELVER=_set_by_buildFS_$|KERNELVER=3.4.11-rt19|" $ROOTFS/etc/init.d/*.sh;

cp -af $ROOTFS_DIR/etc/ $ROOTFS_DIR/usr/share/config/

# symbol link /etc
rm -rf $ROOTFS_DIR/etc
mkdir -p $ROOTFS_DIR/tmp/etc
ln -sf ./tmp/etc $ROOTFS_DIR/etc

# Build modules again to fix modules can not be install issue
# when we find a better way we will remove this
BSP_DIR=$ROOTFS_DIR/../../../extern/broadcom-bsp
TARGET_INSTALL_DIR=$ROOTFS_DIR/../../../extern/target-install
#cd $BSP_DIR && make modbuild
#cd -
cp -af $BSP_DIR/targets/VRV9510RWAC34-1-B-ASU/modules/lib $ROOTFS_DIR

#STRIP=/opt/toolchains/crosstools-mipsel-gcc-4.6-linux-3.4-uclibc-0.9.32-binutils-2.21/usr/bin/mipsel-unknown-linux-uclibc-strip
STRIP=/opt/toolchains/crosstools-arm-gcc-4.6-linux-3.4-uclibc-0.9.32-binutils-2.21-NPTL/usr/bin/arm-unknown-linux-uclibcgnueabi-strip

eval "find $ROOTFS/lib/modules -name '*.ko' |xargs $STRIP --strip-debug"

# Copy *.bin here temporarily until we find a better way
mkdir -p $ROOTFS_DIR/usr/wlan
cp -af $BSP_DIR/targets/VRV9510RWAC34-1-B-ASU/fs.install/etc/wlan/dhd $ROOTFS_DIR/usr/wlan/
cp $BSP_DIR/userspace/private/apps/wlan/util/nvram_params $ROOTFS_DIR/usr/wlan/
mkdir -p $ROOTFS/usr/share/config/etc/wlan/
cp $BSP_DIR/kernel/linux-3.4rt/extern/target-install/etc/wlan/bcm43602_map.bin $ROOTFS/usr/share/config/etc/wlan/
cp $BSP_DIR/kernel/linux-3.4rt/extern/target-install/etc/wlan/bcm43602_nvramvars.bin $ROOTFS/usr/share/config/etc/wlan/
cp $BSP_DIR/kernel/linux-3.4rt/extern/target-install/etc/wlan/bcmcmn_nvramvars.bin $ROOTFS/usr/share/config/etc/wlan/
cp $BSP_DIR/kernel/linux-3.4rt/extern/target-install/etc/wlan/nvram_params $ROOTFS/usr/share/config/etc/wlan/
#cp $BSP_DIR/kernel/linux-3.4rt/extern/target-install/etc/wlan/bcm43602_map.bin $ROOTFS/etc/wlan/
#cp $BSP_DIR/kernel/linux-3.4rt/extern/target-install/etc/wlan/bcm43602_nvramvars.bin $ROOTFS/etc/wlan/
#cp $BSP_DIR/kernel/linux-3.4rt/extern/target-install/etc/wlan/bcmcmn_nvramvars.bin $ROOTFS/etc/wlan/
#cp $BSP_DIR/kernel/linux-3.4rt/extern/target-install/etc/wlan/nvram_params $ROOTFS/etc/wlan/

# copy dhdctl
cp -f $TARGET_INSTALL_DIR/bin/dhd* $ROOTFS_DIR/usr/sbin/

# Copy xdslctl atmctl to handle GFast or adsl.
mkdir $ROOTFS_DIR/usr/share/config/etc/adsl
cp $BSP_DIR/bcmdrivers/broadcom/char/adsl/impl1/adsl_phy.bin $ROOTFS_DIR/usr/share/config/etc/adsl
cp $BSP_DIR/bcmdrivers/broadcom/char/adsl/impl1/adsl_phy0.bin $ROOTFS_DIR/usr/share/config/etc/adsl

cp $BSP_DIR/userspace/private/apps/atmctl/xtmctl $ROOTFS_DIR/usr/sbin/bcm_atmctl
cp $BSP_DIR/userspace/private/apps/xdslctl/xdslctl $ROOTFS_DIR/usr/sbin/bcm_xdslctl

# Copy dsldiagd for xDSL diagnostic
cp $BSP_DIR/userspace/private/apps/dsldiagd/dsldiagd $ROOTFS_DIR/usr/sbin/dsldiagd
cp $BSP_DIR/userspace/private/apps/mcpd/mcpd $ROOTFS_DIR/usr/sbin/mcpd
cp $BSP_DIR/userspace/private/apps/mcpctl/mcpctl $ROOTFS_DIR/usr/sbin/mcpctl
cp $BSP_DIR/userspace/private/libs/snoopctl/libsnoopctl.so $ROOTFS_DIR/lib/libsnoopctl.so
cp $BSP_DIR/userspace/private/libs/cms_dal/libcms_dal.so $ROOTFS_DIR/lib/libcms_dal.so
cp $BSP_DIR/userspace/private/libs/cms_cli/libcms_cli.so $ROOTFS_DIR/lib/libcms_cli.so

# copy conntrack and libraries
cp -f $BSP_DIR/userspace/gpl/apps/conntrack/conntrack-tools-1.4.1/src/conntrack $ROOTFS_DIR/bin/conntrack
cp -f $BSP_DIR/userspace/gpl/apps/conntrack/conntrack-tools-1.4.1/src/conntrackd $ROOTFS_DIR/bin/conntrackd
cp -f $BSP_DIR/userspace/gpl/libs/nfnetlink/libnfnetlink-1.0.1/src/.libs/libnfnetlink.so $ROOTFS_DIR/lib/libnfnetlink.so
cp -f $BSP_DIR/userspace/gpl/libs/mnl/libmnl-1.0.3/src/.libs/libmnl.so $ROOTFS_DIR/lib/libmnl.so
cp -f $BSP_DIR/userspace/gpl/libs/netfilter_queue/libnetfilter_queue-1.0.2/src/.libs/libnetfilter_queue.so $ROOTFS_DIR/lib/libnetfilter_queue.so
cp -f $BSP_DIR/userspace/gpl/libs/netfilter_cttimeout/libnetfilter_cttimeout-1.0.0/src/.libs/libnetfilter_cttimeout.so $ROOTFS_DIR/lib/libnetfilter_cttimeout.so 
cp -f $BSP_DIR/userspace/gpl/libs/netfilter_cthelper/libnetfilter_cthelper-1.0.0/src/.libs/libnetfilter_cthelper.so $ROOTFS_DIR/lib/libnetfilter_cthelper.so

# delete some unuse file from bsp rootfs
rm -fr $ROOTFS_DIR/usr/share/config/etc/init.d
rm -fr $ROOTFS_DIR/usr/share/config/etc/rc3.d
rm $ROOTFS_DIR/usr/share/config/etc/profile
rm $ROOTFS_DIR/usr/share/config/etc/inittab

# Delete some files temporarily, to reduce the fw size
rm -f $ROOTFS_DIR/bin/httpd

# touch the dns file
rm $ROOTFS_DIR/usr/share/config/etc/resolv.conf
echo "" > $ROOTFS_DIR/usr/share/config/etc/resolv.conf

# copy ebtales/libraries to rootfs
cp -f $TARGET_INSTALL_DIR/bin/ebtables $ROOTFS_DIR/usr/sbin/ebtables
cp -f $TARGET_INSTALL_DIR/lib/gpl/* $ROOTFS_DIR/usr/lib

# copy vlanctl
cp -f $TARGET_INSTALL_DIR/bin/vlanctl $ROOTFS_DIR/usr/sbin/vlanctl

#make /tmp/opt symbolic link
ln -sf /tmp/opt $ROOTFS_DIR/opt
if [ -d $ROOTFS_DIR/mnt ] ;
then
	rm -rf $ROOTFS_DIR/mnt
fi
ln -sf /tmp/mnt $ROOTFS_DIR/mnt
