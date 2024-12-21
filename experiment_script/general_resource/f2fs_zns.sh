#!/bin/bash
BENCHMARK_DIR=/mnt
DEV_partition=/dev/nvme3n1p1
DEV_whole=/dev/nvme3n1
#DEV_partition=/dev/nvme0n1p1
#DEV_whole=/dev/nvme0n1

sudo rm $BENCHMARK_DIR/* -rf
sudo umount $DEV_partition\

sudo rmmod f2fs
sudo insmod ./filesystem_module/$1.ko;

#section size: 1 GByte
#sudo mkfs.f2fs -s 512 -f $DEV_partition;\

#section size: 32 MByte
sudo mkfs.f2fs -s 16 -f $DEV_partition;\



#sudo mkfs.f2fs -f -z 2 $DEV_partition;\
#sudo /usr/src/linux-5.11/f2fs-tools/mkfs/mkfs.f2fs -f $DEV_partition;\
#sudo mount -t f2fs -o discard $DEV_partition $BENCHMARK_DIR;\
#sudo mount -t f2fs -o mode=lfs $DEV_partition $BENCHMARK_DIR;\
sudo mount -t f2fs -o mode=lfs -o discard $DEV_partition $BENCHMARK_DIR;\
#sudo mount -t f2fs $DEV_partition $BENCHMARK_DIR;\

