#!/bin/bash

OUTPUT_THROUGHPUT=throughput
OUTPUT_AVG_LAT=avg_lat
OUTPUT_TAIL_LAT=99.95_lat


#===============================================================================================#
# TPC-C Data
D2FS_TPCC=$(find ./d2fs_TPC-C -name "result.txt")
IPLFS_TPCC=$(find ./iplfs_TPC-C -name "result.txt")
ZNS_TPCC=$(find ./zns_TPC-C -name "result.txt")
F2FS_TPCC=$(find ./f2fs_TPC-C -name "result.txt")

# TPC-C Throughput
D2FS_TPCC_THROUGHPUT=$(cat "$D2FS_TPCC"  | grep trx | sed 's/,//g' | awk '{print $3/$1}')
IPLFS_TPCC_THROUGHPUT=$(cat "$IPLFS_TPCC"  | grep trx | sed 's/,//g' | awk '{print $3/$1}')
ZNS_TPCC_THROUGHPUT=$(cat "$ZNS_TPCC"  | grep trx | sed 's/,//g' | awk '{print $3/$1}')
F2FS_TPCC_THROUGHPUT=$(cat "$F2FS_TPCC"  | grep trx | sed 's/,//g' | awk '{print $3/$1}')

# TPC-C Average Latency
D2FS_TPCC_AVG_LAT=$(cat "$D2FS_TPCC"  | awk '/Raw Results2/ {exit} {print}' | grep '\[1\]' | awk '{print $7}')
IPLFS_TPCC_AVG_LAT=$(cat "$IPLFS_TPCC"  | awk '/Raw Results2/ {exit} {print}' | grep '\[1\]' | awk '{print $7}')
ZNS_TPCC_AVG_LAT=$(cat "$ZNS_TPCC"  | awk '/Raw Results2/ {exit} {print}' | grep '\[1\]' | awk '{print $7}')
F2FS_TPCC_AVG_LAT=$(cat "$F2FS_TPCC"  | awk '/Raw Results2/ {exit} {print}' | grep '\[1\]' | awk '{print $7}')

# TPC-C 99.95th Latency
D2FS_TPCC_TAIL_LAT=$(cat "$D2FS_TPCC"  | grep trx | sed 's/,//g' | awk '{print $11}')
IPLFS_TPCC_TAIL_LAT=$(cat "$IPLFS_TPCC"  | grep trx | sed 's/,//g' | awk '{print $11}')
ZNS_TPCC_TAIL_LAT=$(cat "$ZNS_TPCC"  | grep trx | sed 's/,//g' | awk '{print $11}')
F2FS_TPCC_TAIL_LAT=$(cat "$F2FS_TPCC"  | grep trx | sed 's/,//g' | awk '{print $11}')

#===============================================================================================#
# YCSB-A Data
D2FS_YCSBA=$(find ./d2fs_YCSB-A -name "result.txt")
IPLFS_YCSBA=$(find ./iplfs_YCSB-A -name "result.txt")
ZNS_YCSBA=$(find ./zns_YCSB-A -name "result.txt")
F2FS_YCSBA=$(find ./f2fs_YCSB-A -name "result.txt")

# YCSB-A Throughput
D2FS_YCSBA_THROUGHPUT=$(cat "$D2FS_YCSBA"  | grep Throughput | awk '{print $3}')
IPLFS_YCSBA_THROUGHPUT=$(cat "$IPLFS_YCSBA"  | grep Throughput | awk '{print $3}')
ZNS_YCSBA_THROUGHPUT=$(cat "$ZNS_YCSBA"  | grep Throughput | awk '{print $3}')
F2FS_YCSBA_THROUGHPUT=$(cat "$F2FS_YCSBA"  | grep Throughput | awk '{print $3}')

# YCSB-A Average Latency
D2FS_YCSBA_AVG_LAT_UPDATE=$(cat "$D2FS_YCSBA" | grep UPDATE | grep Average | awk '{print $3}')
IPLFS_YCSBA_AVG_LAT_UPDATE=$(cat "$IPLFS_YCSBA" | grep UPDATE | grep Average | awk '{print $3}')
ZNS_YCSBA_AVG_LAT_UPDATE=$(cat "$ZNS_YCSBA" | grep UPDATE | grep Average | awk '{print $3}')
F2FS_YCSBA_AVG_LAT_UPDATE=$(cat "$F2FS_YCSBA" | grep UPDATE | grep Average | awk '{print $3}')

D2FS_YCSBA_AVG_LAT_READ=$(cat "$D2FS_YCSBA" | grep READ | grep Average | awk '{print $3}')
IPLFS_YCSBA_AVG_LAT_READ=$(cat "$IPLFS_YCSBA" | grep READ | grep Average | awk '{print $3}')
ZNS_YCSBA_AVG_LAT_READ=$(cat "$ZNS_YCSBA" | grep READ | grep Average | awk '{print $3}')
F2FS_YCSBA_AVG_LAT_READ=$(cat "$F2FS_YCSBA" | grep READ | grep Average | awk '{print $3}')

# YCSB-A 99.95 Tail Latency
D2FS_YCSBA_TAIL_LAT_UPDATE=$(cat "$D2FS_YCSBA" | grep UPDATE | grep 99.95 | awk '{print $3}')
IPLFS_YCSBA_TAIL_LAT_UPDATE=$(cat "$IPLFS_YCSBA" | grep UPDATE | grep 99.95 | awk '{print $3}')
ZNS_YCSBA_TAIL_LAT_UPDATE=$(cat "$ZNS_YCSBA" | grep UPDATE | grep 99.95 | awk '{print $3}')
F2FS_YCSBA_TAIL_LAT_UPDATE=$(cat "$F2FS_YCSBA" | grep UPDATE | grep 99.95 | awk '{print $3}')

D2FS_YCSBA_TAIL_LAT_READ=$(cat "$D2FS_YCSBA" | grep READ | grep 99.95 | awk '{print $3}')
IPLFS_YCSBA_TAIL_LAT_READ=$(cat "$IPLFS_YCSBA" | grep READ | grep 99.95 | awk '{print $3}')
ZNS_YCSBA_TAIL_LAT_READ=$(cat "$ZNS_YCSBA" | grep READ | grep 99.95 | awk '{print $3}')
F2FS_YCSBA_TAIL_LAT_READ=$(cat "$F2FS_YCSBA" | grep READ | grep 99.95 | awk '{print $3}')

#===============================================================================================#
# YCSB-F Data
D2FS_YCSBF=$(find ./d2fs_YCSB-F -name "result.txt")
IPLFS_YCSBF=$(find ./iplfs_YCSB-F -name "result.txt")
ZNS_YCSBF=$(find ./zns_YCSB-F -name "result.txt")
F2FS_YCSBF=$(find ./f2fs_YCSB-F -name "result.txt")

# YCSB-F Throughput
D2FS_YCSBF_THROUGHPUT=$(cat "$D2FS_YCSBF"  | grep Throughput | awk '{print $3}')
IPLFS_YCSBF_THROUGHPUT=$(cat "$IPLFS_YCSBF"  | grep Throughput | awk '{print $3}')
ZNS_YCSBF_THROUGHPUT=$(cat "$ZNS_YCSBF"  | grep Throughput | awk '{print $3}')
F2FS_YCSBF_THROUGHPUT=$(cat "$F2FS_YCSBF"  | grep Throughput | awk '{print $3}')

# YCSB-F Average Latency
D2FS_YCSBF_AVG_LAT_UPDATE=$(cat "$D2FS_YCSBF" | grep UPDATE | grep Average | awk '{print $3}')
IPLFS_YCSBF_AVG_LAT_UPDATE=$(cat "$IPLFS_YCSBF" | grep UPDATE | grep Average | awk '{print $3}')
ZNS_YCSBF_AVG_LAT_UPDATE=$(cat "$ZNS_YCSBF" | grep UPDATE | grep Average | awk '{print $3}')
F2FS_YCSBF_AVG_LAT_UPDATE=$(cat "$F2FS_YCSBF" | grep UPDATE | grep Average | awk '{print $3}')

D2FS_YCSBF_AVG_LAT_READ=$(cat "$D2FS_YCSBF" | grep READ | grep Average | awk '{print $3}')
IPLFS_YCSBF_AVG_LAT_READ=$(cat "$IPLFS_YCSBF" | grep READ | grep Average | awk '{print $3}')
ZNS_YCSBF_AVG_LAT_READ=$(cat "$ZNS_YCSBF" | grep READ | grep Average | awk '{print $3}')
F2FS_YCSBF_AVG_LAT_READ=$(cat "$F2FS_YCSBF" | grep READ | grep Average | awk '{print $3}')

# YCSB-F 99.95 Tail Latency
D2FS_YCSBF_TAIL_LAT_UPDATE=$(cat "$D2FS_YCSBF" | grep UPDATE | grep 99.95 | awk '{print $3}')
IPLFS_YCSBF_TAIL_LAT_UPDATE=$(cat "$IPLFS_YCSBF" | grep UPDATE | grep 99.95 | awk '{print $3}')
ZNS_YCSBF_TAIL_LAT_UPDATE=$(cat "$ZNS_YCSBF" | grep UPDATE | grep 99.95 | awk '{print $3}')
F2FS_YCSBF_TAIL_LAT_UPDATE=$(cat "$F2FS_YCSBF" | grep UPDATE | grep 99.95 | awk '{print $3}')

D2FS_YCSBF_TAIL_LAT_READ=$(cat "$D2FS_YCSBF" | grep READ | grep 99.95 | awk '{print $3}')
IPLFS_YCSBF_TAIL_LAT_READ=$(cat "$IPLFS_YCSBF" | grep READ | grep 99.95 | awk '{print $3}')
ZNS_YCSBF_TAIL_LAT_READ=$(cat "$ZNS_YCSBF" | grep READ | grep 99.95 | awk '{print $3}')
F2FS_YCSBF_TAIL_LAT_READ=$(cat "$F2FS_YCSBF" | grep READ | grep 99.95 | awk '{print $3}')

#===============================================================================================#
# Fileserver Data
D2FS_FILESERVER=$(find ./d2fs_Fileserver -name "result.txt")
IPLFS_FILESERVER=$(find ./iplfs_Fileserver -name "result.txt")
ZNS_FILESERVER=$(find ./zns_Fileserver -name "result.txt")
F2FS_FILESERVER=$(find ./f2fs_Fileserver -name "result.txt")

# Fileserver Throughput
D2FS_FILESERVER_THROUGHPUT=$(cat "$D2FS_FILESERVER"  | grep Summary | awk '{print $6}')
IPLFS_FILESERVER_THROUGHPUT=$(cat "$IPLFS_FILESERVER"  | grep Summary | awk '{print $6}')
ZNS_FILESERVER_THROUGHPUT=$(cat "$ZNS_FILESERVER"  | grep Summary | awk '{print $6}')
F2FS_FILESERVER_THROUGHPUT=$(cat "$F2FS_FILESERVER"  | grep Summary | awk '{print $6}')

# Fileserver Average Latency
D2FS_FILESERVER_AVG_LAT=$(cat "$D2FS_FILESERVER"  | grep wrtfile | sed 's/ms/ /g' | awk '{print $5}')
IPLFS_FILESERVER_AVG_LAT=$(cat "$IPLFS_FILESERVER"  | grep wrtfile | sed 's/ms/ /g' | awk '{print $5}')
ZNS_FILESERVER_AVG_LAT=$(cat "$ZNS_FILESERVER"  | grep wrtfile | sed 's/ms/ /g' | awk '{print $5}')
F2FS_FILESERVER_AVG_LAT=$(cat "$F2FS_FILESERVER"  | grep wrtfile | sed 's/ms/ /g' | awk '{print $5}')

# Fileserver 99.95th Latency
D2FS_FILESERVER_TAIL_LAT=$(cat "$D2FS_FILESERVER"  | grep wrtfile | awk '{print $21}')
IPLFS_FILESERVER_TAIL_LAT=$(cat "$IPLFS_FILESERVER"  | grep wrtfile | awk '{print $21}')
ZNS_FILESERVER_TAIL_LAT=$(cat "$ZNS_FILESERVER"  | grep wrtfile | awk '{print $21}')
F2FS_FILESERVER_TAIL_LAT=$(cat "$F2FS_FILESERVER"  | grep wrtfile | awk '{print $21}')


#===============================================================================================#
# Plot Throughput Graph

echo -e "#throughput" > $OUTPUT_THROUGHPUT
echo -e "Xsteps\tIPLFS\tD2FS\tzF2FS\tF2FS" >> $OUTPUT_THROUGHPUT
echo -e "TPC-C\\\n(Tx/sec)\t${IPLFS_TPCC_THROUGHPUT}\t${D2FS_TPCC_THROUGHPUT}\t${ZNS_TPCC_THROUGHPUT}\t${F2FS_TPCC_THROUGHPUT}" >> $OUTPUT_THROUGHPUT
echo -e "YCSB-A\\\n(KOPS)\t${IPLFS_YCSBA_THROUGHPUT}\t${D2FS_YCSBA_THROUGHPUT}\t${ZNS_YCSBA_THROUGHPUT}\t${F2FS_YCSBA_THROUGHPUT}" >> $OUTPUT_THROUGHPUT
echo -e "YCSB-F\\\n(KOPS)\t${IPLFS_YCSBF_THROUGHPUT}\t${D2FS_YCSBF_THROUGHPUT}\t${ZNS_YCSBF_THROUGHPUT}\t${F2FS_YCSBF_THROUGHPUT}" >> $OUTPUT_THROUGHPUT
echo -e "Fileserver\\\n(KOPS)\t${IPLFS_FILESERVER_THROUGHPUT}\t${D2FS_FILESERVER_THROUGHPUT}\t${ZNS_FILESERVER_THROUGHPUT}\t${F2FS_FILESERVER_THROUGHPUT}" >> $OUTPUT_THROUGHPUT

gnuplot plot_Fig-14.Macrobenchmark_throughput.gpi

#===============================================================================================#
# Plot Average Latency Graph

echo -e "Xsteps\tIPLFS\tD2FS\tzF2FS\tF2FS" > $OUTPUT_AVG_LAT
echo -e "TPC-C\t${IPLFS_TPCC_AVG_LAT}\t${D2FS_TPCC_AVG_LAT}\t${ZNS_TPCC_AVG_LAT}\t${F2FS_TPCC_AVG_LAT}" >> $OUTPUT_AVG_LAT
echo -e "YCSB-A\t${IPLFS_YCSBA_AVG_LAT_UPDATE}\t${D2FS_YCSBA_AVG_LAT_UPDATE}\t${ZNS_YCSBA_AVG_LAT_UPDATE}\t${F2FS_YCSBA_AVG_LAT_UPDATE}\t#update (msec)" >> $OUTPUT_AVG_LAT
echo -e "YCSB-F\t${IPLFS_YCSBF_AVG_LAT_UPDATE}\t${D2FS_YCSBF_AVG_LAT_UPDATE}\t${ZNS_YCSBF_AVG_LAT_UPDATE}\t${F2FS_YCSBF_AVG_LAT_UPDATE}\t#update (msec)" >> $OUTPUT_AVG_LAT
echo -e "YCSB-A\t${IPLFS_YCSBA_AVG_LAT_READ}\t${D2FS_YCSBA_AVG_LAT_READ}\t${ZNS_YCSBA_AVG_LAT_READ}\t${F2FS_YCSBA_AVG_LAT_READ}\t#read (msec)" >> $OUTPUT_AVG_LAT
echo -e "YCSB-F\t${IPLFS_YCSBF_AVG_LAT_READ}\t${D2FS_YCSBF_AVG_LAT_READ}\t${ZNS_YCSBF_AVG_LAT_READ}\t${F2FS_YCSBF_AVG_LAT_READ}\t#read (msec)" >> $OUTPUT_AVG_LAT
echo -e "Fileserver\t${IPLFS_FILESERVER_AVG_LAT}\t${D2FS_FILESERVER_AVG_LAT}\t${ZNS_FILESERVER_AVG_LAT}\t${F2FS_FILESERVER_AVG_LAT}\t#wrtfile (msec)" >> $OUTPUT_AVG_LAT

gnuplot plot_Fig-16-a.Macrobenchmark_avg_latency.gpi

# Plot 99.95th Latency Graph
echo -e "Xsteps\tIPLFS\tD2FS\tzF2FS\tF2FS" > $OUTPUT_TAIL_LAT
echo -e "TPC-C\t${IPLFS_TPCC_TAIL_LAT}\t${D2FS_TPCC_TAIL_LAT}\t${ZNS_TPCC_TAIL_LAT}\t${F2FS_TPCC_TAIL_LAT}\t# (sec)" >> $OUTPUT_TAIL_LAT
echo -e "YCSB-A\t${IPLFS_YCSBA_TAIL_LAT_UPDATE}\t${D2FS_YCSBA_TAIL_LAT_UPDATE}\t${ZNS_YCSBA_TAIL_LAT_UPDATE}\t${F2FS_YCSBA_TAIL_LAT_UPDATE}\t#update (msec)" >> $OUTPUT_TAIL_LAT
echo -e "YCSB-F\t${IPLFS_YCSBF_TAIL_LAT_UPDATE}\t${D2FS_YCSBF_TAIL_LAT_UPDATE}\t${ZNS_YCSBF_TAIL_LAT_UPDATE}\t${F2FS_YCSBF_TAIL_LAT_UPDATE}\t#update (msec)" >> $OUTPUT_TAIL_LAT
echo -e "YCSB-A\t${IPLFS_YCSBA_TAIL_LAT_READ}\t${D2FS_YCSBA_TAIL_LAT_READ}\t${ZNS_YCSBA_TAIL_LAT_READ}\t${F2FS_YCSBA_TAIL_LAT_READ}\t#read (msec)" >> $OUTPUT_TAIL_LAT
echo -e "YCSB-F\t${IPLFS_YCSBF_TAIL_LAT_READ}\t${D2FS_YCSBF_TAIL_LAT_READ}\t${ZNS_YCSBF_TAIL_LAT_READ}\t${F2FS_YCSBF_TAIL_LAT_READ}\t#read (msec)" >> $OUTPUT_TAIL_LAT
echo -e "Fileserver\t${IPLFS_FILESERVER_TAIL_LAT}\t${D2FS_FILESERVER_TAIL_LAT}\t${ZNS_FILESERVER_TAIL_LAT}\t${F2FS_FILESERVER_TAIL_LAT}\t#wrtfile (msec)" >> $OUTPUT_TAIL_LAT

gnuplot plot_Fig-16-b.Macrobenchmark_tail_latency.gpi

