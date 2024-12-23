#!/bin/bash

OUTPUT=gc_latency_breakdown_data

echo -e "#\tDread\tDwrite\tCP\tMeta\tFilemap\tCache\tHread\tHwrite" > $OUTPUT

D2FS_FIO=$(find ./d2fs_FIO -name "GC_latency_breakdown")
D2FS_TPCC=$(find ./d2fs_TPC-C -name "GC_latency_breakdown")
D2FS_YCSBA=$(find ./d2fs_YCSB-A -name "GC_latency_breakdown")
D2FS_YCSBF=$(find ./d2fs_YCSB-F -name "GC_latency_breakdown")
D2FS_FILESERVER=$(find ./d2fs_Fileserver -name "GC_latency_breakdown")

ZNS_FIO=$(find ./zns_FIO -name "GC_latency_breakdown")
ZNS_TPCC=$(find ./zns_TPC-C -name "GC_latency_breakdown")
ZNS_YCSBA=$(find ./zns_YCSB-A -name "GC_latency_breakdown")
ZNS_YCSBF=$(find ./zns_YCSB-F -name "GC_latency_breakdown")
ZNS_FILESERVER=$(find ./zns_Fileserver -name "GC_latency_breakdown")

# FIO GC Latency Breakdown
D2FS_FIO_READ=$(tail -n 1 "$D2FS_FIO" | awk '{print $3}')
D2FS_FIO_WRITE=$(tail -n 1 "$D2FS_FIO" | awk '{print $4}')

ZNS_FIO_CP=$(tail -n 1 "$ZNS_FIO" | awk '{print $3}')
ZNS_FIO_META=$(tail -n 1 "$ZNS_FIO" | awk '{print $4}')
ZNS_FIO_FILEMAP=$(tail -n 1 "$ZNS_FIO" | awk '{print $5}')
ZNS_FIO_CACHE=$(tail -n 1 "$ZNS_FIO" | awk '{print $6}')
ZNS_FIO_READ=$(tail -n 1 "$ZNS_FIO" | awk '{print $7}')
ZNS_FIO_WRITE=$(tail -n 1 "$ZNS_FIO" | awk '{print $8}')

echo "#fio" >> $OUTPUT
echo -e "D\t${D2FS_FIO_READ}\t${D2FS_FIO_WRITE}\t0\t0\t0\t0\t0\t0" >> $OUTPUT
echo -e "Z\t0\t0\t${ZNS_FIO_CP}\t${ZNS_FIO_META}\t${ZNS_FIO_FILEMAP}\t${ZNS_FIO_CACHE}\t${ZNS_FIO_READ}\t${ZNS_FIO_WRITE}" >> $OUTPUT


# TPC-C GC Latency Breakdown
D2FS_TPCC_READ=$(tail -n 1 "$D2FS_TPCC" | awk '{print $3}')
D2FS_TPCC_WRITE=$(tail -n 1 "$D2FS_TPCC" | awk '{print $4}')

ZNS_TPCC_CP=$(tail -n 1 "$ZNS_TPCC" | awk '{print $3}')
ZNS_TPCC_META=$(tail -n 1 "$ZNS_TPCC" | awk '{print $4}')
ZNS_TPCC_FILEMAP=$(tail -n 1 "$ZNS_TPCC" | awk '{print $5}')
ZNS_TPCC_CACHE=$(tail -n 1 "$ZNS_TPCC" | awk '{print $6}')
ZNS_TPCC_READ=$(tail -n 1 "$ZNS_TPCC" | awk '{print $7}')
ZNS_TPCC_WRITE=$(tail -n 1 "$ZNS_TPCC" | awk '{print $8}')

echo "#TPC-C" >> $OUTPUT
echo -e "D\t${D2FS_TPCC_READ}\t${D2FS_TPCC_WRITE}\t0\t0\t0\t0\t0\t0" >> $OUTPUT
echo -e "Z\t0\t0\t${ZNS_TPCC_CP}\t${ZNS_TPCC_META}\t${ZNS_TPCC_FILEMAP}\t${ZNS_TPCC_CACHE}\t${ZNS_TPCC_READ}\t${ZNS_TPCC_WRITE}" >> $OUTPUT


#python3 parser.py devgc_kiops_raw > devgc_kiops
#python3 parser.py fsgc_kiops_raw > fsgc_kiops

#gnuplot plot.gpi
