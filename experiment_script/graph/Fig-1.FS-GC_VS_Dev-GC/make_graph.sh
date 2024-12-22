#!/bin/bash

DEVGC_KIOPS=$(find ./devgc -name "kiops_sum")
FSGC_KIOPS=$(find ./fsgc -name "kiops_sum")

cp "$DEVGC_KIOPS" ./devgc_kiops_raw
cp "$FSGC_KIOPS" ./fsgc_kiops_raw

python3 parser.py devgc_kiops_raw > devgc_kiops
python3 parser.py fsgc_kiops_raw > fsgc_kiops

gnuplot plot.gpi
#python3 parser.py virt_kiops_sum1 > virt_zns_kiops
