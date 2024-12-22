#!/bin/bash

MG_CMD=$(find ./data -name "migration_command_count")
MG_LOG_MEM=$(find ./data -name "migration_record_memory_footprint")
REG_REGION_UTIL=$(find ./data -name "section_utilization_regular_region")
GC_REGION_UTIL=$(find ./data -name "section_utilization_gc_region")

cp "$MG_CMD" ./
cp "$MG_LOG_MEM" ./
cp "$REG_REGION_UTIL" ./
cp "$GC_REGION_UTIL" ./

python parser.py 2 migration_command_count > migration_command_count_parsed
python parser.py 2 migration_record_memory_footprint > migration_record_memory_footprint_parsed

gnuplot plot_Fig-12.gpi
gnuplot plot_Fig-18.gpi
