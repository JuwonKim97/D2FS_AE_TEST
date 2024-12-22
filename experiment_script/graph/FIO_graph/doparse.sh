#!/bin/bash

python3 parser.py iplfs_kiops_raw > iplfs_kiops
python3 parser.py d2fs_kiops_raw > d2fs_kiops
python3 parser.py zns_kiops_raw > zns_kiops
python3 parser.py f2fs_kiops_raw > f2fs_kiops
