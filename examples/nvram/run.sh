#!/bin/bash

rm -rf afl_outputs
afl-fuzz -i afl_inputs -o afl_outputs -U -- \
python ../../efi_fuzz.py fuzz PlatformInitDxe.efi -x S3SaveStateDxe.efi -j PlatformInitDxe.json nvram SetupVolatileData @@