#!/bin/bash

python ../../efi_fuzz.py run ./SystemSmmAhciAspiLegacyRt.efi -x ./PiSaveStateAccess.efi ./SystemSwSmiAllocatorSmm.efi ./SystemSwSmiAllocatorDxe.efi -j SystemSmmAhciAspiLegacyRt.json -f stop