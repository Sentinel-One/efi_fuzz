#pragma once

#include <Protocol/SmmBase2.h>

VOID * LocateSmmProtocol(IN EFI_SYSTEM_TABLE  *SystemTable, IN EFI_GUID * ProtocolGuid);

extern EFI_SMM_SYSTEM_TABLE2 * g_Smst;