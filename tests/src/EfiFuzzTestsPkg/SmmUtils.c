
#ifdef _MSC_VER
#pragma optimize("", off)
#endif

#include "SmmUtils.h"
#include <Protocol/SmmBase2.h>

EFI_SMM_SYSTEM_TABLE2 * g_Smst = NULL;

VOID * LocateSmmProtocol(IN EFI_SYSTEM_TABLE  *SystemTable, IN EFI_GUID * ProtocolGuid)
{
    EFI_GUID SmmBase2Protocol = EFI_SMM_BASE2_PROTOCOL_GUID;
    EFI_SMM_BASE2_PROTOCOL * SmmBase2Interface = NULL;
    VOID * Interface = NULL;
    EFI_STATUS status = EFI_SUCCESS;
    
    // Get SMM_BASE2_PROTOCOL
    status = SystemTable->BootServices->LocateProtocol(
        &SmmBase2Protocol,
        NULL,
        (VOID **)&SmmBase2Interface);
        
    if (EFI_ERROR(status)) {
        goto Exit;
    }
    
    // Get SMST
    status = SmmBase2Interface->GetSmstLocation(SmmBase2Interface, &g_Smst);
    
    if (EFI_ERROR(status)) {
        goto Exit;
    }
    
    // Locate desired SMM protocol
    status = g_Smst->SmmLocateProtocol(ProtocolGuid, NULL, &Interface);
    
    if (EFI_ERROR(status)) {
        goto Exit;
    }
    
Exit:
    return Interface;
}
