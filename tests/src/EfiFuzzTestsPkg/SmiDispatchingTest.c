/**
 * A small UEFI application to test our implementation of EFI_FIRMWARE_VOLUME2_PROTOCOL.
 */

#ifdef _MSC_VER
#pragma optimize("", off)
#endif

#include <Protocol/SmmBase2.h>
#include <Protocol/SmmSwDispatch2.h>

EFI_STATUS EFIAPI MySmiHandler(
    IN EFI_HANDLE   DispatchHandle,
    IN CONST VOID   *Context            OPTIONAL,
    IN OUT VOID     *CommBuffer         OPTIONAL,
    IN OUT UINTN    *CommBufferSize     OPTIONAL
)
{
    return EFI_SUCCESS;
}

VOID * SmmLocateProtocol(IN EFI_SYSTEM_TABLE  *SystemTable, IN EFI_GUID * ProtocolGuid)
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
    EFI_SMM_SYSTEM_TABLE2 * Smst = NULL;
    status = SmmBase2Interface->GetSmstLocation(SmmBase2Interface, &Smst);
    
    if (EFI_ERROR(status)) {
        goto Exit;
    }
    
    // Locate desired SMM protocol
    status = Smst->SmmLocateProtocol(ProtocolGuid, NULL, &Interface);
    
    if (EFI_ERROR(status)) {
        goto Exit;
    }
    
Exit:
    return Interface;
}

EFI_STATUS
EFIAPI
SmiDispatchingTestMain(
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
    EFI_GUID SmmSwDispatch2ProtocolGuid = EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID;
    EFI_SMM_SW_DISPATCH2_PROTOCOL * SmmSwDispatch2Interface = NULL;
    EFI_STATUS status = EFI_SUCCESS;
    
    
    SmmSwDispatch2Interface = SmmLocateProtocol(SystemTable, &SmmSwDispatch2ProtocolGuid);
    if (!SmmSwDispatch2Interface) {
        goto Exit;
    }
    
    EFI_SMM_SW_REGISTER_CONTEXT RegisterContext = {0};
    RegisterContext.SwSmiInputValue = 0x9F; // Just a random integer in the range 0-255
    
    EFI_HANDLE DispatchHandle = NULL;
    status = SmmSwDispatch2Interface->Register(
        SmmSwDispatch2Interface,
        &MySmiHandler,
        &RegisterContext,
        &DispatchHandle);
        
    if (EFI_ERROR(status)) {
        goto Exit;
    }
    
Exit:
    return status;
}