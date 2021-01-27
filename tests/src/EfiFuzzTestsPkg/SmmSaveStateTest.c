/**
 * A small UEFI application to test our implementation of EFI_FIRMWARE_VOLUME2_PROTOCOL.
 */

#ifdef _MSC_VER
#pragma optimize("", off)
#endif

#include <Protocol/SmmBase2.h>
#include <Protocol/SmmCpu.h>
#include <Protocol/SmmSwDispatch2.h>

#include "SmmUtils.h"

EFI_STATUS EFIAPI TestSaveStateSmiHandler(
    IN EFI_HANDLE   DispatchHandle,
    IN CONST VOID   *Context            OPTIONAL,
    IN OUT VOID     *CommBuffer         OPTIONAL,
    IN OUT UINTN    *CommBufferSize     OPTIONAL
)
{
    EFI_GUID SmmCpuProtoclGuid = EFI_SMM_CPU_PROTOCOL_GUID;
    EFI_SMM_CPU_PROTOCOL * SmmCpuInterface = NULL;
    EFI_STATUS status = EFI_SUCCESS;
    
    status = g_Smst->SmmLocateProtocol(&SmmCpuProtoclGuid, NULL, (void **)&SmmCpuInterface);
    if (EFI_ERROR(status)) {
        goto Exit;
    }
    
    UINTN SavedRax = 0;
    status = SmmCpuInterface->ReadSaveState(
        SmmCpuInterface, 4, EFI_SMM_SAVE_STATE_REGISTER_RAX, 0, &SavedRax);
    if (EFI_ERROR(status)) {
        goto Exit;
    }
    
Exit:
    return status;
}

EFI_STATUS
EFIAPI
SmmSaveStateTestMain(
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
    EFI_GUID SmmSwDispatch2ProtocolGuid = EFI_SMM_SW_DISPATCH2_PROTOCOL_GUID;
    EFI_SMM_SW_DISPATCH2_PROTOCOL * SmmSwDispatch2Interface = NULL;
    EFI_STATUS status = EFI_SUCCESS;
    
    
    SmmSwDispatch2Interface = LocateSmmProtocol(SystemTable, &SmmSwDispatch2ProtocolGuid);
    if (!SmmSwDispatch2Interface) {
        goto Exit;
    }
    
    EFI_SMM_SW_REGISTER_CONTEXT RegisterContext = {0};
    RegisterContext.SwSmiInputValue = 0x9F; // Just a random integer in the range 0-255
    
    EFI_HANDLE DispatchHandle = NULL;
    status = SmmSwDispatch2Interface->Register(
        SmmSwDispatch2Interface,
        &TestSaveStateSmiHandler,
        &RegisterContext,
        &DispatchHandle);
        
    if (EFI_ERROR(status)) {
        goto Exit;
    }
    
Exit:
    return status;
}