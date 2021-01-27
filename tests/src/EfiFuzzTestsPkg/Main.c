/**
 * A small UEFI application to test taint propagation of uninitialized memory.
 * When drawing the buffers, 'x' will be used to denote an initialized byte,
 * whereas 'u' will be used to denote an uninitialized byte.
 *
 * For example:
 * +-----------+
 * | x | u u u |
 * +-----------+
 *
 * represents a buffer with one initialized byte and 3 uninitialized bytes.
 */

#ifdef _MSC_VER
#pragma optimize("", off)
#endif

#include <Library/BaseLib.h>


EFI_STATUS
EFIAPI
UninitializedMemoryTrackerTestMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );
  
EFI_STATUS
EFIAPI
FirmwareVolumeTestMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  );

EFI_STATUS
EFIAPI
_ModuleEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
    EFI_GUID DummyGuid =   {0x8BE4DF61, 0x93CA, 0x11d2, {0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0xAA, 0xBB }};
    UINT32 Attributes = 0;
    EFI_STATUS status = EFI_SUCCESS;
    CHAR8 * TestName = NULL;
    UINTN NeededSize = 0;
    
    SystemTable->RuntimeServices->GetVariable(L"TestName",
                                              &DummyGuid,
                                              &Attributes,
                                              &NeededSize,
                                              NULL);
    
    // Allocate a pool buffer which is bigger.
    status = SystemTable->BootServices->AllocatePool(EfiLoaderData,
                                                     NeededSize,
                                                     (VOID **)&TestName);
    if (EFI_ERROR(status)) {
        goto Exit;
    }
    
    SystemTable->RuntimeServices->GetVariable(L"TestName",
                                              &DummyGuid,
                                              &Attributes,
                                              &NeededSize,
                                              TestName);
    
    if (AsciiStrCmp(TestName, "UninitializedMemoryTracker") == 0) {
        status = UninitializedMemoryTrackerTestMain(ImageHandle, SystemTable);
    } else if (AsciiStrCmp(TestName, "FirmwareVolume") == 0) {
        status = FirmwareVolumeTestMain(ImageHandle, SystemTable);
    } else {
        status = EFI_INVALID_PARAMETER;
    }
    
    
Exit:
    if (TestName) {
        SystemTable->BootServices->FreePool(TestName);
    }
        
    return status;
}