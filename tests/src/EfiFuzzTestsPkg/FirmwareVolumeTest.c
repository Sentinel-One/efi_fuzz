/**
 * A small UEFI application to test our implementation of EFI_FIRMWARE_VOLUME2_PROTOCOL.
 */

#ifdef _MSC_VER
#pragma optimize("", off)
#endif

#include <Pi/PiFirmwareFile.h>
#include <Pi/PiFirmwareVolume.h>
#include <Protocol/FirmwareVolume2.h>


EFI_STATUS
EFIAPI
FirmwareVolumeTestMain(
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
    EFI_GUID FirmwareVolume2ProtocolGuid = EFI_FIRMWARE_VOLUME2_PROTOCOL_GUID;
    EFI_FIRMWARE_VOLUME2_PROTOCOL * FirmwareVolume2Interface = NULL;
    EFI_STATUS status = EFI_SUCCESS;
    VOID * Buffer = NULL;
    UINTN BufferSize = 0;
    
    status = SystemTable->BootServices->LocateProtocol(
        &FirmwareVolume2ProtocolGuid,
        NULL,
        (VOID **)&FirmwareVolume2Interface);
        
    if (EFI_ERROR(status)) {
        goto Exit;
    }
    // {3A0CA891-9BA9-4123-A54A- B7 40 96 BD DB B9}
    const EFI_GUID FileName = 
    { 0x35b898ca, 0xb6a9, 0x49ce, { 0x8c, 0x72, 0x90, 0x47, 0x35, 0xcc, 0x49, 0xb7 } };
    
    status = FirmwareVolume2Interface->ReadSection(
        FirmwareVolume2Interface,
        &FileName,
        EFI_SECTION_USER_INTERFACE,
        0,
        (VOID **)&Buffer,
        &BufferSize,
        NULL);
        
    if (EFI_ERROR(status)) {
        goto Exit;
    }
    
Exit:
    return status;
}