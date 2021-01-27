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


EFI_STATUS
EFIAPI
UninitializedMemoryTrackerTestMain(
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
    EFI_GUID DummyGuid =   {0x8BE4DF61, 0x93CA, 0x11d2, {0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0xAA, 0xBB }};
    UINT8 StackBuffer[16]; // Intentionally uninitialized.
    UINTN StackBufferSize = sizeof(StackBuffer);
    UINT32 Attributes = 0;
    EFI_STATUS status = EFI_SUCCESS;
    UINT8 * PoolBuffer = NULL;
    UINTN PoolBufferSize = 20;
    
    // Read a variable into the uninitialized stack buffer.
    // We except 'foo' to be 4 bytes in length, so the stack buffer should now
    // look like this:
    // +-----------------------------------+
    // | x x x x | u u u u u u u u u u u u |
    // +-----------------------------------+
    status = SystemTable->RuntimeServices->GetVariable(L"foo",
                                                       &DummyGuid,
                                                       &Attributes,
                                                       &StackBufferSize,
                                                       StackBuffer);
    if (EFI_ERROR(status) || StackBufferSize != 4) {
        goto Exit;
    }
    
    // Set the next 4 bytes to the value of the first byte.
    // The buffer would now look like this:
    // +-----------------------------------+
    // | x x x x x x x x | u u u u u u u u |
    // +-----------------------------------+
    SystemTable->BootServices->SetMem(StackBuffer + 4, 4, StackBuffer[0]);
    
    // Allocate a pool buffer which is bigger.
    status = SystemTable->BootServices->AllocatePool(EfiLoaderData,
                                                     PoolBufferSize,
                                                     (VOID **)&PoolBuffer);
    if (EFI_ERROR(status)) {
        goto Exit;
    }
    
    // Overwrite the first 4 bytes of the stack buffer with an
    // uninitialized value taken from the pool buffer.
    // The stack buffer would now look like this:
    // +-------------------------------------+
    // | u u u u | x x x x | u u u u u u u u |
    // +-------------------------------------+
    SystemTable->BootServices->SetMem(StackBuffer, 4, PoolBuffer[16]);
    
    // Write some fixed value to the last byte of the buffer.
    // The last byte would become untainted:
    // +---------------------------------------+
    // | u u u u | x x x x | u u u u u u u | x |
    // +---------------------------------------+
    StackBuffer[sizeof(StackBuffer) - 1] = 0xAA;
    
    // Copy the contents of the stack buffer to the middle of the pool buffer.
    // The pool buffer should now look like this:
    // +-------------------------------------------------+
    // | u u u u u u | x x x x | u u u u u u u | x | u u |
    // +-------------------------------------------------+
    SystemTable->BootServices->CopyMem(PoolBuffer + 2, 
                                       StackBuffer,
                                       sizeof(StackBuffer));
    
    // Write the pool buffer back to NVRAM.
    status = SystemTable->RuntimeServices->SetVariable(L"bar",
                                                       &DummyGuid,
                                                       Attributes,
                                                       PoolBufferSize,
                                                       PoolBuffer);
    if (EFI_ERROR(status)) {
        goto Exit;
    }
    
Exit:
    return status;
}