#pragma optimize("", off)

EFI_GUID DummyGuid =   {0x8BE4DF61, 0x93CA, 0x11d2, {0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0xAA, 0xBB }};

typedef enum _FAULT_TYPE_T
{
    // Triggers an overflow from BS->CopyMem()
    POOL_OVERFLOW_COPY_MEM = 1,
    // Triggers an underflow from BS->CopyMem()
    POOL_UNDERFLOW_COPY_MEM = 2,
    // Triggers an overflow from BS->SetMem()
    POOL_OVERFLOW_SET_MEM = 3,
    // Triggers an underflow from BS->SetMem()
    POOL_UNDERFLOW_SET_MEM = 4,
    // Triggers an overflow from user code
    POOL_OVERFLOW_USER_CODE = 5,
    // Triggers an underflow from user code
    POOL_UNDERFLOW_USER_CODE = 6,
    // Triggers an out-of-bounds read ahead of the buffer
    POOL_OOB_READ_AHEAD = 7,
    // Triggers an out-of-bounds read behind the buffer
    POOL_OOB_READ_BEHIND = 8,
    // Frees the same pool block twice in a row
    POOL_DOUBLE_FREE = 9,
    // Frees a pointer which wasn't allocated by BS->AllocatePool()
    POOL_INVALID_FREE = 10,
    // Reads from the buffer after it was freed
    POOL_UAF_READ = 11,
    // Writes to the buffer after it was freed
    POOL_UAF_WRITE = 12,
    // Writes to the NULL page
    NULL_DEREFERENCE_DETERMINISTIC = 13,
    // Allocates a buffer with BS->AllocatePool(), then uses it without checking for NULL first
    NULL_DEREFERENCE_NON_DETERMINISTIC = 14,
    // Stack-based buffer overflow
    STACK_BUFFER_OVERFLOW = 15
} FAULT_TYPE_T;

// A hand-rolled implementation for memset()
VOID MySetMem(IN VOID *Buffer, IN UINTN Size, IN UINT8 Value)
{
    UINTN i;
    UINT8 * OutputBuffer = (UINT8 *)Buffer;
    for (i = 0; i < Size; i++) {
        OutputBuffer[i] = Value;
    }
}


EFI_STATUS
EFIAPI
_ModuleEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
    UINT32 FaultType = 0;
    UINTN DataSize = sizeof(FaultType);
    UINT32 Attributes = 0;
    UINT8 * Buffer = NULL;
    UINTN BufferSize = 8;
    EFI_STATUS status = EFI_SUCCESS;
    
    // Allocate the vulnerable pool buffer.
    status = SystemTable->BootServices->AllocatePool(EfiLoaderData,
                                                     BufferSize,
                                                     &Buffer);
    if (EFI_ERROR(status)) {
        goto Exit;
    }
  
    // Get the contents of the 'FaultType' variable.
    status = SystemTable->RuntimeServices->GetVariable(L"FaultType",
                                                       &DummyGuid,
                                                       &Attributes,
                                                       &DataSize,
                                                       &FaultType);
    if (EFI_ERROR(status)) {
        goto Exit;
    }

    // Carry-out the selected fault.
    switch (FaultType)
    {
    case POOL_OVERFLOW_COPY_MEM:
        SystemTable->BootServices->CopyMem(Buffer, &DummyGuid, BufferSize + 1);
        break;
        
    case POOL_UNDERFLOW_COPY_MEM:
        SystemTable->BootServices->CopyMem(Buffer - 1, &DummyGuid, BufferSize);
        break;
        
    case POOL_OVERFLOW_SET_MEM:
        SystemTable->BootServices->SetMem(Buffer, BufferSize + 1, 0xAA);
        break;

    case POOL_UNDERFLOW_SET_MEM:
        SystemTable->BootServices->SetMem(Buffer - 1, BufferSize, 0xAA);
        break;

    case POOL_OVERFLOW_USER_CODE:
        MySetMem(Buffer, BufferSize + 1, 0xAA);
        break;

    case POOL_UNDERFLOW_USER_CODE:
        MySetMem(Buffer - 1, BufferSize, 0xAA);
        break;

    case POOL_OOB_READ_AHEAD:
        status = *(Buffer + BufferSize);
        break;

    case POOL_OOB_READ_BEHIND:
        status = *(Buffer - 1);
        break;

    case POOL_DOUBLE_FREE:
        SystemTable->BootServices->FreePool(Buffer);
        SystemTable->BootServices->FreePool(Buffer);
        break;

    case POOL_INVALID_FREE:
        SystemTable->BootServices->FreePool(Buffer + 1);
        break;
    
    case POOL_UAF_READ:
        SystemTable->BootServices->FreePool(Buffer);
        status = Buffer[2];
        break;
        
    case POOL_UAF_WRITE:
        SystemTable->BootServices->FreePool(Buffer);
        Buffer[2] = 0xAA;
        break;
        
    case NULL_DEREFERENCE_DETERMINISTIC:
        *(UINT8 *)NULL = 0xAA;
        break;

    case NULL_DEREFERENCE_NON_DETERMINISTIC:
        UINT8 * MaybeNull = NULL;
        SystemTable->BootServices->AllocatePool(EfiLoaderData,
                                                BufferSize,
                                                &MaybeNull);
        // We're not checking for the return value from AllocatePool()
        *MaybeNull = 0xAA;
        SystemTable->BootServices->FreePool(MaybeNull);
        break;
        
    case STACK_BUFFER_OVERFLOW:
        SystemTable->BootServices->SetMem(&Buffer, 0x100, 0xAA);
        break;

    default:
        break;
  }

Exit:
  return status;
}