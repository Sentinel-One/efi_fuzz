# efi_fuzz tests

# Running
1. Make sure `pytest` and `mockito` are installed: `pip3 install -U pytest mockito`
2. Run the tests: `cd tests; pytest -s -v`

If everything is successful, output should look somewhat like this:
```
=============================================================================== test session starts ===============================================================================
platform linux -- Python 3.8.2, pytest-6.1.1, py-1.9.0, pluggy-0.13.1 -- /usr/bin/python3
cachedir: .pytest_cache
rootdir: /mnt/c/Users/Assaf/Work/efi_fuzz/tests
collected 1 item

test_efi_fuzz.py::test_uninitialized_memory_tracker [+] Initiate stack address at 0x7ffffffde000
[+] Loading ./bin/UninitializedMemoryTrackerTest.efi to 0x10000
[+] PE entry point at 0x10240
[+] Done with loading ./bin/UninitializedMemoryTrackerTest.efi
[+] Running from 0x10240 of ./bin/UninitializedMemoryTrackerTest.efi
Tainting range 0x80000001cf80-0x80000001cfe8
Untainting range 0x80000001cfd0-0x80000001cfd4
0x500000130: GetVariable(VariableName = "foo", Attributes = 0x80000001cfbc, DataSize = 0x80000001cfc8, Data = 0x80000001cfd0) = 0x0
Untainting range 0x80000001cfd4-0x80000001cfd8
0x500000430: SetMem(Buffer = 0x80000001cfd4, Size = 0x4, Value = 0xde)
Tainting range 0x500100060-0x500100074
0x500000310: AllocatePool(PoolType = 0x2, Size = 0x14, Buffer = 0x80000001cfc0) = 0x0
Tainting range 0x80000001cfd0-0x80000001cfd4
0x500000430: SetMem(Buffer = 0x80000001cfd0, Size = 0x4, Value = 0x0)
0x500000428: CopyMem(Destination = 0x500100062, Source = 0x80000001cfd0, Length = 0x10)
Untainting range 0x500100060-0x500100074
0x500000140: SetVariable(VariableName = "bar", Attributes = 0x0, DataSize = 0x14, Data = 0x500100060) = 0x0
[+] No more modules to run
PASSED
```

## Compiling
1. Clone and setup EDK2.
2. Copy `tests/src/EfiFuzzTestsPkg` to the edk2 base dir
3. Edit the `edk2/Conf/target.txt` file: \
  3.1. Set ACTIVE_PLATFORM = MdeModulePkg/MdeModulePkg.dsc \
  3.2. Set TARGET_ARCH = X64 \
  3.3. Set TOOL_CHAIN_TAG = VS2019
4. Add the entry `EfiFuzzTestsPkg/EfiFuzzTests.inf` to the [components] section of `edk2/MdeModulePkg/MdeModulePkg.dsc`
5. Execute `build`, the binaries should be at `edk2/MdeModule/DEBUG_VS2019/X64/EfiFuzzTestsPkg/EfiFuzzTests/OUTPUT`

## List of currently available tests
* `test_uninitialized_memory_tracker`: tests the Triton-based taint propagation logic which is used to keep track of uninitialized memory.
