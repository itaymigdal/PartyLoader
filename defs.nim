import winim

proc NtQueryObject*(Handle: HANDLE, ObjectInformationClass: OBJECT_INFORMATION_CLASS, ObjectInformation: PVOID, ObjectInformationLength: ULONG, ReturnLength: PULONG): NTSTATUS {.winapi, stdcall, dynlib: "ntdll", importc.}

const
    PROCESS_HANDLE_INFORMATION* = 51
    OBJECT_TYPE_INFORMATION* = 2
    STATUS_INFO_LENGTH_MISMATCH*: NTSTATUS = cast[NTSTATUS](0xC0000004)
    WORKER_FACTORY_RELEASE_WORKER* = 0x0001
    WORKER_FACTORY_WAIT* = 0x0002
    WORKER_FACTORY_SET_INFORMATION* = 0x0004
    WORKER_FACTORY_QUERY_INFORMATION* = 0x0008
    WORKER_FACTORY_READY_WORKER* = 0x0010
    WORKER_FACTORY_SHUTDOWN* = 0x0020
    WORKER_FACTORY_ALL_ACCESS* = (
        STANDARD_RIGHTS_REQUIRED or
        WORKER_FACTORY_RELEASE_WORKER or
        WORKER_FACTORY_WAIT or
        WORKER_FACTORY_SET_INFORMATION or
        WORKER_FACTORY_QUERY_INFORMATION or
        WORKER_FACTORY_READY_WORKER or
        WORKER_FACTORY_SHUTDOWN
    )

type
    TP_TASK_CALLBACKS* = object
        ExecuteCallback, Unposted: LPVOID

    TP_TASK* = object
        Callbacks: ptr TP_TASK_CALLBACKS
        NumaNode: uint32
        IdealProcessor: uint8
        Padding_242: array[3, char]
        ListEntry: LIST_ENTRY

    TPP_REFCOUNT* = object
        Refcount: int32

    TPP_CALLER* = object
        ReturnAddress: LPVOID

    TPP_PH_LINKS* = object
        Siblings, Children: LIST_ENTRY
        Key: int64

    TPP_PH* = object
        Root: ptr TPP_PH_LINKS

    TP_DIRECT* = object
        Task: TP_TASK
        Lock: uint64
        IoCompletionInformationList: LIST_ENTRY
        Callback: LPVOID
        NumaNode: uint32
        IdealProcessor: uint8
        Padding_3: array[3, char]

    TPP_TIMER_SUBQUEUE* = object
        Expiration: int64
        WindowStart, WindowEnd: TPP_PH
        Timer, TimerPkt: LPVOID
        Direct: TP_DIRECT
        ExpirationWindow: uint32
        Padding_1: array[1, int32]

    TPP_TIMER_QUEUE* = object
        Lock: RTL_SRWLOCK
        AbsoluteQueue, RelativeQueue: TPP_TIMER_SUBQUEUE
        AllocatedTimerCount: int32
        Padding_1: array[1, int32]

    TPP_NUMA_NODE* = object
        WorkerCount: int32

    TPP_POOL_QUEUE_STATE* {.pure, union.} = object
        Exchange: int64
        RunningThreadGoal, PendingReleaseCount, QueueLength: uint32

    TPP_QUEUE* = object
        Queue: LIST_ENTRY
        Lock: RTL_SRWLOCK

    FULL_TP_POOL* = object
        Refcount: TPP_REFCOUNT
        Padding_239: cint
        QueueState: TPP_POOL_QUEUE_STATE
        TaskQueue: array[3, ptr TPP_QUEUE]
        NumaNode: ptr TPP_NUMA_NODE
        ProximityInfo: ptr GROUP_AFFINITY
        WorkerFactory, CompletionPort: LPVOID
        Lock: RTL_SRWLOCK
        PoolObjectList, WorkerList: LIST_ENTRY
        TimerQueue: TPP_TIMER_QUEUE
        ShutdownLock: RTL_SRWLOCK
        ShutdownInitiated, Released: uint8
        PoolFlags: uint16
        Padding_240: cint
        PoolLinks: LIST_ENTRY
        AllocCaller, ReleaseCaller: TPP_CALLER
        AvailableWorkerCount, LongRunningWorkerCount: int32 # Volatile
        LastProcCount: uint32
        NodeStatus, BindingCount: int32 # Volatile
        CallbackChecksDisabled, TrimTarget, TrimmedThrdCount: uint32
        SelectedCpuSetCount: uint32
        Padding_241: cint
        TrimComplete: RTL_CONDITION_VARIABLE
        TrimmedWorkerList: LIST_ENTRY

    ALPC_WORK_ON_BEHALF_TICKET* = object
        ThreadId, ThreadCreationTimeLow: uint32

    TPP_WORK_STATE* {.pure, union.} = object
        Exchange: int32
        Insertable: bool
        PendingCallbackCount: uint32

    TPP_ITE_WAITER* = object
        Next: ptr TPP_ITE_WAITER
        ThreadId: LPVOID

    TPP_ITE* = object
        First: ptr TPP_ITE_WAITER

    TPP_FLAGS_COUNT* {.pure, union.} = object
        Count: uint64
        Flags: uint64
        Data: int64

    TPP_BARRIER* = object
        Ptr: TPP_FLAGS_COUNT # Volatile
        WaitLock: RTL_SRWLOCK
        WaitList: TPP_ITE

    TP_CLEANUP_GROUP* = object
        Refcount: TPP_REFCOUNT
        Released: int32
        MemberLock: RTL_SRWLOCK
        MemberList: LIST_ENTRY
        Barrier: TPP_BARRIER
        CleanupLock: RTL_SRWLOCK
        CleanupList: LIST_ENTRY

    TPP_CLEANUP_GROUP_MEMBER* = object
        Refcount: TPP_REFCOUNT
        Padding_233: clong
        VFuncs: LPVOID # ptr TPP_CLEANUP_GROUP_MEMBER_VFUNCS ?
        CleanupGroup: ptr TP_CLEANUP_GROUP
        CleanupGroupCancelCallback, FinalizationCallback: LPVOID
        CleanupGroupMemberLinks: LIST_ENTRY
        CallbackBarrier: TPP_BARRIER
        Callback: LPVOID # UNION https://github.com/icyguider/Shhhloader/blob/898004b60b360e7c9b50e59665c2f4331e08e278/PoolParty.h#L225
        Context: LPVOID
        ActivationContext: ptr ACTIVATION_CONTEXT
        SubProcessTag: LPVOID
        ActivityId: GUID
        WorkOnBehalfTicket: ALPC_WORK_ON_BEHALF_TICKET
        RaceDll: LPVOID
        Pool: ptr FULL_TP_POOL
        PoolObjectLinks: LIST_ENTRY
        Flags: int32 # UNION https://github.com/icyguider/Shhhloader/blob/898004b60b360e7c9b50e59665c2f4331e08e278/PoolParty.h#L245
        Padding_234: clong
        AllocCaller, ReleaseCaller: TPP_CALLER
        CallbackPriority: TP_CALLBACK_PRIORITY
        Padding_1: array[1, int32]

    FULL_TP_WORK* = object
        CleanupGroupMember: TPP_CLEANUP_GROUP_MEMBER
        Task: TP_TASK
        WorkState: TPP_WORK_STATE # Volatile
        Padding_1: array[1, int32]

    FULL_TP_TIMER* = object
        Work: FULL_TP_WORK
        Lock: RTL_SRWLOCK
        WindowEndLinks: TPP_PH_LINKS
        ExpirationLinks: LIST_ENTRY
        WindowStartLinks: TPP_PH_LINKS
        DueTime: int64
        Ite: TPP_ITE
        Window, Period: uint32
        Inserted: uint8
        WaitTimer: uint8
        TimerStatus: uint8 # UNION https://github.com/icyguider/Shhhloader/blob/898004b60b360e7c9b50e59665c2f4331e08e278/PoolParty.h#L287
        BlockInsert: uint8
        Padding_1: array[1, int32]

    FULL_TP_WAIT* = object
        Timer: FULL_TP_TIMER
        Handle, WaitPkt, NextWaitHandle: LPVOID
        NextWaitTimeout: LARGE_INTEGER
        Direct: TP_DIRECT
        WaitFlags: uint8 # UNION https://github.com/icyguider/Shhhloader/blob/898004b60b360e7c9b50e59665c2f4331e08e278/PoolParty.h#L306
        Padding_7: array[7, char]

    FULL_TP_IO* = object
        CleanupGroupMember: TPP_CLEANUP_GROUP_MEMBER
        Direct: TP_DIRECT
        File: LPVOID
        PendingIrpCount: int32 # Volatile
        Padding_1: array[1, int32]

    FULL_TP_ALPC* = object
        Direct: TP_DIRECT
        CleanupGroupMember: TPP_CLEANUP_GROUP_MEMBER
        AlpcPort: LPVOID
        DeferredSendCount, LastConcurrencyCount: int32
        Flags: uint32 # UNION https://github.com/icyguider/Shhhloader/blob/898004b60b360e7c9b50e59665c2f4331e08e278/PoolParty.h#L336
        Padding_1: array[1, int32]

    T2_SET_PARAMETERS* = object
        Version, Reserved: uint32
        NoWakeTolerance: int64

    PROCESS_HANDLE_TABLE_ENTRY_INFO* = object
        HandleValue*: HANDLE
        HandleCount*, PointerCount*: ULONG_PTR
        GrantedAccess*: ACCESS_MASK
        ObjectTypeIndex*, HandleAttributes*, Reserved*: ULONG

    PPROCESS_HANDLE_TABLE_ENTRY_INFO* = ptr PROCESS_HANDLE_TABLE_ENTRY_INFO

    PROCESS_HANDLE_SNAPSHOT_INFORMATION* = object
        NumberOfHandles*, Reserved*: ULONG_PTR
        Handles*: array[ANYSIZE_ARRAY, PROCESS_HANDLE_TABLE_ENTRY_INFO]
    
    PPROCESS_HANDLE_SNAPSHOT_INFORMATION* = ptr PROCESS_HANDLE_SNAPSHOT_INFORMATION

    WORKER_FACTORY_BASIC_INFORMATION* = object
        Timeout, RetryTimeout, IdleTimeout: LARGE_INTEGER
        Paused, TimerSet, QueuedToExWorker, MayCreate, CreateInProgress, InsertedIntoQueue, Shutdown: bool
        BindingCount, ThreadMinimum, ThreadMaximum, PendingWorkerCount, WaitingWorkerCount, TotalWorkerCount, ReleaseCount: ULONG
        InfiniteWaitGoal: LONGLONG
        StartRoutine, StartParameter: LPVOID
        ProcessId: HANDLE
        StackReserve, StackCommit: SIZE_T
        LastThreadCreationStatus: NTSTATUS

    PUBLIC_OBJECT_TYPE_INFORMATION* = object
        TypeName*: UNICODE_STRING
        Reserved*: array[22, ULONG]
    
    PPUBLIC_OBJECT_TYPE_INFORMATION* = ptr PUBLIC_OBJECT_TYPE_INFORMATION

