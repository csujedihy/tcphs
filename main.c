/*

tcphs - TCP handshake benchmark

IO model:

For client:
The client spins up multiple (by default, the # of CPU cores) workers each running on a separate thread.
Each worker repeats connecting to the server and disconnecting forcibly (avoid timewaits)
right after the connection is established. Each worker can have a constant number of pending connects.

Each worker is assigned a IOCP handle and all connect IOs that are initiated by same worker are associated
with the same IOCP handle.

For server:
The only difference is all workers share the same IOCP handle and the acceptex IOs are initiated by only one
worker. The other workers are used to process the accept IO completions.

*/

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <mswsock.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define USAGE L"Usage: tcphs -s|-c <ip> [-p <port>] [-o <num conns>] [-a <num accepts>] [-t <duration in sec>] [-r <num procs>]\n" \
              L"  -s: server mode\n" \
              L"  -c: client mode\n" \
              L"  -p: port number (default: 0)\n" \
              L"  -o: number of connections (default: 16)\n" \
              L"  -a: number of accepts (default: 512)\n" \
              L"  -t: duration in seconds (default: 5)\n" \
              L"  -r: number of threads (default: number of processors)\n"
#define DEFAULT_NUM_CONNS 16
#define DEFAULT_NUM_ACCEPTS 512
#define DEFAULT_DURATION_IN_SEC 5
#define HISTO_SIZE 512
#define HISTO_GRANULARITY_US 100

typedef enum {
    RoleServer = L's',
    RoleClient = L'c',
} Role;

DECLSPEC_ALIGN(SYSTEM_CACHE_ALIGNMENT_SIZE)
typedef struct WORKER {
    HANDLE Iocp;
    SOCKET ListenSocket;
    volatile BOOLEAN Running;
    volatile LONG64 AcceptedCount;
    volatile LONG64 FailedAcceptCount;
    volatile LONG64 ConnectedCount;
    volatile LONG64 FailedConnectCount;
    volatile LONG64 FailedBindCount;
    volatile LONG64 PendingIoCount;
    void* IoContexts;
    ULONG Histo[HISTO_SIZE];
    USHORT HistoIdx;
} WORKER;

typedef struct GLOBAL_CONFIG {
    Role Role;
    HANDLE TerminationEvent;
    SOCKADDR_STORAGE RemoteAddress;
    SOCKADDR_STORAGE LocalAddress;
    BOOLEAN RandomizedPorts;
    BOOLEAN PortScalability;
    BOOLEAN LatencyHistogram;
    LONG AcceptIOStarted;
    LONG AcceptWorkerRef;
    ULONG GQCSBatchSize;
    ULONG NumProcs;
    ULONG NumConns;
    ULONG NumAccepts;
    ULONG DurationInSec;
    WORKER Workers[1];
} GLOBAL_CONFIG;

GLOBAL_CONFIG* GlobalConfig;

typedef enum {
    ServerCompletionKey = 0,
    ClientCompletionKey,
    TestStart,
    IoLoopEnd,
} CompletionKey;

static_assert(ClientCompletionKey > ServerCompletionKey, "ClientCompletionKey must be greater than ServerCompletionKey");

// Overlapped be the first member so we don't need CONTAINING_RECORD.
typedef struct BASE_CTX {
    WSAOVERLAPPED Overlapped;
    SOCKET Socket;
    ULONG ContextIdx;
    BOOLEAN IoCompleted;
} BASE_CTX;

DECLSPEC_ALIGN(SYSTEM_CACHE_ALIGNMENT_SIZE)
typedef struct ACCEPT_CTX {
    BASE_CTX;
    char Buffer[(sizeof(SOCKADDR_STORAGE) + 16) * 2];
} ACCEPT_CTX;

DECLSPEC_ALIGN(SYSTEM_CACHE_ALIGNMENT_SIZE)
typedef struct CONNECT_CTX {
    BASE_CTX;
    ULONG StartTimeInUs;
} CONNECT_CTX;

LPFN_ACCEPTEX FnAcceptEx = NULL;
GUID GuidAcceptEx = WSAID_ACCEPTEX;
LPFN_CONNECTEX FnConnectEx = NULL;
GUID GuidConnectEx = WSAID_CONNECTEX;
LARGE_INTEGER QPCFreq;

typedef enum {
    LOG_INFO = 0,
    LOG_VERBOSE = 1,
} LogLevel;

#define LOGI(Format, ...) LOG(LOG_INFO, Format, __VA_ARGS__)
#define LOGV(Format, ...) LOG(LOG_VERBOSE, Format, __VA_ARGS__)

LogLevel LoggingLevel = LOG_INFO;

void
LOG(
    LogLevel Level,
    const wchar_t* Format,
    ...)
{
    if (Level > LoggingLevel) {
        return;
    }

    va_list args;
    va_start(args, Format);
    vfwprintf(stdout, Format, args);
    va_end(args);
}

inline
ULONG
GetUsTicks(
    void
    )
{
    LARGE_INTEGER QPC;
    QueryPerformanceCounter(&QPC);
    ULONG64 High = (QPC.QuadPart >> 32) * 1000000;
    ULONG64 Low = (QPC.QuadPart & 0xFFFFFFFF) * 1000000;
    QPC.QuadPart =
        ((High / QPCFreq.QuadPart) << 32) +
        ((Low + ((High % QPCFreq.QuadPart) << 32)) / QPCFreq.QuadPart);
    return QPC.LowPart;
}

VOID
NotifyWorkers(
    GLOBAL_CONFIG* Config,
    CompletionKey Cmd
    )
{
    for (ULONG i = 0; i < (Config->Role == RoleServer ? 1 : Config->NumProcs); ++i) {
        PostQueuedCompletionStatus(Config->Workers[i].Iocp, 0, Cmd, NULL);
    }
}

BOOL
WINAPI
CtrlHandler(
    DWORD CtrlEvent
    )
{
    switch (CtrlEvent) {
    case CTRL_BREAK_EVENT:
    case CTRL_C_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
    case CTRL_CLOSE_EVENT:
        LOGV(L"Exiting IOCP loop...\n");
        NotifyWorkers(GlobalConfig, IoLoopEnd);
        SetEvent(GlobalConfig->TerminationEvent);
        break;
    default:
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
PostConnectExIoToWorker(
    WORKER* Worker,
    ULONG Idx
    )
{
    CONNECT_CTX* ConnectCtx = &((CONNECT_CTX*)Worker->IoContexts)[Idx];
    INT Status = 0;
    LINGER Linger;
    Linger.l_onoff = 1;
    Linger.l_linger = 0;

    memset(&ConnectCtx->Overlapped, 0, sizeof(ConnectCtx->Overlapped));
    ConnectCtx->Socket =
        WSASocket(
            AF_INET6,
            SOCK_STREAM,
            IPPROTO_IP,
            NULL,
            0,
            WSA_FLAG_OVERLAPPED);
    if (ConnectCtx->Socket == INVALID_SOCKET) {
        goto Failed;
    }

    INT Opt = 0;
    Status =
        setsockopt(
            ConnectCtx->Socket, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&Opt, sizeof(Opt));
    if (Status == SOCKET_ERROR) {
        Worker->FailedConnectCount++;
        goto Failed;
    }

    Status =
        setsockopt(
            ConnectCtx->Socket,
            SOL_SOCKET,
            SO_LINGER,
            (char*)&Linger,
            sizeof(Linger));
    if (Status == SOCKET_ERROR) {
        Worker->FailedConnectCount++;
        goto Failed;
    }

    if (GlobalConfig->PortScalability) {
        DWORD Opt = 1;
        Status =
            setsockopt(
                ConnectCtx->Socket,
                SOL_SOCKET,
                SO_PORT_SCALABILITY,
                (char*)&Opt,
                sizeof(Opt));
        if (Status == SOCKET_ERROR) {
            Worker->FailedConnectCount++;
            goto Failed;
        }
    }

    if (GlobalConfig->RandomizedPorts) {
        DWORD Opt = 1;
        Status =
            setsockopt(
                ConnectCtx->Socket,
                SOL_SOCKET,
                SO_RANDOMIZE_PORT,
                (char*)&Opt,
                sizeof(Opt));
        if (Status == SOCKET_ERROR) {
            Worker->FailedConnectCount++;
            goto Failed;
        }
    }

    Status =
        bind(
            ConnectCtx->Socket,
            (PSOCKADDR)&GlobalConfig->LocalAddress,
            sizeof(GlobalConfig->LocalAddress));
    if (Status == SOCKET_ERROR) {
        Worker->FailedBindCount++;
        goto Failed;
    }

    CreateIoCompletionPort(
        (HANDLE)ConnectCtx->Socket,
        Worker->Iocp,
        (ULONG_PTR)ClientCompletionKey, 0);

    if (!FnConnectEx(
            ConnectCtx->Socket,
            (PSOCKADDR)&GlobalConfig->RemoteAddress,
            sizeof(GlobalConfig->RemoteAddress),
            NULL,
            0,
            NULL,
            &ConnectCtx->Overlapped)) {
        Status = WSAGetLastError();
        if (Status != WSA_IO_PENDING) {
            LOGI(L"ConnectEx failed with error: %u\n", WSAGetLastError());
            goto Failed;
        }
    }

    ConnectCtx->StartTimeInUs = GetUsTicks();
    ConnectCtx->IoCompleted = FALSE;
    ConnectCtx->ContextIdx = Idx;
    Worker->PendingIoCount++;

    return TRUE;

Failed:
    if (ConnectCtx->Socket != INVALID_SOCKET) {
        closesocket(ConnectCtx->Socket);
    }

    ConnectCtx->IoCompleted = TRUE;
    return FALSE;
}

BOOLEAN
PostAcceptExIoToWorker(
    WORKER* Worker,
    ULONG Idx
    )
{
    ACCEPT_CTX* AcceptCtx = &((ACCEPT_CTX*)Worker->IoContexts)[Idx];
    INT Status = 0;
    DWORD Bytes;

    memset(&AcceptCtx->Overlapped, 0, sizeof(AcceptCtx->Overlapped));
    AcceptCtx->Socket =
        WSASocket(
            AF_INET6,
            SOCK_STREAM,
            IPPROTO_IP,
            NULL,
            0,
            WSA_FLAG_OVERLAPPED);
    if (AcceptCtx->Socket == INVALID_SOCKET) {
        goto Failed;
    }

    AcceptCtx->ContextIdx = Idx;
    AcceptCtx->IoCompleted = FALSE;

    if (!FnAcceptEx(
            Worker->ListenSocket,
            AcceptCtx->Socket,
            AcceptCtx->Buffer,
            0,
            sizeof(SOCKADDR_STORAGE) + 16,
            sizeof(SOCKADDR_STORAGE) + 16,
            &Bytes,
            &AcceptCtx->Overlapped)) {
        Status = WSAGetLastError();
        if (Status != WSA_IO_PENDING) {
            LOGI(L"AcceptEx failed with error: %u\n", WSAGetLastError());
            goto Failed;
        }
    } else {
        assert(FALSE); // AcceptEx never completes inline.
    }

    ++Worker->PendingIoCount;
    return TRUE;

Failed:
    Worker->FailedAcceptCount++;

    if (AcceptCtx->Socket != INVALID_SOCKET) {
        closesocket(AcceptCtx->Socket);
    }

    AcceptCtx->IoCompleted = TRUE;

    return FALSE;
}

DWORD
WINAPI
IocpLoop(
    LPVOID Context
    )
{
    WORKER* Worker = (WORKER*)Context;
    ULONG Count;
    PVOID IocpCompletionKey = NULL;
    OVERLAPPED_ENTRY IoCompletions[64];
    ULONG GQCSBatchSize =
        ARRAYSIZE(IoCompletions) <= GlobalConfig->GQCSBatchSize ?
            ARRAYSIZE(IoCompletions) : GlobalConfig->GQCSBatchSize;
    WSAOVERLAPPED* IocpOverlapped;
    BOOL Success;
    CONNECT_CTX* ConnectCtx;
    ACCEPT_CTX* AcceptCtx;
    ULONG Status;
    DWORD ThreadId = GetCurrentThreadId();
    BOOLEAN ShouldCleanUpServer = FALSE;

    LOGV(L"(%d) Entering IOCP loop...\n", ThreadId);

    while (Worker->Running) {
        Success =
            GetQueuedCompletionStatusEx(
                Worker->Iocp,
                IoCompletions,
                GQCSBatchSize,
                &Count,
                INFINITE,
                FALSE);
        Status = WSAGetLastError();
        if (Success == FALSE) {
            LOGI(L"GetQueuedCompletionStatusEx failed: 0x%x\n", Status);
        }
        ULONG Now = GetUsTicks();
        for (ULONG OvId = 0; OvId < Count; ++OvId) {
            IocpOverlapped = IoCompletions[OvId].lpOverlapped;
            IocpCompletionKey = (PVOID)IoCompletions[OvId].lpCompletionKey;
            Success = (IoCompletions[OvId].Internal == 0) ? TRUE : FALSE;
            if (IocpCompletionKey == (PULONG_PTR)ServerCompletionKey) {
                AcceptCtx = (ACCEPT_CTX*)IocpOverlapped;

                if (Success) {
                    ++Worker->AcceptedCount;
                    setsockopt(
                        AcceptCtx->Socket,
                        SOL_SOCKET,
                        SO_UPDATE_ACCEPT_CONTEXT,
                        (PCHAR)&Worker->ListenSocket,
                        sizeof(Worker->ListenSocket));
                } else {
                    ++Worker->FailedAcceptCount;
                }
                closesocket(AcceptCtx->Socket);
                --Worker->PendingIoCount;
                AcceptCtx->IoCompleted = TRUE;

                PostAcceptExIoToWorker(Worker, AcceptCtx->ContextIdx);
            } else if (IocpCompletionKey == (PULONG_PTR)ClientCompletionKey) {
                ConnectCtx = (CONNECT_CTX*)IocpOverlapped;

                if (Success) {
                    ULONG LatencyIdx = (Now - ConnectCtx->StartTimeInUs) / HISTO_GRANULARITY_US;
                    Worker->Histo[LatencyIdx < HISTO_SIZE ? LatencyIdx : HISTO_SIZE - 1]++;
                    ++Worker->ConnectedCount;
                    setsockopt(
                        ConnectCtx->Socket,
                        SOL_SOCKET,
                        SO_UPDATE_CONNECT_CONTEXT,
                        NULL,
                        0);
                } else {
                    ++Worker->FailedConnectCount;
                }
                closesocket(ConnectCtx->Socket);
                --Worker->PendingIoCount;
                ConnectCtx->IoCompleted = TRUE;

                PostConnectExIoToWorker(Worker, ConnectCtx->ContextIdx);
            } else if (IocpCompletionKey == (PULONG_PTR)IoLoopEnd) {
                Worker->Running = FALSE;
                if (GlobalConfig->Role == RoleServer) {
                    // For server, we need to flood the exiting signal to all threads.
                    if (InterlockedDecrement(&GlobalConfig->AcceptWorkerRef) == 0) {
                        ShouldCleanUpServer = TRUE;
                    } else {
                        NotifyWorkers(GlobalConfig, IoLoopEnd);
                    }
                }
            } else if (IocpCompletionKey == (PULONG_PTR)TestStart) {
                // Kick off testing.
                if (GlobalConfig->Role == RoleClient) {
                    for (ULONG i = 0; i < GlobalConfig->NumConns; ++i) {
                        PostConnectExIoToWorker(Worker, i);
                    }
                } else {
                    // RoleServer
                    // Note: in server role, all threads share the same IOCP handle. So, ensure
                    // that only one thread kicks off the acceptex IOs.
                    if (InterlockedExchange(&GlobalConfig->AcceptIOStarted, 1) == 0) {
                        for (ULONG i = 0; i < GlobalConfig->NumAccepts; ++i) {
                            PostAcceptExIoToWorker(Worker, i);
                        }
                    }
                }
            } else {
                assert(FALSE);
            }
        }
    }

    ULONG PendingIoCount = 0;
    if (GlobalConfig->Role == RoleClient) {
        for (ULONG i = 0; i < GlobalConfig->NumConns; ++i) {
            CONNECT_CTX* ConnectCtx = &((CONNECT_CTX*)Worker->IoContexts)[i];
            if (ConnectCtx->IoCompleted == FALSE) {
                ++PendingIoCount;
                closesocket(ConnectCtx->Socket);
            }
        }
    } else if (ShouldCleanUpServer) { // RoleServer
        // For server, last thread to exit will clean up all pending IOs.
        for (ULONG i = 0; i < GlobalConfig->NumAccepts; ++i) {
            ACCEPT_CTX* AcceptCtx = &((ACCEPT_CTX*)Worker->IoContexts)[i];
            if (AcceptCtx->IoCompleted == FALSE) {
                ++PendingIoCount;
                closesocket(AcceptCtx->Socket);
            }
        }
    }

    LOGV(
        L"(%d) stats: %lu pending %llu completed\n",
        ThreadId,
        PendingIoCount,
        GlobalConfig->Role == RoleServer ? Worker->AcceptedCount : Worker->ConnectedCount);

    while (PendingIoCount > 0) {
        Success =
            GetQueuedCompletionStatusEx(
                Worker->Iocp,
                IoCompletions,
                ARRAYSIZE(IoCompletions),
                &Count,
                INFINITE,
                FALSE);
        for (ULONG OvId = 0; OvId < Count; ++OvId) {
            IocpOverlapped = IoCompletions[OvId].lpOverlapped;
            IocpCompletionKey = (PVOID)IoCompletions[OvId].lpCompletionKey;
            Success = (IoCompletions[OvId].Internal == 0) ? TRUE : FALSE;
            if ((PULONG_PTR)IocpCompletionKey <= (PULONG_PTR)ClientCompletionKey) {
                BASE_CTX* Ctx = (BASE_CTX*)IocpOverlapped;
                Ctx->IoCompleted = TRUE;
                --PendingIoCount;
            }
        }
    }

    return 0;
}

PCWSTR
GetIpStringFromAddress(
    PSOCKADDR_STORAGE Address,
    PWSTR AddressBuffer,
    ULONG AddressBufferSize
    )
{
    VOID* InetAddr;

    if (Address->ss_family == AF_INET) {
        InetAddr = &(((PSOCKADDR_INET)Address)->Ipv4.sin_addr);
    } else {
        InetAddr = &(((PSOCKADDR_INET)Address)->Ipv6.sin6_addr);
    }

    return
        InetNtop(
            Address->ss_family,
            InetAddr,
            AddressBuffer,
            AddressBufferSize);
}

INT
RunClient(
    GLOBAL_CONFIG* Config
    )
{
    PHANDLE ThreadArray = NULL;
    INT Status = 0;
    BOOLEAN RetValue = FALSE;
    LONG64 ConnectedCount = 0;
    LONG64 PendingIoCount = 0;
    LONG64 FailedConnectCount = 0;
    LONG64 FailedBindCount = 0;

    ThreadArray = (PHANDLE)calloc(1, sizeof(HANDLE) * Config->NumProcs);
    if (ThreadArray == NULL) {
        LOGI(L"Failed to allocate memory for ThreadArray\n");
        goto Failed;
    }

    for (ULONG i = 0; i < Config->NumProcs; ++i) {
        WORKER* Worker = &Config->Workers[i];
        Worker->Running = TRUE;

        Worker->IoContexts = calloc(Config->NumConns, sizeof(CONNECT_CTX));
        if (Worker->IoContexts == NULL) {
            LOGI(L"Failed to allocate IoContexts array\n");
            goto Failed;
        }

        // Create an IOCP for the worker.
        Worker->Iocp =
            CreateIoCompletionPort(
                INVALID_HANDLE_VALUE,
                NULL,
                (ULONG_PTR)ClientCompletionKey,
                0);
        if (Worker->Iocp == NULL) {
            LOGI(
                L"CreateIoCompletionPort failed with error: %u\n",
                GetLastError());
            goto Failed;
        }
    }

    ULONG ThreadIdx;
    for (ThreadIdx = 0; ThreadIdx < Config->NumProcs; ++ThreadIdx) {
        WORKER* Worker = &Config->Workers[ThreadIdx];
        ThreadArray[ThreadIdx] = CreateThread(NULL, 0, IocpLoop, Worker, 0, NULL);
        if (ThreadArray[ThreadIdx] == NULL) {
            LOGI(L"CreateThread failed with %d\n", GetLastError());
            break;
        }
    }

    if (ThreadIdx == Config->NumProcs) {
        WCHAR AddressBufferRemote[100] = { 0 };
        WCHAR AddressBufferLocal[100] = { 0 };
        LOGI(
            L"Connecting to %s:%d from %s\n",
            GetIpStringFromAddress(
                &Config->RemoteAddress,
                AddressBufferRemote,
                sizeof(AddressBufferRemote)),
            ntohs(SS_PORT(&Config->RemoteAddress)),
            GetIpStringFromAddress(
                &Config->LocalAddress,
                AddressBufferLocal,
                sizeof(AddressBufferLocal)));

        NotifyWorkers(Config, TestStart);
        WaitForSingleObject(Config->TerminationEvent, Config->DurationInSec * 1000);
    }
    NotifyWorkers(Config, IoLoopEnd);

    WaitForMultipleObjects(ThreadIdx, ThreadArray, TRUE, INFINITE);

    for (ULONG i = 0; i < Config->NumProcs; ++i) {
        ConnectedCount += Config->Workers[i].ConnectedCount;
        PendingIoCount += Config->Workers[i].PendingIoCount;
        FailedConnectCount += Config->Workers[i].FailedConnectCount;
        FailedBindCount += Config->Workers[i].FailedBindCount;
    }

    LOGI(L"HPS: %lld\n", ConnectedCount / Config->DurationInSec);
    LOGI(L"Failed connect: %lld\n", FailedConnectCount);
    LOGI(L"Failed bind: %lld\n", FailedBindCount);

    if (Config->LatencyHistogram) {
        LOGI(L"\nLatency Histogram\n");
        LOGI(L"-------------+-----------+-------------------\n");

        // Find maximum count for scaling
        ULONG MaxCount = 0;
        for (ULONG i = 0; i < HISTO_SIZE; ++i) {
            // Accumulate histogram from all threads into first worker
            for (ULONG j = 1; j < Config->NumProcs; ++j) {
                Config->Workers[0].Histo[i] += Config->Workers[j].Histo[i];
            }
            if (Config->Workers[0].Histo[i] > MaxCount) {
                MaxCount = Config->Workers[0].Histo[i];
            }
        }

        // Print header
        LOGI(L"Latency (us) |   Count   | Distribution\n");
        LOGI(L"-------------+-----------+-------------------\n");

        // Print histogram with bars (scaled to 50 characters max width)
        const ULONG MaxBarWidth = 50;
        for (ULONG i = 0; i < HISTO_SIZE; ++i) {
            ULONG Count = Config->Workers[0].Histo[i];
            if (Count > 0 || i == HISTO_SIZE - 1) {  // Only print non-zero buckets + last bucket
                ULONG BarWidth = MaxCount > 0 ? (Count * MaxBarWidth) / MaxCount : 0;

                // Print latency range
                if (i == HISTO_SIZE - 1) {
                    LOGI(L"%5lu+      ", i * HISTO_GRANULARITY_US);
                } else {
                    LOGI(L"%5lu-%-5lu ", i * HISTO_GRANULARITY_US, (i + 1) * HISTO_GRANULARITY_US - 1);
                }

                // Print count
                LOGI(L" | %9u | ", Count);
                // Print bar
                for (ULONG j = 0; j < BarWidth; j++) {
                    LOGI(L"#");
                }
                LOGI(L"\n");
            }
        }
    }

    RetValue = TRUE;

Failed:

    for (ULONG i = 0; i < Config->NumProcs; ++i) {
        if (Config->Workers[i].Iocp != NULL) {
            CloseHandle(Config->Workers[i].Iocp);
        }
        if (Config->Workers[i].IoContexts != NULL) {
            free(Config->Workers[i].IoContexts);
        }
    }

    if (ThreadArray) {
        for (ULONG i = 0; i < Config->NumProcs; ++i) {
            if (ThreadArray[i] != NULL) {
                CloseHandle(ThreadArray[i]);
            }
        }

        free(ThreadArray);
    }

    return RetValue;
}

BOOLEAN
RunServer(
    GLOBAL_CONFIG* Config
    )
{
    WCHAR AddressBuffer[100] = { 0 };
    PHANDLE ThreadArray = NULL;
    INT Status = 0;
    BOOLEAN RetValue = FALSE;
    SOCKET ListenSocket = INVALID_SOCKET;
    HANDLE Iocp = NULL;
    LINGER Linger;
    Linger.l_onoff = 1;
    Linger.l_linger = 0;

    ListenSocket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (ListenSocket == INVALID_SOCKET) {
        LOGI(L"socket failed with %d\n", WSAGetLastError());
        goto Failed;
    }

    INT Opt = 0;
    Status =
        setsockopt(
            ListenSocket, IPPROTO_IPV6, IPV6_V6ONLY, (char*)&Opt, sizeof(Opt));
    if (Status == SOCKET_ERROR) {
        LOGI(L"IPPROTO_IPV6 failed with %d\n", WSAGetLastError());
        goto Failed;
    }

    Status =
        setsockopt(
            ListenSocket,
            SOL_SOCKET,
            SO_LINGER,
            (char*)&Linger,
            sizeof(Linger));
    if (Status == SOCKET_ERROR) {
        LOGI(L"SO_LINGER (listener) failed with %d\n", WSAGetLastError());
        goto Failed;
    }

    Status = bind(ListenSocket, (PSOCKADDR)&Config->LocalAddress, sizeof(Config->LocalAddress));
    if (Status == SOCKET_ERROR) {
        LOGI(L"bind failed with %d\n", WSAGetLastError());
        goto Failed;
    }

    Status = listen(ListenSocket, SOMAXCONN_HINT(SOMAXCONN));
    if (Status == SOCKET_ERROR) {
        LOGI(L"listen failed with %d\n", WSAGetLastError());
    }

    Iocp =
        CreateIoCompletionPort(
            (HANDLE)ListenSocket,
            NULL,
            (ULONG_PTR)ServerCompletionKey,
            0);
    if (Iocp == NULL) {
        LOGI(
            L"CreateIoCompletionPort failed with error: %u\n",
            GetLastError());
        goto Failed;
    }

    LOGI(
        L"Listening on %s:%d\n",
        GetIpStringFromAddress(
            &Config->LocalAddress,
            AddressBuffer,
            sizeof(AddressBuffer)),
        ntohs(SS_PORT(&Config->LocalAddress)));

    // All workers share the same IO context array.
    void* IoContexts = calloc(Config->NumAccepts, sizeof(ACCEPT_CTX));
    if (IoContexts == NULL) {
        LOGI(L"Failed to allocate IoContexts array\n");
        goto Failed;
    }

    for (ULONG i = 0; i < Config->NumProcs; ++i) {
        WORKER* Worker = &Config->Workers[i];
        Worker->Running = TRUE;
        Worker->ListenSocket = ListenSocket;
        Worker->Iocp = Iocp;
        Worker->IoContexts = IoContexts;
    }

    ThreadArray = (PHANDLE)calloc(1, sizeof(HANDLE) * Config->NumProcs);
    if (ThreadArray == NULL) {
        LOGI(L"Failed to allocate memory for ThreadArray\n");
        goto Failed;
    }

    ULONG ThreadIdx;
    for (ThreadIdx = 0; ThreadIdx < Config->NumProcs; ++ThreadIdx) {
        WORKER* Worker = &Config->Workers[ThreadIdx];
        InterlockedIncrement(&Config->AcceptWorkerRef);
        ThreadArray[ThreadIdx] = CreateThread(NULL, 0, IocpLoop, Worker, 0, NULL);
        if (ThreadArray[ThreadIdx] == NULL) {
            LOGI(L"CreateThread failed with %d\n", GetLastError());
            break;
        }
    }

    NotifyWorkers(Config, ThreadIdx == Config->NumProcs ? TestStart : IoLoopEnd);
    WaitForMultipleObjects(ThreadIdx, ThreadArray, TRUE, INFINITE);

Failed:

    for (ULONG i = 0; i < Config->NumProcs; ++i) {
        WORKER* Worker = &Config->Workers[i];
        if (Worker->IoContexts && i == 0) {
            free(Worker->IoContexts);
        }
    }

    // TODO: Close the listen socket before shutting down the iocp loop?
    if (ListenSocket != INVALID_SOCKET) {
        closesocket(ListenSocket);
    }

    if (Iocp != NULL) {
        CloseHandle(Iocp);
    }

    if (ThreadArray != NULL) {
        for (ULONG i = 0; i < Config->NumProcs; ++i) {
            if (ThreadArray[i] != NULL) {
                CloseHandle(ThreadArray[i]);
            }
        }

        free(ThreadArray);
    }

    return RetValue;
}

INT
ParseIPAddress(
    PCWSTR IpAddress,
    PSOCKADDR_INET SockAddr
    )
{
    IN_ADDR Addr4;
    IN6_ADDR Addr6;

    SockAddr->si_family = 0;
    if (InetPtonW(AF_INET6, IpAddress, &Addr6)) {
        SockAddr->si_family = AF_INET6;
        memcpy(&SockAddr->Ipv6.sin6_addr, &Addr6, sizeof(Addr6));
    } else if (InetPtonW(AF_INET, IpAddress, &Addr4)) {
        SockAddr->si_family = AF_INET;
        memcpy(&SockAddr->Ipv4.sin_addr, &Addr4, sizeof(Addr4));
    } else {
        return -1;
    }

    return SockAddr->si_family;
}

BOOLEAN
ParseCmd(
    INT Argc,
    WCHAR* Args[],
    GLOBAL_CONFIG* Config
    )
{
    BOOLEAN Status = FALSE;
    LONG Index = 1;
    SYSTEM_INFO SystemInfo;

    if (Argc < 2) {
        return FALSE;
    }

    GetSystemInfo(&SystemInfo);

    Config->NumProcs = SystemInfo.dwNumberOfProcessors;
    Config->NumConns = DEFAULT_NUM_CONNS;
    Config->NumAccepts = DEFAULT_NUM_ACCEPTS;
    Config->DurationInSec = DEFAULT_DURATION_IN_SEC;
    Config->GQCSBatchSize = 0xFFFFFFFF;
    IN6ADDR_SETANY((PSOCKADDR_IN6)&Config->LocalAddress); // dual mode socket

    while (Index < Argc) {
        if (_wcsicmp(Args[Index], L"-c") == 0) {
            Config->Role = RoleClient;
            ++Index;
            if (Index < Argc) {
                SOCKADDR_STORAGE TempAddr = { 0 };
                if (ParseIPAddress(Args[Index], (PSOCKADDR_INET)&TempAddr) == -1) {
                    LOGI(L"Invalid IP address: %s\n", Args[Index]);
                    goto Done;
                }
                if (TempAddr.ss_family == AF_INET) {
                    SCOPE_ID Scope = {0};
                    IN6ADDR_SETV4MAPPED(
                        (SOCKADDR_IN6*)&Config->RemoteAddress,
                        &((SOCKADDR_IN*)&TempAddr)->sin_addr,
                        Scope, 0);
                } else {
                    Config->RemoteAddress = TempAddr;
                }
            } else {
                goto Done;
            }
        } else if (_wcsicmp(Args[Index], L"-s") == 0) {
            Config->Role = RoleServer;
        }else if (_wcsicmp(Args[Index], L"-p") == 0) {
            ++Index;
            if (Index < Argc) {
                if (Config->Role == RoleClient) {
                    SS_PORT(&Config->RemoteAddress) = htons((USHORT)_wtoi(Args[Index]));
                } else {
                    SS_PORT(&Config->LocalAddress) = htons((USHORT)_wtoi(Args[Index]));
                }
            } else {
                goto Done;
            }
        } else if (_wcsicmp(Args[Index], L"-o") == 0) {
            ++Index;
            if (Index < Argc && Config->Role == RoleClient) {
                Config->NumConns = _wtoi(Args[Index]);
            } else {
                goto Done;
            }
        } else if (_wcsicmp(Args[Index], L"-a") == 0) {
            ++Index;
            if (Index < Argc && Config->Role == RoleServer) {
                Config->NumAccepts = _wtoi(Args[Index]);
            } else {
                goto Done;
            }
        } else if (_wcsicmp(Args[Index], L"-t") == 0) {
            ++Index;
            if (Index < Argc) {
                Config->DurationInSec = _wtoi(Args[Index]);
            } else {
                goto Done;
            }
        } else if (_wcsicmp(Args[Index], L"-r") == 0) {
            ++Index;
            if (Index < Argc) {
                Config->NumProcs = _wtoi(Args[Index]);
            } else {
                goto Done;
            }
        } else if (_wcsicmp(Args[Index], L"-g") == 0) {
            ++Index;
            if (Index < Argc) {
                Config->GQCSBatchSize = _wtoi(Args[Index]);
            } else {
                goto Done;
            }
        }  else if (_wcsicmp(Args[Index], L"-b") == 0) {
            ++Index;
            if (Index < Argc && Config->Role == RoleClient) {
                SOCKADDR_STORAGE TempAddr = { 0 };
                if (ParseIPAddress(Args[Index], (PSOCKADDR_INET)&TempAddr) == -1) {
                    LOGI(L"Invalid IP address: %s\n", Args[Index]);
                    goto Done;
                }
                if (TempAddr.ss_family == AF_INET) {
                    SCOPE_ID Scope = {0};
                    IN6ADDR_SETV4MAPPED(
                        (SOCKADDR_IN6*)&Config->LocalAddress,
                        &((SOCKADDR_IN*)&TempAddr)->sin_addr,
                        Scope, 0);
                } else {
                    Config->LocalAddress = TempAddr;
                }
            } else {
                goto Done;
            }
        } else if (_wcsicmp(Args[Index], L"-m") == 0) {
            Config->RandomizedPorts = TRUE;
        } else if (_wcsicmp(Args[Index], L"-h") == 0) {
            Config->LatencyHistogram = TRUE;
        } else if (_wcsicmp(Args[Index], L"-l") == 0) {
            Config->PortScalability = TRUE;
        } else if (_wcsicmp(Args[Index], L"-v") == 0) {
            LoggingLevel = LOG_VERBOSE;
        }else {
            goto Done;
        }

        ++Index;
    }

    Status = TRUE;

Done:
    return Status;
}

VOID
PrintUsage(
    VOID
    )
{
    LOGI(USAGE);
}

INT
__cdecl
wmain(
    INT Argc,
    WCHAR* Args[]
    )
{
    WSADATA WsaData;
    INT Status = -1;
    DWORD Bytes;
    SOCKET Socket;
    GLOBAL_CONFIG TempConfig = {0};

    WSAStartup(MAKEWORD(2, 2), &WsaData);

    if (!ParseCmd(Argc, Args, &TempConfig)) {
        PrintUsage();
        goto Done;
    }

    GlobalConfig =
        calloc(
            1,
            sizeof(GLOBAL_CONFIG) + sizeof(WORKER) * (TempConfig.NumProcs - 1));
    if (GlobalConfig == NULL) {
        LOGI(L"Failed to allocate memory for GlobalConfig\n");
        goto Done;
    }

    *GlobalConfig = TempConfig;
    LOGV(L"Configs:\n");
    LOGV(L"  Role: %s\n", GlobalConfig->Role == RoleClient ? L"Client" : L"Server");
    LOGV(L"  NumProcs: %lu\n", GlobalConfig->NumProcs);
    LOGV(L"  NumConns: %lu\n", GlobalConfig->NumConns);
    LOGV(L"  NumAccepts: %lu\n", GlobalConfig->NumAccepts);
    LOGV(L"  DurationInSec: %lu\n", GlobalConfig->DurationInSec);
    LOGV(L"  GQCSBatchSize: %lu\n", GlobalConfig->GQCSBatchSize);
    LOGV(L"  RandomizedPorts: %s\n", GlobalConfig->RandomizedPorts ? L"TRUE" : L"FALSE");
    LOGV(L"  PortScalability: %s\n", GlobalConfig->PortScalability ? L"TRUE" : L"FALSE");

    if (!QueryPerformanceFrequency(&QPCFreq)) {
        LOGI(L"QueryPerformanceFrequency failed with %d\n", GetLastError());
        goto Done;
    }

    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    Socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    Status =
        WSAIoctl(
            Socket,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &GuidConnectEx,
            sizeof(GuidConnectEx), &FnConnectEx, sizeof(FnConnectEx),
            &Bytes, NULL, NULL);
    if (Status == SOCKET_ERROR) {
        LOGI(L"WSAIoctl failed with error: %u\n", WSAGetLastError());
        goto Done;
    }

    Status =
        WSAIoctl(
            Socket,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &GuidAcceptEx, sizeof(GuidAcceptEx),
            &FnAcceptEx, sizeof(FnAcceptEx),
            &Bytes, NULL, NULL);
    if (Status == SOCKET_ERROR) {
        LOGI(L"WSAIoctl failed with error: %u\n", WSAGetLastError());
        goto Done;
    }

    GlobalConfig->TerminationEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (GlobalConfig->TerminationEvent == NULL) {
        LOGI(L"CreateEvent failed with error: %u\n", GetLastError());
        goto Done;
    }

    if (GlobalConfig->Role == RoleServer) {
        if (!RunServer(GlobalConfig)) {
            goto Done;
        }
    } else if (GlobalConfig->Role == RoleClient) {
        if (!RunClient(GlobalConfig)) {
            goto Done;
        }
    } else {
        PrintUsage();
        goto Done;
    }

    Status = 0;

Done:
    SetConsoleCtrlHandler(CtrlHandler, FALSE);
    WSACleanup();
    LOGI(L"Done...\n");
    return Status;
}
