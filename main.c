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

typedef enum {
    RoleServer = L's',
    RoleClient = L'c',
} Role;

typedef struct _WORKER {
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
} WORKER;

typedef struct _GLOBAL_CONFIG {
    Role Role;
    HANDLE CompletionEvent;
    SOCKADDR_STORAGE Address;
    ULONG NumProcs;
    ULONG NumConns;
    ULONG NumAccepts;
    ULONG DurationInSec;
    WORKER Workers[1];
} GLOBAL_CONFIG;

GLOBAL_CONFIG* GlobalConfig;

typedef enum {
    ServerCompletionKey,
    ClientCompletionKey,
    TestStart,
    IoLoopEnd,
} CompletionKey;

//
// Overlapped be the first member so we don't need CONTAINING_RECORD.
//
typedef struct _BASE_CTX {
    WSAOVERLAPPED Overlapped;
    SOCKET Socket;
    ULONG ContextIdx;
    BOOLEAN IoCompleted;
} BASE_CTX;

typedef struct _ACCEPT_CTX {
    BASE_CTX;
    char Buffer[(sizeof(SOCKADDR_STORAGE) + 16) * 2];
} ACCEPT_CTX, * PACCEPT_CTX;

typedef struct _CONNECT_CTX {
    BASE_CTX;
} CONNECT_CTX;

LPFN_ACCEPTEX FnAcceptEx = NULL;
GUID GuidAcceptEx = WSAID_ACCEPTEX;
LPFN_CONNECTEX FnConnectEx = NULL;
GUID GuidConnectEx = WSAID_CONNECTEX;

VOID
NotifyWorkers(
    GLOBAL_CONFIG* Config,
    CompletionKey Cmd
    )
{
    for (DWORD i = 0; i < Config->NumProcs; ++i) {
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
        wprintf(L"Exiting IOCP loop...\n");
        NotifyWorkers(GlobalConfig, IoLoopEnd);
        break;
    default:
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
PostConnectExToIoCompletionPort(
    WORKER* Worker,
    ULONG Idx
    )
{
    CONNECT_CTX* ConnectCtx = &((CONNECT_CTX*)Worker->IoContexts)[Idx];
    SOCKADDR_STORAGE LocalAddress = { 0 };
    INT Status = 0;
    LINGER Linger;
    Linger.l_onoff = 1;
    Linger.l_linger = 0;

    memset(&ConnectCtx->Overlapped, 0, sizeof(ConnectCtx->Overlapped));
    ConnectCtx->Socket =
        WSASocket(
            GlobalConfig->Address.ss_family,
            SOCK_STREAM,
            IPPROTO_IP,
            NULL,
            0,
            WSA_FLAG_OVERLAPPED);
    if (ConnectCtx->Socket == INVALID_SOCKET) {
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

    if (GlobalConfig->Address.ss_family == AF_INET) {
        IN4ADDR_SETANY((PSOCKADDR_IN)&LocalAddress);
    } else {
        IN6ADDR_SETANY((PSOCKADDR_IN6)&LocalAddress);
    }

    SS_PORT(&LocalAddress) = 0;

    Status =
        bind(
            ConnectCtx->Socket,
            (PSOCKADDR)&LocalAddress,
            sizeof(LocalAddress));
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
        (PSOCKADDR)&GlobalConfig->Address,
        sizeof(GlobalConfig->Address),
        NULL,
        0,
        NULL,
        &ConnectCtx->Overlapped)) {
        Status = WSAGetLastError();
        if (Status != WSA_IO_PENDING) {
            wprintf(L"ConnectEx failed with error: %u\n", WSAGetLastError());
            goto Failed;
        }
    }

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
PostAcceptExToIoCompletionPort(
    WORKER* Worker,
    ULONG Idx
    )
{
    PACCEPT_CTX AcceptCtx = &((PACCEPT_CTX)Worker->IoContexts)[Idx];
    INT Status = 0;
    DWORD Bytes;
    LINGER Linger;
    Linger.l_onoff = 1;
    Linger.l_linger = 0;

    memset(&AcceptCtx->Overlapped, 0, sizeof(AcceptCtx->Overlapped));
    AcceptCtx->Socket =
        WSASocket(
            GlobalConfig->Address.ss_family,
            SOCK_STREAM,
            IPPROTO_IP,
            NULL,
            0,
            WSA_FLAG_OVERLAPPED);
    if (AcceptCtx->Socket == INVALID_SOCKET) {
        goto Failed;
    }

    Status =
        setsockopt(
            AcceptCtx->Socket,
            SOL_SOCKET,
            SO_LINGER,
            (char*)&Linger,
            sizeof(Linger));
    if (Status == SOCKET_ERROR) {
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
            wprintf(L"AcceptEx failed with error: %u\n", WSAGetLastError());
            goto Failed;
        }
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
    OVERLAPPED_ENTRY IoCompletions[32];
    WSAOVERLAPPED* IocpOverlapped;
    BOOL Success;
    CONNECT_CTX* ConnectCtx;
    ACCEPT_CTX* AcceptCtx;
    ULONG Status;
    DWORD ThreadId = GetCurrentThreadId();

    wprintf(L"(%d) Entering IOCP loop...\n", ThreadId);

    while (Worker->Running) {
        Success =
            GetQueuedCompletionStatusEx(
                Worker->Iocp,
                IoCompletions,
                ARRAYSIZE(IoCompletions),
                &Count,
                INFINITE,
                FALSE);
        Status = WSAGetLastError();
        if (Success == FALSE) {
            wprintf(L"GetQueuedCompletionStatusEx failed: 0x%x\n", Status);
        }
        for (ULONG OvId = 0; OvId < Count; ++OvId) {
            IocpOverlapped = IoCompletions[OvId].lpOverlapped;
            IocpCompletionKey = (PVOID)IoCompletions[OvId].lpCompletionKey;
            Success = (IoCompletions[OvId].Internal == 0) ? TRUE : FALSE;
            if (IocpCompletionKey == (PULONG_PTR)ServerCompletionKey) {
                AcceptCtx = (PACCEPT_CTX)IocpOverlapped;
                if (Success) {
                    ++Worker->AcceptedCount;
                    setsockopt(
                        AcceptCtx->Socket,
                        SOL_SOCKET,
                        SO_UPDATE_ACCEPT_CONTEXT,
                        (PCHAR)&Worker->ListenSocket,
                        sizeof(Worker->ListenSocket));
                    closesocket(AcceptCtx->Socket);
                } else {
                    ++Worker->FailedAcceptCount;
                }
                --Worker->PendingIoCount;
                AcceptCtx->IoCompleted = TRUE;
                PostAcceptExToIoCompletionPort(Worker, AcceptCtx->ContextIdx);
            } else if (IocpCompletionKey == (PULONG_PTR)ClientCompletionKey) {
                ConnectCtx = (CONNECT_CTX*)IocpOverlapped;
                if (Success) {
                    ++Worker->ConnectedCount;
                    setsockopt(
                        ConnectCtx->Socket,
                        SOL_SOCKET,
                        SO_UPDATE_CONNECT_CONTEXT,
                        NULL,
                        0);
                    closesocket(ConnectCtx->Socket);
                } else {
                    ++Worker->FailedConnectCount;
                    closesocket(ConnectCtx->Socket);
                }
                --Worker->PendingIoCount;
                ConnectCtx->IoCompleted = TRUE;
                PostConnectExToIoCompletionPort(Worker, ConnectCtx->ContextIdx);
            } else if (IocpCompletionKey == (PULONG_PTR)IoLoopEnd) {
                Worker->Running = FALSE;
            } else if (IocpCompletionKey == (PULONG_PTR)TestStart) {
                //
                // Kick off testing.
                //
                if (GlobalConfig->Role == RoleClient) {
                    for (ULONG i = 0; i < GlobalConfig->NumConns; ++i) {
                        PostConnectExToIoCompletionPort(Worker, i);
                    }
                } else { // RoleServer
                    for (ULONG i = 0; i < GlobalConfig->NumAccepts; ++i) {
                        PostAcceptExToIoCompletionPort(Worker, i);
                    }
                }
            } else {
                Worker->Running = FALSE;
                wprintf(L"Unexpected socket notification\n");
            }
        }
    }

    wprintf(L"(%d) Draining %llu pending IOs on\n", ThreadId, Worker->PendingIoCount);
    ULONG PendingIoCount = 0;
    if (GlobalConfig->Role == RoleClient) {
        for (ULONG i = 0; i < GlobalConfig->NumConns; ++i) {
            CONNECT_CTX* ConnectCtx = &((CONNECT_CTX*)Worker->IoContexts)[i];
            if (ConnectCtx->IoCompleted == FALSE) {
                ++PendingIoCount;
                closesocket(ConnectCtx->Socket);
            }
        }
    } else {
        for (ULONG i = 0; i < GlobalConfig->NumAccepts; ++i) {
            ACCEPT_CTX* AcceptCtx = &((ACCEPT_CTX*)Worker->IoContexts)[i];
            if (AcceptCtx->IoCompleted == FALSE) {
                ++PendingIoCount;
                closesocket(AcceptCtx->Socket);
            }
        }
    }

    assert(PendingIoCount == Worker->PendingIoCount);

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
            if (IocpCompletionKey == (PULONG_PTR)ServerCompletionKey) {
                AcceptCtx = (PACCEPT_CTX)IocpOverlapped;
                AcceptCtx->IoCompleted = TRUE;
                --PendingIoCount;
            } else if (IocpCompletionKey == (PULONG_PTR)ClientCompletionKey) {
                ConnectCtx = (CONNECT_CTX*)IocpOverlapped;
                ConnectCtx->IoCompleted = TRUE;
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
    WCHAR AddressBuffer[100] = { 0 };
    PHANDLE ThreadArray = NULL;
    INT Status = 0;
    BOOLEAN RetValue = FALSE;
    LONG64 ConnectedCount = 0;
    LONG64 PendingIoCount = 0;
    LONG64 FailedConnectCount = 0;
    LONG64 FailedBindCount = 0;

    ThreadArray = (PHANDLE)calloc(1, sizeof(HANDLE) * Config->NumProcs);
    if (ThreadArray == NULL) {
        wprintf(L"Failed to allocate memory for ThreadArray\n");
        goto Failed;
    }

    for (ULONG i = 0; i < Config->NumProcs; ++i) {
        WORKER* Worker = &Config->Workers[i];
        Worker->Running = TRUE;

        Worker->IoContexts = calloc(Config->NumConns, sizeof(CONNECT_CTX));
        if (Worker->IoContexts == NULL) {
            wprintf(L"Failed to allocate IoContexts array\n");
            goto Failed;
        }

        //
        // Create an IOCP for the worker.
        //
        Worker->Iocp =
            CreateIoCompletionPort(
                INVALID_HANDLE_VALUE,
                NULL,
                (ULONG_PTR)ClientCompletionKey,
                0);
        if (Worker->Iocp == NULL) {
            wprintf(
                L"CreateIoCompletionPort failed with error: %u\n",
                GetLastError());
            goto Failed;
        }
    }

    for (ULONG i = 0; i < Config->NumProcs; ++i) {
        WORKER* Worker = &Config->Workers[i];
        ThreadArray[i] =
            CreateThread(NULL, 0, IocpLoop, Worker, 0, NULL);
    }

    wprintf(
        L"Connecting to %s:%d\n",
        GetIpStringFromAddress(
            &Config->Address,
            AddressBuffer,
            sizeof(AddressBuffer)),
        ntohs(SS_PORT(&Config->Address)));

    NotifyWorkers(Config, TestStart);
    WaitForSingleObject(Config->CompletionEvent, Config->DurationInSec * 1000);
    NotifyWorkers(Config, IoLoopEnd);

    WaitForMultipleObjects(Config->NumProcs, ThreadArray, TRUE, INFINITE);

    for (ULONG i = 0; i < Config->NumProcs; ++i) {
        ConnectedCount += Config->Workers[i].ConnectedCount;
        PendingIoCount += Config->Workers[i].PendingIoCount;
        FailedConnectCount += Config->Workers[i].FailedConnectCount;
        FailedBindCount += Config->Workers[i].FailedBindCount;
    }

    wprintf(L"HPS: %lld\n", ConnectedCount / Config->DurationInSec);
    wprintf(L"Failed connect: %lld\n", FailedConnectCount);
    wprintf(L"Failed bind: %lld\n", FailedBindCount);
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

    assert(Config->NumProcs == 1); // Server only supports 1 processor.

    for (ULONG i = 0; i < Config->NumProcs; ++i) {
        WORKER* Worker = &Config->Workers[i];
        Worker->Running = TRUE;
        Worker->ListenSocket = socket(Config->Address.ss_family, SOCK_STREAM, IPPROTO_TCP);

        Worker->IoContexts = calloc(Config->NumAccepts, sizeof(ACCEPT_CTX));
        if (Worker->IoContexts == NULL) {
            wprintf(L"Failed to allocate IoContexts array\n");
            goto Failed;
        }
        Status = bind(Worker->ListenSocket, (PSOCKADDR)&Config->Address, sizeof(Config->Address));
        if (Status == SOCKET_ERROR) {
            wprintf(L"bind failed with %d\n", WSAGetLastError());
            goto Failed;
        }

        Status = listen(Worker->ListenSocket, SOMAXCONN);
        if (Status == SOCKET_ERROR) {
            wprintf(L"listen failed with %d\n", WSAGetLastError());
        }

        wprintf(
            L"Listening on %s:%d\n",
            GetIpStringFromAddress(
                &Config->Address,
                AddressBuffer,
                sizeof(AddressBuffer)),
            ntohs(SS_PORT(&Config->Address)));

        Worker->Iocp =
            CreateIoCompletionPort(
                (HANDLE)Worker->ListenSocket,
                NULL,
                (ULONG_PTR)ServerCompletionKey,
                0);
        if (Worker->Iocp == NULL) {
            wprintf(
                L"CreateIoCompletionPort failed with error: %u\n",
                GetLastError());
            goto Failed;
        }
    }

    ThreadArray = (PHANDLE)calloc(1, sizeof(HANDLE) * Config->NumProcs);
    if (ThreadArray == NULL) {
        wprintf(L"Failed to allocate memory for ThreadArray\n");
        goto Failed;
    }


    for (ULONG i = 0; i < Config->NumProcs; ++i) {
        WORKER* Worker = &Config->Workers[i];
        ThreadArray[i] = CreateThread(NULL, 0, IocpLoop, Worker, 0, NULL);
    }

    NotifyWorkers(Config, TestStart);
    WaitForMultipleObjects(Config->NumProcs, ThreadArray, TRUE, INFINITE);

Failed:

    for (ULONG i = 0; i < Config->NumProcs; ++i) {
        WORKER* Worker = &Config->Workers[i];
        if (Worker->ListenSocket != INVALID_SOCKET) {
            closesocket(Worker->ListenSocket);
        }
        if (Worker->Iocp != NULL) {
            CloseHandle(Worker->Iocp);
        }
        if (Worker->IoContexts) {
            free(Worker->IoContexts);
        }
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

    if (Argc < 2) {
        return FALSE;
    }

    Config->NumConns = 16;
    Config->NumAccepts = 512;

    while (Index < Argc) {
        if (_wcsicmp(Args[Index], L"-c") == 0 ||
            _wcsicmp(Args[Index], L"-s") == 0) {
            Config->Role = (INT)Args[Index][1];
            ++Index;
            if (Index < Argc) {
                ParseIPAddress(Args[Index], (PSOCKADDR_INET)&Config->Address);
            } else {
                goto Done;
            }
        } else if (_wcsicmp(Args[Index], L"-p") == 0) {
            ++Index;
            if (Index < Argc) {
                SS_PORT(&Config->Address) = htons((USHORT)_wtoi(Args[Index]));
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
        } else {
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
    wprintf(L"Usage: tcphs <-c|-s IP> <-p port> [-o # of conns per core] [-a # pre-posted accetps]\n");
}

INT
__cdecl
wmain(
    INT Argc,
    WCHAR* Args[]
    )
{
    WSADATA WsaData;
    SYSTEM_INFO SystemInfo;
    INT Status = 1;
    DWORD Bytes;
    SOCKET Socket;

    WSAStartup(MAKEWORD(2, 2), &WsaData);

    GetSystemInfo(&SystemInfo);
    GlobalConfig =
        calloc(
            1,
            sizeof(GLOBAL_CONFIG) + sizeof(WORKER) * (SystemInfo.dwNumberOfProcessors - 1));
    if (GlobalConfig == NULL) {
        wprintf(L"Failed to allocate memory for GlobalConfig\n");
        goto Done;
    }

    if (!ParseCmd(Argc, Args, GlobalConfig)) {
        PrintUsage();
        goto Done;
    }

    GlobalConfig->NumProcs = GlobalConfig->Role == RoleClient ? SystemInfo.dwNumberOfProcessors : 1;

    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    Socket = socket(GlobalConfig->Address.ss_family, SOCK_STREAM, IPPROTO_TCP);
    Status =
        WSAIoctl(
            Socket,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &GuidConnectEx,
            sizeof(GuidConnectEx), &FnConnectEx, sizeof(FnConnectEx),
            &Bytes, NULL, NULL);
    if (Status == SOCKET_ERROR) {
        wprintf(L"WSAIoctl failed with error: %u\n", WSAGetLastError());
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
        wprintf(L"WSAIoctl failed with error: %u\n", WSAGetLastError());
        goto Done;
    }

    GlobalConfig->CompletionEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
    if (GlobalConfig->CompletionEvent == NULL) {
        wprintf(L"CreateEvent failed with error: %u\n", GetLastError());
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
    return Status;
}
