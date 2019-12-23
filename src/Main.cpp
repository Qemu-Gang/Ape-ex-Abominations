#include "vmread/hlapi/hlapi.h"
#include "utils/Logger.h"
#include "utils/minitrace.h"

#include "m0dular/utils/threading.h"
#include "m0dular/utils/pattern_scan.h"

#include <unistd.h> //getpid
#include <thread>
#include <atomic>
#include <csignal>
#include <numeric>
#include <thread>
#include <chrono>
#include <iostream>

#include <unistd.h>   //close
#include <arpa/inet.h>    //close
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h> //FD_SET, FD_ISSET, FD_ZERO macros
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>

#include "PacketStructure.h"
#include "Signatures.h"

/* Some Networking code pasted from jxh: https://stackoverflow.com/questions/25091148/single-tcp-ip-server-that-handles-multiple-clients-in-c */

static thread_t mainThread;

inline bool running = true;

#if (LMODE() == MODE_EXTERNAL())

int main() {
    while (running) {
        char c = (char) getchar();

        if (c == 'Q')
            break;
    }

    return 0;
}
#endif

typedef std::chrono::high_resolution_clock Clock;

static bool sigscanFailed = false;

static WinContext *ctx;

static void *ThreadSignature(const Signature *sig) {
    MTR_SCOPED_TRACE("Initialization", "ThreadedSignature");

    try{
        WinProcess *desiredProcess = nullptr;
        uintptr_t desiredModuleBase = 0;
        uintptr_t desiredModuleSize = 0;


        ctx->processList.Refresh();

        for (auto &i : ctx->processList) {
            if (!strcasecmp(sig->processName, i.proc.name)) {
                desiredProcess = &i;

                for (auto &o : i.modules) {
                    if (!strcasecmp(sig->moduleName, o.info.name)) {
                        desiredModuleBase = o.info.baseAddress;
                        desiredModuleSize = o.info.sizeOfModule;
                    }
                }
            }
        }

        if( !desiredProcess || !desiredModuleBase || !desiredModuleSize ){
            Logger::Log("Could not find one of the signature procs/modules! - proc(%s) - module(%s)\n"
                                "Found proc(%p) - moduleBase(%p) - moduleSize(%p)\n",
                        sig->processName, sig->moduleName, (void*)desiredProcess, (void*)desiredModuleBase, (void*)desiredModuleSize);
            sigscanFailed = true;
        }

        *sig->result = PatternScan::FindPattern(desiredProcess, sig->pattern, desiredModuleBase, (desiredModuleBase + desiredModuleSize));

        if (!*sig->result) {
            Logger::Log("Failed to find pattern {%s}\n", sig->pattern);
            sigscanFailed = true;
        }

    } catch (VMException &e) {
        Logger::Log("Failed to Init Ctx in ThreadSignature!\n");
        sigscanFailed = true;
        return nullptr;
    }

    return nullptr;
}

static bool IsClosed( int sock ){
    char x;
    interrupted:
    ssize_t r = ::recv(sock, &x, 1, MSG_DONTWAIT|MSG_PEEK);
    if (r < 0) {
        switch (errno) {
            case EINTR:       goto interrupted;
            case EWOULDBLOCK: break; /* empty rx queue */
            case ETIMEDOUT:   break; /* recv timeout */
            case ENOTCONN:    break; /* not connected yet */
            case ECONNRESET:  break; /* connection reset by peer. (closed program) */
            default:          Logger::Log("Connection Closed. Code(%d)\n", errno);
        }
    }
    return r == 0;
}

static void* NewConnection( void *raw_NewSock ){
    ssize_t r;
    int sock = *(int*)raw_NewSock;
    free( raw_NewSock );

    ReapRequestGeneric request;
    ReapRequestGeneric response;
    ReapOpenProcessRequest *openProcess;
    ReapErrorReport error = ReapErrorReport();

    WinProcess *process = nullptr;

    Logger::Log("New Connection (%d). Waiting for message.\n", sock);
    while( !IsClosed(sock) && running ){
        r = recv( sock, &request, sizeof(ReapRequestGeneric), 0 );
        if( r < 0 ){
            Logger::Log("Error receiving on open sock!(%d)\n", sock); // can happen when client alt-f4's
            break;
        } else if( r < sizeof(ReapPacketHeader) || ( strcmp( request.magic, "reap" ) != 0 ) ){
            Logger::Log("Invalid pkt header!(%d)\n", sock);
            r = snprintf( error.errorString, sizeof(error.errorString), "Invalid packet header.");
            error.errorStringLen = r;
            error.errorType = OperationType_t::PING;
            send( sock, &error, sizeof( ReapErrorReport ), 0 );
            continue;
        } else if( request.version != REAP_VERSION ){
            Logger::Log("Client version mismatch!(%d)\n", sock);
            r = snprintf( error.errorString, sizeof(error.errorString), "Version Mismatch, please update.");
            error.errorStringLen = r;
            error.errorType = OperationType_t::PING;
            send( sock, &error, sizeof( ReapErrorReport ), 0 );
            continue;
        } else {
            switch( request.type ){
                case OperationType_t::PING:
                    Logger::Log("Received ping packet. Responding...\n");
                    response.type = OperationType_t::PING;
                    r = send( sock, &response, sizeof(ReapPacketHeader), 0 );
                    break;
                case OperationType_t::OPENPROCESS:
                    process = nullptr;
                    ctx->processList.Refresh();
                    openProcess = (ReapOpenProcessRequest*)&request;

                    Logger::Log("Opening process (%s) for (%d)\n", openProcess->processName, sock);

                    for (auto &i : ctx->processList) {
                        if (!strcasecmp(openProcess->processName, i.proc.name)) {
                            Logger::Log("Found process (%s)\n", openProcess->processName);
                            process = &i;
                        }
                    }
                    if( !process ){
                        r = snprintf( error.errorString, sizeof(error.errorString), "Failed to find your process." );
                        error.errorStringLen = r;
                        error.errorType = OperationType_t::OPENPROCESS;
                        send( sock, &error, sizeof(ReapErrorReport), 0 );
                    } else {
                        openProcess = (ReapOpenProcessRequest*)&response;
                        openProcess->type = OperationType_t::OPENPROCESS;
                        snprintf( openProcess->processName, sizeof(openProcess->processName), "Process Set." ); // unnecessary, but why not
                        send( sock, openProcess, sizeof( ReapOpenProcessRequest ), 0 );
                    }
                    break;
                case OperationType_t::READPROCESSMEMORY:
                    if( !process ){
                        r = snprintf( error.errorString, sizeof(error.errorString), "You need to Open Process before you can read/write!");
                        error.errorStringLen = r;
                        error.errorType = OperationType_t::READPROCESSMEMORY;
                        send( sock, &error, sizeof(ReapErrorReport), 0 );
                    }
                    break;
                case OperationType_t::WRITEPROCESSMEMORY:
                    if( !process ){
                        r = snprintf( error.errorString, sizeof(error.errorString), "You need to Open Process before you can read/write!");
                        error.errorStringLen = r;
                        error.errorType = OperationType_t::WRITEPROCESSMEMORY;
                        send( sock, &error, sizeof(ReapErrorReport), 0 );
                    }

                    break;
                default:
                    /// Send back invalid packet
                    break;
            }
        }
        sleep(1);
    }
    Logger::Log("Connection Closed (%d)\n", sock);
    close(sock);


    return nullptr;
}

static void *MainThread(void *) {
    pid_t pid = getpid();
    int opt = true;
    int sock;
    int sockFlags;
    struct addrinfo hints = {};
    struct addrinfo *res = 0, *ai = 0, *ai_ipv4 = 0;
    int *newSock;

    Threading::InitThreads();



#if (LMODE() == MODE_EXTERNAL())
    FILE *pipe = popen("pidof qemu-system-x86_64", "r");
    fscanf(pipe, "%d", &pid);
    pclose(pipe);
#else
    pid = getpid();
#endif

#ifdef MTR_ENABLED
    Logger::Log("Initialize performance tracing...\n");
    mtr_init("/tmp/ReapProcessMemory.json");
    MTR_META_PROCESS_NAME("Reap");
#endif

    try{
        ctx = new WinContext( pid );
    } catch( VMException ex ){
        Logger::Log("VmRead Context Init failed(%d). Stopping.\n", ex.value);
        return nullptr;
    }

    Logger::Log("Main Loaded.\n");

    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    getaddrinfo( "0.0.0.0", "666", &hints, &res);

    for( ai = res; ai; ai = ai->ai_next ){
        if (ai->ai_family == PF_INET6) break;
        else if( ai->ai_family == PF_INET) ai_ipv4 = ai;
    }
    ai = ai ? ai : ai_ipv4;

    if( (sock = socket(ai->ai_family, SOCK_STREAM, 0)) == 0 ){
        Logger::Log("Failed to create socket\n");
        goto quit;
    }
    if( setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) ){
        Logger::Log("Failed to configure socket for multiple connections\n");
        goto quit;
    }
    if( (sockFlags = fcntl( sock, F_GETFL ) ) == -1 ){
        Logger::Log("Couldn't get socket flags!\n");
        goto quit;
    }
    // Set socket to non-blocking. This will prevent accept() from blocking
    // however read()/write() can now fail with error EWOULDBLOCK/EAGAIN(same value).
    if( fcntl( sock, F_SETFL, sockFlags | O_NONBLOCK ) == -1 ){
        Logger::Log("Couldn't set socket flags!\n");
        goto quit;
    }
    if( bind(sock, ai->ai_addr, ai->ai_addrlen) ){
        Logger::Log("Failed to bind socket\n");
        goto quit;
    }
    // Listen for up to 256 pending connections
    if( listen(sock, 256) < 0 ){
        Logger::Log("Failed to listen for connections\n");
        goto quit;
    }

    // Ignore broken pipe signal from send(). Default behavior is to end the program.
    signal(SIGPIPE, SIG_IGN);

    Logger::Log("Main Loop Started. Waiting For Connections...\n");


    newSock = (int*)malloc( sizeof(int) );

    while (running) {
        *newSock = accept(sock, 0, 0);

        if( *newSock == -1 ){
            if( errno == EWOULDBLOCK ){
                // No Pending Connections. Sleep for 5ms or so.

                usleep( 1000 * 5 );
                continue;
            } else {
                Logger::Log("Error accepting Connection!\n");
                goto quit;
            }
        } else {
            Threading::StartThread(NewConnection, newSock, false); // might want to detach here
            newSock = (int*)malloc( sizeof(int) );
        }
    }


    quit:
    Logger::Log("Main Loop Ended.\n");
    delete ctx;
    running = false;

    Threading::FinishQueue(true);
    Threading::EndThreads();

#ifdef MTR_ENABLED
    mtr_flush();
    mtr_shutdown();
#endif

    Logger::Log("Main Ended.\n");

    return nullptr;
}

static void __attribute__((constructor)) Startup() {
    mainThread = Threading::StartThread(MainThread, nullptr, false);
}

static void __attribute__((destructor)) Shutdown() {
    Logger::Log("Unloading...");

    running = false;

    Threading::JoinThread(mainThread, nullptr);

    Logger::Log("Done\n");
}
