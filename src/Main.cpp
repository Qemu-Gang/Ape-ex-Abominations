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

std::atomic<int> uniquePid = 1024;

static void *ThreadSignature(const Signature *sig) {
    MTR_SCOPED_TRACE("Initialization", "ThreadedSignature");

    pid_t pid = ++uniquePid;

    try{
        WinProcess *desiredProcess = nullptr;
        uintptr_t desiredModuleBase = 0;
        uintptr_t desiredModuleSize = 0;

        WinContext ctx(pid);

        ctx.processList.Refresh();

        for (auto &i : ctx.processList) {
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
            default:          throw(errno);
        }
    }
    return r == 0;
}

static void* NewConnection( void *rawArg ){
    ssize_t r;
    int sock = *(int*)rawArg;
    free( rawArg );

    Logger::Log("New Connection (%d)!\n", sock);
    while( !IsClosed(sock) && running ){
        r = send(sock, "swag\n", 5, 0);
        if( r < 0 ) break;
        sleep(1);
    }
    Logger::Log("Connection Closed (%d)\n", sock);
    close(sock);


    return nullptr;
}

static void *MainThread(void *) {
    pid_t pid;
    int opt = true;
    int sock;
    int sockFlags;
    struct addrinfo hints = {};
    struct addrinfo *res = 0, *ai = 0, *ai_ipv4 = 0;
    int *newSock;


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

    Logger::Log("Main Loaded.\n");

    hints.ai_family = PF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    getaddrinfo( "0::0", "666", &hints, &res);

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

    /*
    Threading::InitThreads();
    auto t1 = Clock::now();


    MTR_BEGIN("Initialization", "InitCTX");
    WinContext ctx(pid);
    MTR_END("Initialization", "InitCTX");

    MTR_BEGIN("Initialization", "FindProcesses");
    ctx.processList.Refresh();
    for (auto &i : ctx.processList) {
        //Logger::Log("\nFound Process %s(PID:%ld)", i.proc.name, i.proc.pid);
        if (!strcasecmp(PROCNAME, i.proc.name)) {
            Logger::Log("\nFound Process %s(PID:%ld)", i.proc.name, i.proc.pid);
            PEB peb = i.GetPeb();
            short magic = i.Read<short>(peb.ImageBaseAddress);
            uintptr_t translatedBase = VTranslate(&i.ctx->process, i.proc.dirBase, peb.ImageBaseAddress);
            Logger::Log("\tWinBase:\t%p\tBase:\t%p\tQemuBase:\t%p\tMagic:\t%hx (valid: %hhx)\n", (void *) peb.ImageBaseAddress, (void *) i.proc.process,
                        (void *) translatedBase,
                        magic, (char) (magic == IMAGE_DOS_SIGNATURE));
            process = &i;

            for (auto &o : i.modules) {
                if (!strcasecmp(MODNAME, o.info.name)) {
                    Logger::Log("Found Module: (%s) - baseAddr(%p)\n", o.info.name, o.info.baseAddress);
                } else if (!strcasecmp(PROCFULLNAME, o.info.name)) {
                    Logger::Log("Found Module: (%s) - baseAddr(%p)\n", o.info.name, o.info.baseAddress);
                }
            }
        }
    }
    MTR_END("Initialization", "FindProcesses");

    if (!process) {
        Logger::Log("Could not Find Process/Base. Exiting...\n");
        goto quit;
    }


    auto t2 = Clock::now();
    printf("Initialization time: %lld ms\n", (long long) std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count());
    */


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
