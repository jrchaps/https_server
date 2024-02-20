#include <WinSock2.h>
#include <WS2tcpip.h>
#include <MSWSock.h>
#include "ntstatus.h"
#include <bcrypt.h>
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Bcrypt.lib")

#include "../../jrc_modules/modules_4/basic/basic.c"
#include "../../jrc_modules/modules_4/slice/slice.c"
#include "../../jrc_modules/modules_4/arena/arena.c"

typedef struct windows_client_ctx windows_client_ctx;
typedef struct server_ctx server_ctx;
typedef struct client_ctx client_ctx;
typedef struct process_client_ctx process_client_ctx;

server_ctx start(void);
process_client_ctx process_client(client_ctx, slice, u32);

struct server_ctx {
    size_t client_capacity;
    u32 cargo_capacity;
    char* port;
};

struct process_client_ctx {
    client_ctx client;
    u32 flags;
    slice cargo;
    slice filename;
};

struct windows_client_ctx {
    windows_client_ctx* next;
    client_ctx client;
    OVERLAPPED io_data;
    SOCKET socket;
    HANDLE file;
    u64 file_index;
    u32 flags;
    WSABUF cargo;
};