#pragma once

#define REAP_VERSION 001

enum class OperationType_t : uint16_t
{
    OPENPROCESS = 1,
    WRITEPROCESSMEMORY = 2,
    READPROCESSMEMORY = 3,
};

struct ReapRequest
{
    static const char magic[4] = "reap";
    uint8_t version;
    OperationType_t type;
};

struct ReapMemoryRequest : ReapRequest
{
    uint64_t startAddr;
    uint64_t endAddr;
    uint32_t totalBytesManipulated;
};

struct ReapWriteRequest : ReapMemoryRequest
{};

struct ReapReadRequest : ReapMemoryRequest
{
    char buffer[65535]; // should be dynamic, make sure this is at the end and we'll just cut if off
};


// Process Setup
struct ReapOpenProcessRequest : ReapRequest
{
    const char moduleName[64];
    const char processName[16]; // gets cut off
};