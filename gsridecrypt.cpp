#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <tlhelp32.h>
#include <DbgHelp.h>
#include <ProcessSnapshot.h>

#include <enet/protocol.h>

#include <openssl/evp.h>

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <Mstcpip.h>

#include <stdio.h>

#define DUMP_PATH "C:\\Windows\\Temp\\NvStreamer.dmp"

#define PREFIX_SUFFIX_LEN 2
#define KEY_LEN 16

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "Dbghelp.lib")

#pragma pack(push, 1)

// TCP/IP structs from https://github.com/Microsoft/Windows-classic-samples/blob/master/Samples/Win7Samples/netds/winsock/rcvall/iphdr.h

//
// IPv4 Header (without any IP options)
//
typedef struct ip_hdr
{
    unsigned char  ip_verlen;        // 4-bit IPv4 version
                                     // 4-bit header length (in 32-bit words)
    unsigned char  ip_tos;           // IP type of service
    unsigned short ip_totallength;   // Total length
    unsigned short ip_id;            // Unique identifier 
    unsigned short ip_offset;        // Fragment offset field
    unsigned char  ip_ttl;           // Time to live
    unsigned char  ip_protocol;      // Protocol(TCP,UDP etc)
    unsigned short ip_checksum;      // IP checksum
    unsigned int   ip_srcaddr;       // Source address
    unsigned int   ip_destaddr;      // Source address
} IPV4_HDR, *PIPV4_HDR;

//
// Define the UDP header 
//
typedef struct udp_hdr
{
    unsigned short src_portno;       // Source port no.
    unsigned short dest_portno;      // Dest. port no.
    unsigned short udp_length;       // Udp packet length
    unsigned short udp_checksum;     // Udp checksum
} UDP_HDR, *PUDP_HDR;

typedef struct gs_enc_ctl_hdr
{
    unsigned short encryptedType; // Always 0x0001
    unsigned short length;
    unsigned int seq; // Used for IV
    unsigned char tag[16]; // GCM authentication tag
} GS_ENC_CTL_HDR, *PGS_ENC_CTL_HDR;

typedef struct gs_ctl_hdr_v2
{
    unsigned short type;
    unsigned short payloadLength;
} GS_CTL_HDR_V2, *PGS_CTL_HDR_V2;

#pragma pack(pop)

unsigned char* hexStringToBytes(char* string)
{
    unsigned char* buf = (unsigned char*)malloc(strlen(string) / 2);
    for (unsigned int i = 0; i < strlen(string); i += 2) {
        char byteStr[3];

        strncpy(byteStr, &string[i], 2);

        buf[i / 2] = (unsigned char)strtoul(byteStr, NULL, 16);
    }
    return buf;
}

void printBuffer(unsigned short type, unsigned short length, bool toServer, unsigned char* buffer)
{
    time_t timer;
    char time_buffer[26];
    struct tm* tm_info;

    time(&timer);
    tm_info = localtime(&timer);

    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("%s: %s: Type %04x (Length: %d bytes): ", time_buffer, toServer ? "Client -> Server" : "Server -> Client", type, length);
    for (int i = 0; i < length; i++) {
        printf("%02x ", buffer[i]);
    }
    printf("\n");
    fflush(stdout);
}

unsigned char* readFileToBuffer(const char* filePath, size_t* fileSize = NULL) {
    FILE* file = fopen(filePath, "rb");
    if (!file) {
        fprintf(stderr, "Failed to open %s\n", filePath);
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    rewind(file);

    unsigned char* buf = (unsigned char*)malloc(size);
    fread(buf, 1, size, file);
    fclose(file);

    if (fileSize != NULL) {
        *fileSize = size;
    }

    return buf;
}

BOOL CALLBACK MiniDumpWriteDumpCallback(
    __in     PVOID CallbackParam,
    __in     const PMINIDUMP_CALLBACK_INPUT CallbackInput,
    __inout  PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
)
{
    switch (CallbackInput->CallbackType)
    {
    case IsProcessSnapshotCallback:
        CallbackOutput->Status = S_FALSE;
        break;
    }
    return TRUE;
}

void waitForNvStreamer() {
    bool foundNvStreamer = false;

    printf("Waiting for NvStreamer to start...");
    while (!foundNvStreamer) {
        // Poll each second for Nvstreamer.exe
        Sleep(1000);

        HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        PROCESSENTRY32 procEntry;
        Process32First(processSnapshot, &procEntry);

        // Find the PID of NvStreamer.exe
        do {
            if (strstr(procEntry.szExeFile, "nvstreamer.exe") != NULL) {
                printf("done\n");
                foundNvStreamer = true;
                break;
            }
        } while (Process32Next(processSnapshot, &procEntry));

        CloseHandle(processSnapshot);
    }
}

unsigned char* extractRiKey() {
    // Wait for NvStreamer to start before proceeding with RI key extraction
    waitForNvStreamer();

    printf("Attempting to extract RI key from current streaming session\n");

    char* keyString = NULL;
    char* streamerLogData = NULL;
    const char* linePrefix = "SESSION_PARAMETER_RI_ENCRYPTION_KEY: ";

    do {
        // Give NvStreamer some time to write these log entries
        Sleep(1000);

        // First open the NvStreamerCurrent.log to pull the prefix and suffix of the RI key
        streamerLogData = (char*)readFileToBuffer("C:\\ProgramData\\NVIDIA Corporation\\NvStream\\NvStreamerCurrent.log");
        if (streamerLogData == NULL) {
            continue;
        }

        // Find the log line that contains the redacted key
        keyString = strstr(streamerLogData, linePrefix);
        if (keyString == NULL) {
            fprintf(stderr, "No SESSION_PARAMETER_RI_ENCRYPTION_KEY found yet!\n");
            free(streamerLogData);
            continue;
        }
    } while (keyString == NULL);

    // Skip the line prefix
    keyString += strlen(linePrefix);

    // Terminate the key line at the first space
    *strstr(keyString, " ") = 0;

    // Extract the prefix (prior to the ..)
    char* keyPrefixStr = strtok(keyString, ".");
    unsigned char* keyPrefix = hexStringToBytes(keyPrefixStr);

    // Extract the suffix (after the ..)
    char* keySuffixStr = strtok(NULL, ".");
    unsigned char* keySuffix = hexStringToBytes(keySuffixStr);

    printf("Found redacted RI key in NvStreamer log: %02X%02X ... %02X%02X\n",
        keyPrefix[0], keyPrefix[1],
        keySuffix[0], keySuffix[1]);

    free(streamerLogData);

    HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    PROCESSENTRY32 procEntry;
    Process32First(processSnapshot, &procEntry);

    // Find the PID of NvStreamer.exe
    do {
        if (strstr(procEntry.szExeFile, "nvstreamer.exe") != NULL) {
            HANDLE processHandle = OpenProcess(GENERIC_ALL, FALSE, procEntry.th32ProcessID);
            if (processHandle == NULL) {
                fprintf(stderr, "Unable to open handle to nvstreamer.exe\n");
                exit(-1);
            }

            printf("Found nvstreamer.exe with PID %d\n", procEntry.th32ProcessID);

            // Create a dump file
            HANDLE dumpFileHandle = CreateFileA(DUMP_PATH, GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_ALWAYS, 0, NULL);
            if (dumpFileHandle == INVALID_HANDLE_VALUE) {
                fprintf(stderr, "Failed to create dump file: %d\n", GetLastError());
                exit(-1);
            }

            printf("Capturing a snapshot of nvstreamer...");
            HPSS pssSnapshot;
            DWORD error = PssCaptureSnapshot(processHandle, PSS_CAPTURE_VA_CLONE | PSS_CREATE_BREAKAWAY, 0, &pssSnapshot);
            if (error != NO_ERROR) {
                fprintf(stderr, "Failed to snapshot nvstreamer.exe: %d\n", error);
                exit(-1);
            }
            printf("done\n");

            printf("Dumping NvStreamer.exe process memory from snapshot...");
            MINIDUMP_CALLBACK_INFORMATION callbackInfo;
            callbackInfo.CallbackRoutine = MiniDumpWriteDumpCallback;
            callbackInfo.CallbackParam = NULL;
            if (!MiniDumpWriteDump((HANDLE)pssSnapshot, procEntry.th32ProcessID, dumpFileHandle, MiniDumpWithPrivateReadWriteMemory, NULL, NULL, &callbackInfo)) {
                fprintf(stderr, "Failed to write nvstreamer.exe dump: %x\n", GetLastError());
                exit(-1);
            }
            printf("done\n");

            PssFreeSnapshot(GetCurrentProcess(), pssSnapshot);
            CloseHandle(processHandle);
            CloseHandle(dumpFileHandle);

            // Search the dump file for the prefix and suffix
            size_t dumpSize;
            unsigned char* dumpData = readFileToBuffer(DUMP_PATH, &dumpSize);
            for (size_t j = 0; j < dumpSize - KEY_LEN; j++) {
                // Check for the prefix to match
                if (memcmp(keyPrefix, &dumpData[j], PREFIX_SUFFIX_LEN) == 0) {
                    // Check for the suffix to match
                    if (memcmp(keySuffix, &dumpData[j + KEY_LEN - PREFIX_SUFFIX_LEN], PREFIX_SUFFIX_LEN) == 0) {
                        // Found it!
                        unsigned char* key = (unsigned char*)malloc(KEY_LEN);
                        memcpy(key, &dumpData[j], KEY_LEN);

                        printf("RI Key: ");
                        for (int k = 0; k < KEY_LEN; k++) {
                            printf("%02X", key[k]);
                        }
                        printf("\n");

                        free(dumpData);
                        return key;
                    }
                }
            }

            fprintf(stderr, "No matching key found in NvStreamer.exe memory!\n");
            free(dumpData);
            exit(-1);
        }
    } while (Process32Next(processSnapshot, &procEntry));

    fprintf(stderr, "NvStreamer.exe is not running!\n");
    exit(-1);
}

typedef struct _data_entry {
    struct _data_entry* next;

    bool toServer;
    GS_ENC_CTL_HDR hdr;
    // Payload data
} DATA_ENTRY, *PDATA_ENTRY;

static HANDLE g_DataReadyEvent;
static CRITICAL_SECTION g_DataListLock;
static PDATA_ENTRY g_DataListHead;
static PDATA_ENTRY g_DataListTail;

DWORD WINAPI DecryptionThreadProc(LPVOID) {
    EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();

    // While the extraction is happening, early packets
    // will queue up so we don't miss any.
    unsigned char* riKey = extractRiKey();

    for (;;) {
        WaitForSingleObject(g_DataReadyEvent, INFINITE);

        EnterCriticalSection(&g_DataListLock);
        PDATA_ENTRY dataEntry = g_DataListHead;
        if (g_DataListHead == nullptr) {
            g_DataListTail = nullptr;
            ResetEvent(g_DataReadyEvent);
            LeaveCriticalSection(&g_DataListLock);
            continue;
        }
        g_DataListHead = dataEntry->next;
        if (g_DataListHead == nullptr) {
            g_DataListTail = nullptr;
            ResetEvent(g_DataReadyEvent);
        }
        LeaveCriticalSection(&g_DataListLock);

        PGS_ENC_CTL_HDR encCtl = (PGS_ENC_CTL_HDR)&dataEntry->hdr;

        unsigned char iv[16] = {};
        iv[0] = (unsigned char)encCtl->seq;

        EVP_CIPHER_CTX_reset(aes_ctx);
        EVP_DecryptInit_ex(aes_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
        EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL);
        EVP_DecryptInit_ex(aes_ctx, NULL, NULL, (const unsigned char*)riKey, iv);

        unsigned char plaintext[1024];
        int len = encCtl->length - sizeof(encCtl->seq) - sizeof(encCtl->tag);
        EVP_DecryptUpdate(aes_ctx, plaintext, &len, (unsigned char*)(encCtl + 1), len);

        EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_TAG, sizeof(encCtl->tag), encCtl->tag);

        if (EVP_DecryptFinal_ex(aes_ctx, plaintext, &len) != 1) {
            printf("Decryption failed!\n");
            DebugBreak();
            free(dataEntry);
            continue;
        }

        PGS_CTL_HDR_V2 ctl = (PGS_CTL_HDR_V2)plaintext;

        printBuffer(ctl->type, sizeof(*ctl) + ctl->payloadLength, dataEntry->toServer, plaintext);
        free(dataEntry);
    }
}

int main(int argc, char* argv[])
{
    WSADATA startupData;

    if (argc != 2) {
        printf("Usage: gsridecrypt <local interface address>\n");
        return -1;
    }

    WSAStartup(MAKEWORD(2, 2), &startupData);

    SOCKET s;

    g_DataReadyEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    InitializeCriticalSection(&g_DataListLock);

    s = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (s == INVALID_SOCKET) {
        printf("socket() failed: %d\n", WSAGetLastError());
        return -1;
    }

    struct sockaddr_in sin;
    int sinLen;

    RtlZeroMemory(&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.S_un.S_addr = inet_addr(argv[1]);
    int err = bind(s, (sockaddr*)&sin, sizeof(sin));
    if (err == SOCKET_ERROR) {
        printf("bind() failed: %d\n", WSAGetLastError());
        return -1;
    }

    DWORD rcvAllVal = RCVALL_IPLEVEL;
    DWORD bytesReturned;
    err = WSAIoctl(s, SIO_RCVALL, &rcvAllVal, sizeof(rcvAllVal), NULL, 0, &bytesReturned, NULL, NULL);
    if (err == SOCKET_ERROR) {
        printf("WSAIoctl() failed: %d\n", WSAGetLastError());
        return -1;
    }

    CreateThread(NULL, 0, DecryptionThreadProc, NULL, 0, NULL);

    // NB: The below parsing logic doesn't take enough precaution with untrusted input.
    // It's only designed for more quickly identifying changes in the GameStream
    // protocol with a trusted server over a private connection.
    char buffer[1500];
    for (;;) {
        sinLen = sizeof(sin);
        int len = recvfrom(s, buffer, sizeof(buffer), 0, (sockaddr*)&sin, &sinLen);
        if (len < 0 && WSAGetLastError() != WSAEMSGSIZE) {
            printf("recvfrom() failed: %d\n", WSAGetLastError());
            return -1;
        }
        else if (len < 0) {
            // Packet too large is fine
            continue;
        }

        PIPV4_HDR ip = (PIPV4_HDR)buffer;

        // Skip non-UDP traffic
        if (ip->ip_protocol != IPPROTO_UDP) {
            continue;
        }

        PUDP_HDR udp = (PUDP_HDR)(ip + 1);

        udp->src_portno = htons(udp->src_portno);
        udp->dest_portno = htons(udp->dest_portno);
        udp->udp_length = htons(udp->udp_length);
        udp->udp_checksum = htons(udp->udp_checksum);

        // Skip non-ENET traffic
        if (udp->dest_portno != 47999 && udp->src_portno != 47999) {
            continue;
        }

        // There is a transport layer protocol header that we want to skip
        ENetProtocolHeader* enetProtoHeader = (ENetProtocolHeader*)(udp + 1);

        // The application layer header starts here
        ENetProtocolCommandHeader* enetCmdHdr = (ENetProtocolCommandHeader*)(enetProtoHeader + 1);

        // Skip packets that aren't reliable sends on channel 0
        if (enetCmdHdr->command != 0x86 || enetCmdHdr->channelID != 0) {
            continue;
        }

        ENetProtocolSendReliable* enetRelHdr = (ENetProtocolSendReliable*)enetCmdHdr;

        PGS_ENC_CTL_HDR encCtl = (PGS_ENC_CTL_HDR)(enetRelHdr + 1);

        if (encCtl->encryptedType != 0x0001) {
            printf("Unknown packet type: 0x%04x\n", encCtl->encryptedType);
            continue;
        }

        int payloadLength = encCtl->length - sizeof(encCtl->seq) - sizeof(encCtl->tag);
        PDATA_ENTRY dataEntry = (PDATA_ENTRY)malloc(sizeof(*dataEntry) + payloadLength);

        dataEntry->next = nullptr;
        dataEntry->toServer = (udp->dest_portno == 47999);
        RtlCopyMemory(&dataEntry->hdr, encCtl, sizeof(*encCtl) + payloadLength);

        EnterCriticalSection(&g_DataListLock);
        if (g_DataListTail == nullptr) {
            g_DataListHead = dataEntry;
        }
        else {
            g_DataListTail->next = dataEntry;
        }
        g_DataListTail = dataEntry;
        LeaveCriticalSection(&g_DataListLock);
        SetEvent(g_DataReadyEvent);
    }
}

