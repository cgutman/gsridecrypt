#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>

#include <openssl/evp.h>

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <Mstcpip.h>

#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")

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

// This is specifically for the reliable send command
typedef struct enet_hdr
{
    unsigned short peer_id;
    unsigned short sent_time;
    unsigned char command;

    unsigned char channel_id;
    unsigned short seq_num;
    unsigned short data_len;
} ENET_HDR, *PENET_HDR;

typedef struct gs_ctl_input_hdr
{
    unsigned short type;
    unsigned short unused; // Moonlight doesn't send this field but Shield Hub does?
    unsigned int length;
    unsigned char data[ANYSIZE_ARRAY];
} GS_CTL_INPUT_HDR, *PGS_CTL_INPUT_HDR;


typedef struct gs_ctl_hdr
{
    unsigned short type;
    unsigned char data[ANYSIZE_ARRAY];
} GS_CTL_HDR, *PGS_CTL_HDR;

#pragma pack(pop)

char* hexStringToBytes(char* string)
{
    char* buf = (char*)malloc(strlen(string) / 2);
    for (unsigned int i = 0; i < strlen(string); i += 2) {
        char byteStr[3];

        strncpy(byteStr, &string[i], 2);

        buf[i / 2] = (char)strtoul(byteStr, NULL, 16);
    }
    return buf;
}

void printBuffer(unsigned short type, bool toServer, unsigned char* buffer, int len)
{
    time_t timer;
    char time_buffer[26];
    struct tm* tm_info;

    time(&timer);
    tm_info = localtime(&timer);

    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);

    printf("%s: %s: Type %04x: ", time_buffer, toServer ? "Client -> Server" : "Server -> Client", type);
    for (int i = 0; i < len; i++) {
        printf("%02x ", buffer[i]);
    }
    printf("\n");
    fflush(stdout);
}

int main(int argc, char* argv[])
{
    WSADATA startupData;

    if (argc != 3) {
        printf("Usage: gsridecrypt <local interface address> <ri key>\n");
        return -1;
    }

    WSAStartup(MAKEWORD(2, 2), &startupData);

    SOCKET s;

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

    EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();

    char* riKey = hexStringToBytes(argv[2]);
    unsigned char currentAesIv[16];

    // NB: The below parsing logic doesn't take enough precaution with untrusted input.
    // It's only designed for more quickly identifying changes in the GameStream
    // remote input protocol with a trusted server over a private connection.
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

        PENET_HDR enet = (PENET_HDR)(udp + 1);

        // Skip packets that aren't reliable sends on channel 0
        if (enet->command != 0x86 || enet->channel_id != 0) {
            continue;
        }

        PGS_CTL_HDR ctl = (PGS_CTL_HDR)(enet + 1);

        // Skip frame stats data
        if (ctl->type == 0x0207) {
            continue;
        }

        // Skip loss stats data
        if (ctl->type == 0x0201) {
            continue;
        }

        if (ctl->type == 0x0206) {
            PGS_CTL_INPUT_HDR input = (PGS_CTL_INPUT_HDR)(enet + 1);

            input->length = htonl(input->length);

            EVP_DecryptInit_ex(aes_ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
            EVP_CIPHER_CTX_ctrl(aes_ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL);
            EVP_DecryptInit_ex(aes_ctx, NULL, NULL, (const unsigned char*)riKey, currentAesIv);

            unsigned char plaintext[256];
            len = sizeof(plaintext);
            EVP_DecryptUpdate(aes_ctx, plaintext, &len, &input->data[16], input->length - 16); // Skip the tag

            printBuffer(input->type, udp->dest_portno == 47999, plaintext, len);

            if (input->length >= 16 + sizeof(currentAesIv)) {
                memcpy(currentAesIv,
                    &input->data[input->length - sizeof(currentAesIv)],
                    sizeof(currentAesIv));
            }
        }
        else {
            printBuffer(ctl->type, udp->dest_portno == 47999, (PUCHAR)ctl, len - ((PUCHAR)ctl - (PUCHAR)buffer));
        }
    }
}

