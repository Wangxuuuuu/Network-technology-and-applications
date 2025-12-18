/*
 *  NPcap 简化路由器程序
 * 本程序使用 NPcap 库实现一个简化的网络路由器，支持 IPv4 数据包转发、ARP 缓存管理和 ICMP Echo 响应。
 * 主要功能包括：
 * - 捕获网络数据包
 * - 解析以太网、IPv4 和 ARP 协议
 * - 路由查找和数据包转发
 * - ARP 请求/响应处理
 * - ICMP Echo Request/Reply 处理
 * - 路由表和 ARP 缓存管理
 *
 * 编译环境：Windows + MinGW/GCC + NPcap
 * 我们的编译命令是:
 * g++ lab5/version13.cpp -o bin/version13.exe -I Include -L Lib/x64 -lPacket -lwpcap -lws2_32 -liphlpapi -fexec-charset=UTF-8 -finput-charset=UTF-8
 * 其中我们使用的不是g++吗?为什么是MinGW/GCC?
 * 回答: 因为MinGW是Windows平台上的GCC编译器集合, 它允许我们在Windows上使用GCC编译C++代码. NPcap是一个网络捕获库, 提供了类似于libpcap的功能, 但专门为Windows设计. 通过将MinGW/GCC与NPcap结合使用, 我们能够在Windows环境下开发和编译网络相关的应用程序.
 * g++与MinGW/GCC的关系:
 * g++是GNU编译器集合(GCC)中的C++编译器. MinGW(GNU的Windows端口)包含了GCC工具链, 包括g++. 因此, 当我们在Windows上使用MinGW时, 实际上是在使用GCC中的g++来编译C++代码.
 */

#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <csignal>
#include <atomic>
#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <locale> // 设置中文(utf-8)输出
#include <vector>
#include <array>
#include <sstream> // 用于 IP 字符串转换
#include <map> // 用于 ARP 缓存 map
#include <chrono> // 用于超时等待
#include <thread> // 用于睡眠等待
#include <mutex> // 用于线程安全

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

using namespace std;

// ========== Ethernet Header ==========
// 以太网帧头部结构体，定义了目的MAC、源MAC和以太网类型
#pragma pack(push, 1)
struct EthernetHeader {
    unsigned char dest_mac[6];    // 目的MAC地址
    unsigned char src_mac[6];     // 源MAC地址
    unsigned short ether_type;    // 以太网类型 (0x0800=IPv4, 0x0806=ARP, etc.)
};
#pragma pack(pop)

// ========== IPv4 Header ==========
// IPv4 数据包头部结构体，包含版本、长度、TTL、协议等字段
#pragma pack(push, 1)
struct IpHeader {
    unsigned char ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
    unsigned char tos;            // 服务类型
    unsigned short total_len;     // 总长度
    unsigned short id;            // 标识
    unsigned short frag_offset;   // 标志位 (3 bits) + 片偏移 (13 bits)
    unsigned char ttl;            // 生存时间 (TTL)
    unsigned char protocol;       // 协议 (1=ICMP, 6=TCP, 17=UDP)
    unsigned short checksum;      // 首部校验和
    unsigned int src_addr;        // 源IP地址
    unsigned int dst_addr;        // 目的IP地址
};
#pragma pack(pop)

// ========== ICMP Header ==========
// ICMP 头部结构体，用于处理 ICMP Echo Request 和 Reply
#pragma pack(push, 1)
struct IcmpHeader {
    unsigned char type;        // 类型 (8=Echo Request, 0=Echo Reply)
    unsigned char code;        // 代码
    unsigned short checksum;   // 校验和
    unsigned short id;         // 标识符 (通常与进程ID相关)
    unsigned short sequence;   // 序列号
};
#pragma pack(pop)

// ========== ARP Packet ==========
// ARP 数据包结构体，用于地址解析协议
#pragma pack(push, 1)
struct ArpPacket {
    unsigned short htype;      // 硬件类型 (1=以太网)
    unsigned short ptype;      // 协议类型 (0x0800=IPv4)
    unsigned char hlen;        // 硬件地址长度 (6 for MAC)
    unsigned char plen;        // 协议地址长度 (4 for IPv4)
    unsigned short oper;       // 操作 (1=Request, 2=Reply)
    unsigned char sha[6];      // 发送方硬件地址 (MAC)
    unsigned char spa[4];      // 发送方协议地址 (IP)
    unsigned char tha[6];      // 目标硬件地址 (MAC)
    unsigned char tpa[4];      // 目标协议地址 (IP)
};
#pragma pack(pop)

// ========== Route Entry ==========
// 路由表条目结构体，定义网络、掩码和网关
struct RouteEntry {
    array<unsigned char, 4> network;  // 网络地址
    array<unsigned char, 4> netmask;  // 子网掩码
    array<unsigned char, 4> gateway;  // 网关地址
    bool is_default = false;          // 是否为默认路由
    string to_string() const {
        stringstream ss;
        ss << (int)network[0] << "." << (int)network[1] << "." << (int)network[2] << "." << (int)network[3] << "/" << (int)netmask[0] << "." << (int)netmask[1] << "." << (int)netmask[2] << "." << (int)netmask[3] << " -> " << (int)gateway[0] << "." << (int)gateway[1] << "." << (int)gateway[2] << "." << (int)gateway[3];
        return ss.str();
    }
};

// ========== ARP Cache Entry ==========
// ARP 缓存条目结构体，用于存储 IP 到 MAC 的映射
// 前向声明
string ip_to_string(const unsigned char ip[4]);
string mac_to_string(const unsigned char* mac);

struct ArpCacheEntry {
    array<unsigned char, 4> ip;                    // IP 地址
    array<unsigned char, 6> mac;                   // MAC 地址
    chrono::steady_clock::time_point last_update;  // 最后更新时间
    bool valid = true;                             // 是否有效
    string to_string() const {                     // 转换为字符串表示
        stringstream ss;
        ss << ip_to_string(ip.data()) << " -> " << mac_to_string(mac.data());
        return ss.str();
    }
};

// ========== Global Variables ==========
// 全局变量定义，用于程序状态管理
atomic<bool> g_stop_capture(false);         // 停止捕获标志
volatile sig_atomic_t g_user_interrupted = 0; // 用户中断标志
pcap_t* g_handle = nullptr;                 // NPcap 句柄
vector<array<unsigned char, 4>> local_ips_all; // 本机所有 IP 地址
vector<RouteEntry> routing_table;           // 路由表
unsigned char g_local_mac[6];               // 本机 MAC 地址
map<array<unsigned char, 4>, ArpCacheEntry> arp_cache; // ARP 缓存
mutex arp_cache_mutex;                      // ARP 缓存互斥锁

// ========== Signal Handler ==========
// 信号处理函数，用于处理 Ctrl+C 中断信号，停止数据包捕获
void signal_handler(int signum) {
    cout << "\n收到中断信号，停止捕获..." << endl;
    g_stop_capture = true;
    g_user_interrupted = 1;
    if (g_handle) {
        pcap_breakloop(g_handle);  // 停止 pcap_loop
    }
}

// ========== Utility Functions ==========
// 工具函数：将 MAC 地址转换为字符串格式
string mac_to_string(const unsigned char* mac) {
    char buf[18];
    sprintf_s(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return string(buf);
}

// 工具函数：将 IP 地址（字节数组）转换为字符串格式
string ip_to_string(const unsigned char ip[4]) {
    stringstream ss;
    ss << (int)ip[0] << "." << (int)ip[1] << "." << (int)ip[2] << "." << (int)ip[3];
    return ss.str();
}

// 工具函数：将 IP 地址（uint）转换为字符串格式
string ip_to_string_uint(unsigned int ip_uint) {
    unsigned char* ip_bytes = (unsigned char*)&ip_uint;
    return ip_to_string(ip_bytes);
}

// 工具函数：根据以太网类型返回协议名称
string get_ethertype_name(unsigned short ether_type) {
    switch (ntohs(ether_type)) {
    case 0x0800: return "IPv4";
    case 0x0806: return "ARP";
    case 0x86DD: return "IPv6";
    case 0x8100: return "VLAN";
    default: return "Unknown";
    }
}

// ========== IP Routing Lookup ==========
// 路由查找函数：根据目的 IP 查找最佳路由（最长前缀匹配）
RouteEntry* find_route(unsigned char dest_ip[4]) {
    RouteEntry* best_match = nullptr;
    int longest_prefix_len = -1;
    for (auto& route : routing_table) {
        bool match = true;
        for (int i = 0; i < 4; ++i) {
            if ((dest_ip[i] & route.netmask[i]) != (route.network[i] & route.netmask[i])) {
                match = false;
                break;
            }
        }
        if (match) {
            int prefix_len = 0;
            for (int i = 0; i < 4; ++i) {
                unsigned char mask = route.netmask[i];
                while (mask) {
                    prefix_len += (mask & 1);
                    mask >>= 1;
                }
            }
            if (prefix_len > longest_prefix_len) {
                longest_prefix_len = prefix_len;
                best_match = &route;
            }
        }
    }
    return best_match;
}

// ========== Checksum Calculations ==========
// 计算 IP 头部校验和
unsigned short calculate_checksum(unsigned short* buf, int nwords) {
    unsigned long sum = 0;
    for (; nwords > 0; nwords--) {
        sum += *buf++;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// 计算 ICMP 校验和
unsigned short calculate_icmp_checksum(unsigned short* buf, int nbytes) {
    unsigned long sum = 0;
    unsigned short* w = buf;
    int nleft = nbytes;
    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1) {
        unsigned short tmp = 0;
        *(unsigned char*)(&tmp) = *(unsigned char*)w;
        sum += tmp;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// ========== ARP Cache Functions ==========
// 在 ARP 缓存中查找 MAC 地址
bool find_mac_in_cache(const unsigned char ip[4], unsigned char mac_out[6]) {
    lock_guard<mutex> lock(arp_cache_mutex);  // 线程安全锁
    array<unsigned char, 4> key_ip;
    memcpy(key_ip.data(), ip, 4);
    auto it = arp_cache.find(key_ip);
    if (it != arp_cache.end() && it->second.valid) {
        memcpy(mac_out, it->second.mac.data(), 6);
        return true;
    }
    return false;
}

// 更新或添加 ARP 缓存条目
void update_or_add_cache_entry(const unsigned char ip[4], const unsigned char mac[6]) {
    lock_guard<mutex> lock(arp_cache_mutex);  // 线程安全锁
    array<unsigned char, 4> key_ip;
    array<unsigned char, 6> value_mac;
    memcpy(key_ip.data(), ip, 4);
    memcpy(value_mac.data(), mac, 6);
    ArpCacheEntry entry;
    entry.ip = key_ip;
    entry.mac = value_mac;
    entry.last_update = chrono::steady_clock::now();
    entry.valid = true;
    arp_cache[key_ip] = entry;
    cout << "\[ARP缓存] 更新: " << entry.to_string() << endl;
}

// 打印 ARP 缓存表
void print_arp_cache() {
    lock_guard<mutex> lock(arp_cache_mutex);  // 线程安全锁
    cout << "\n======= ARP 缓存表 =======\n";
    if (arp_cache.empty()) {
        cout << "(空)\n";
    }
    else {
        for (const auto& pair : arp_cache) {
            const auto& entry = pair.second;
            if (entry.valid) {
                cout << entry.to_string() << endl;
            }
        }
    }
    cout << "========================\n";
}

// ========== Packet Handlers ==========
// 检查 IP 是否为本机 IP
bool is_local_ip(const unsigned char ip[4]);

// ARP 等待相关全局变量
atomic<bool> g_waiting_for_arp_reply(false);  // 是否正在等待 ARP 回复
unsigned char g_arp_query_ip[4];              // 查询的 IP
unsigned char g_arp_query_result_mac[6];      // 查询结果 MAC

// ARP 回复等待处理器：用于处理 ARP 回复
void arp_reply_waiter_handler(u_char* user, const pcap_pkthdr* header, const u_char* data) {
    if (header->caplen < sizeof(EthernetHeader) + sizeof(ArpPacket)) return;
    const EthernetHeader* eth = (const EthernetHeader*)data;
    if (ntohs(eth->ether_type) != 0x0806) return;
    const ArpPacket* arp = (const ArpPacket*)(data + sizeof(EthernetHeader));
    if (ntohs(arp->oper) == 2 && memcmp(arp->spa, g_arp_query_ip, 4) == 0) {
        memcpy(g_arp_query_result_mac, arp->sha, 6);
        g_waiting_for_arp_reply = false;
    }
}

// 发送 ARP 请求并等待回复
bool send_arp_and_wait_reply(pcap_t* handle, const unsigned char local_mac[6], const unsigned char local_ip[4],
    const unsigned char target_ip[4], unsigned char result_mac[6], int timeout_ms = 2000) {
    // 构造 ARP 请求帧
    unsigned char frame[42] = { 0 };
    EthernetHeader* eth = (EthernetHeader*)frame;
    ArpPacket* arp = (ArpPacket*)(frame + sizeof(EthernetHeader));
    memset(eth->dest_mac, 0xFF, 6);  // 广播 MAC
    memcpy(eth->src_mac, local_mac, 6);
    eth->ether_type = htons(0x0806);  // ARP
    arp->htype = htons(1);  // 以太网
    arp->ptype = htons(0x0800);  // IPv4
    arp->hlen = 6;
    arp->plen = 4;
    arp->oper = htons(1);  // Request
    memcpy(arp->sha, local_mac, 6);
    memcpy(arp->spa, local_ip, 4);
    memset(arp->tha, 0, 6);
    memcpy(arp->tpa, target_ip, 4);
    if (pcap_sendpacket(handle, frame, sizeof(frame)) != 0) {
        cerr << "\[ARP] 发送请求失败: " << pcap_geterr(handle) << endl;
        return false;
    }
    // 等待回复
    g_waiting_for_arp_reply = true;
    memcpy(g_arp_query_ip, target_ip, 4);
    memset(g_arp_query_result_mac, 0, 6);
    auto start_time = chrono::steady_clock::now();
    while (g_waiting_for_arp_reply.load() && !g_user_interrupted) {
        int res = pcap_dispatch(handle, 1, arp_reply_waiter_handler, nullptr);
        if (res == -1) {
            cerr << "\[ARP] pcap_dispatch 错误: " << pcap_geterr(handle) << endl;
            break;
        }
        if (!g_waiting_for_arp_reply.load()) {
            break;
        }
        this_thread::sleep_for(chrono::milliseconds(10));
        auto now = chrono::steady_clock::now();
        if (chrono::duration_cast<chrono::milliseconds>(now - start_time).count() > timeout_ms) {
            cout << "\[ARP] 等待超时，未收到回复。" << endl;
            return false;
        }
    }
    if (g_user_interrupted) {
        cout << "\[ARP] 等待被用户中断。" << endl;
        return false;
    }
    if (!g_waiting_for_arp_reply.load()) {
        memcpy(result_mac, g_arp_query_result_mac, 6);
        update_or_add_cache_entry(target_ip, result_mac);
        return true;
    }
    cout << "\[ARP] 等待结束，未收到回复。" << endl;
    return false;
}

// 处理 ICMP Echo Request，构造并发送 Echo Reply
void handle_icmp_echo_request(const u_char* packet_data, int packet_len) {
    // 检查数据包长度
    if (packet_len < sizeof(EthernetHeader) + sizeof(IpHeader) + sizeof(IcmpHeader)) {
        cout << " \[ICMP] 数据包太短，无法处理为 Echo Request." << endl;
        return;
    }
    // 解析头部
    const EthernetHeader* eth_header = (const EthernetHeader*)packet_data;
    const IpHeader* ip_header = (const IpHeader*)(packet_data + sizeof(EthernetHeader));
    const IcmpHeader* icmp_header = (const IcmpHeader*)((const char*)ip_header + (ip_header->ver_ihl & 0x0F) * 4);
    // 检查是否为 Echo Request
    if (icmp_header->type != 8 || icmp_header->code != 0) {
        cout << " \[ICMP] 收到非 Echo Request 的 ICMP 包 (Type: " << (int)icmp_header->type << ", Code: " << (int)icmp_header->code << ")." << endl;
        return;
    }
    cout << " \[ICMP] 收到 Echo Request，正在构造 Reply..." << endl;
    // 构造回复数据包
    vector<u_char> reply_buffer(packet_len);
    memcpy(reply_buffer.data(), packet_data, packet_len);
    EthernetHeader* reply_eth = (EthernetHeader*)reply_buffer.data();
    IpHeader* reply_ip = (IpHeader*)(reply_buffer.data() + sizeof(EthernetHeader));
    IcmpHeader* reply_icmp = (IcmpHeader*)((char*)reply_ip + (reply_ip->ver_ihl & 0x0F) * 4);
    // 交换 MAC 地址
    unsigned char temp_mac[6];
    memcpy(temp_mac, reply_eth->dest_mac, 6);
    memcpy(reply_eth->dest_mac, reply_eth->src_mac, 6);
    memcpy(reply_eth->src_mac, temp_mac, 6);
    // 交换 IP 地址
    unsigned int temp_ip = reply_ip->dst_addr;
    reply_ip->dst_addr = reply_ip->src_addr;
    reply_ip->src_addr = temp_ip;
    // 设置 ICMP 类型为 Reply
    reply_icmp->type = 0; // Echo Reply
    reply_icmp->checksum = 0;
    // 计算 ICMP 校验和
    int icmp_total_len = ntohs(reply_ip->total_len) - (reply_ip->ver_ihl & 0x0F) * 4;
    reply_icmp->checksum = calculate_icmp_checksum((unsigned short*)reply_icmp, icmp_total_len);
    // 计算 IP 校验和
    reply_ip->checksum = 0;
    reply_ip->checksum = calculate_checksum((unsigned short*)reply_ip, (reply_ip->ver_ihl & 0x0F) * 4 / 2);
    // 发送回复
    if (pcap_sendpacket(g_handle, reply_buffer.data(), packet_len) == 0) {
        cout << " \[ICMP] Echo Reply 已发送给 " << ip_to_string((unsigned char*)&reply_ip->dst_addr) << endl;
    }
    else {
        cerr << " \[ICMP] 发送 Echo Reply 失败: " << pcap_geterr(g_handle) << endl;
    }
}

// 主数据包处理函数：处理捕获到的网络数据包
void packet_handler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet_data) {
    static int packet_count = 0;  // 数据包计数器
    packet_count++;
    // 检查数据包长度
    if (header->caplen < sizeof(EthernetHeader)) {
        cout << "\[" << setw(4) << packet_count << "] 数据包过小，无法解析" << endl;
        return;
    }
    // 解析以太网头部
    const EthernetHeader* eth_header = (const EthernetHeader*)packet_data;
    unsigned short ether_type = ntohs(eth_header->ether_type);
    // 忽略自己发送的数据包
    if (memcmp(eth_header->src_mac, g_local_mac, 6) == 0) {
        packet_count--;
        return;
    }
    // 处理 IPv4 数据包
    if (ether_type == 0x0800) { // IPv4
        if (header->caplen < sizeof(EthernetHeader) + sizeof(IpHeader)) {
            cout << "\[" << setw(4) << packet_count << "]\[IPv4] IP头部过短" << endl;
            return;
        }
        const IpHeader* ip_header = (const IpHeader*)(packet_data + sizeof(EthernetHeader));
        unsigned char src_ip[4], dst_ip[4];
        memcpy(src_ip, &(ip_header->src_addr), 4);
        memcpy(dst_ip, &(ip_header->dst_addr), 4);
        cout << "\[" << setw(4) << packet_count << "]\[IPv4] ";
        cout << "源IP: " << ip_to_string(src_ip);
        cout << " -> 目的IP: " << ip_to_string(dst_ip);
        cout << " | TTL=" << (int)ip_header->ttl << " | 协议=" << (int)ip_header->protocol;
        // 检查是否为本机 IP
        if (is_local_ip(dst_ip)) {
            cout << " (本机接收)" << endl;
            if (ip_header->protocol == 1) { // ICMP
                handle_icmp_echo_request(packet_data, header->caplen);
                return;
            }
            else {
                cout << " \[本机] 收到发给本机的非ICMP包 (协议 " << (int)ip_header->protocol << ")，丢弃。" << endl;
                return;
            }
        }
        else { // 转发逻辑
            RouteEntry* route = find_route(dst_ip);
            if (route) {
                cout << " (下一跳: " << ip_to_string(route->gateway.data()) << ")" << endl;
                // TTL 检查
                if (ip_header->ttl <= 1) {
                    cout << " \[转发] TTL 已耗尽，丢弃数据包" << endl;
                    return;
                }
                // 构造新数据包
                vector<u_char> new_packet(header->caplen);
                memcpy(new_packet.data(), packet_data, header->caplen);
                EthernetHeader* new_eth = (EthernetHeader*)new_packet.data();
                IpHeader* new_ip = (IpHeader*)(new_packet.data() + sizeof(EthernetHeader));
                new_ip->ttl--;  // 减少 TTL
                new_ip->checksum = 0;
                new_ip->checksum = calculate_checksum((unsigned short*)new_ip, (new_ip->ver_ihl & 0x0F) * 4 / 2);
                cout << " \[转发] TTL -> " << (int)new_ip->ttl << endl;
                // ARP 查询逻辑
                unsigned char next_hop_mac[6];
                const unsigned char* next_hop_ip = route->gateway.data();
                
                // 判断是否为直接连接的主机
                bool is_directly_connected_host = false;
                const unsigned char* arp_local_ip_for_direct = nullptr;
                for (const auto& local_ip_item : local_ips_all) {
                    bool same_subnet_dst = true, same_subnet_local = true;
                    for (int i = 0; i < 4; ++i) {
                        if ((local_ip_item[i] & route->netmask[i]) != (dst_ip[i] & route->netmask[i])) same_subnet_dst = false;
                        if ((local_ip_item[i] & route->netmask[i]) != (route->network[i] & route->netmask[i])) same_subnet_local = false;
                    }
                    if (same_subnet_dst && same_subnet_local) {
                        is_directly_connected_host = true;
                        arp_local_ip_for_direct = local_ip_item.data();
                        break;
                    }
                }
                // 确定 ARP 查询的目标 IP 和本地 IP
                const unsigned char* arp_target_ip = nullptr;
                const unsigned char* arp_local_ip_final = nullptr;
                if (is_directly_connected_host && arp_local_ip_for_direct) {
                    arp_target_ip = dst_ip;
                    arp_local_ip_final = arp_local_ip_for_direct;
                    cout << " \[转发] 将直接查询目标主机 (" << ip_to_string(arp_target_ip) << ") 的 MAC 地址。" << endl;
                } else {
                    const unsigned char* arp_local_ip_via_route = nullptr;
                    for (const auto& local_ip_item : local_ips_all) {
                        bool same_subnet = true;
                        for(int i = 0; i < 4; ++i) if ((local_ip_item[i] & route->netmask[i]) != (next_hop_ip[i] & route->netmask[i])) same_subnet = false;
                        if (same_subnet) {
                            arp_local_ip_via_route = local_ip_item.data();
                            break;
                        }
                    }
                    if (!arp_local_ip_via_route) { cerr << " \[转发] 错误：无法确定用于 ARP 查询的本地 IP 地址。" << endl; return; }
                    if (is_local_ip(next_hop_ip)) {
                        arp_target_ip = dst_ip;
                        cout << " \[转发] 将查询目标主机 (" << ip_to_string(arp_target_ip) << ") 的 MAC 地址。" << endl;
                    } else {
                        arp_target_ip = next_hop_ip;
                        cout << " \[转发] 将查询网关 (" << ip_to_string(arp_target_ip) << ") 的 MAC 地址。" << endl;
                    }
                    arp_local_ip_final = arp_local_ip_via_route;
                }
                // 检查 ARP 缓存
                if (find_mac_in_cache(arp_target_ip, next_hop_mac)) {
                    cout << " \[ARP缓存命中] 目标 MAC: " << mac_to_string(next_hop_mac) << endl;
                } else {
                    cout << " \[ARP缓存缺失] 正在查询 (" << ip_to_string(arp_target_ip) << ") 的 MAC 地址..." << endl;
                    if (send_arp_and_wait_reply(g_handle, g_local_mac, arp_local_ip_final, arp_target_ip, next_hop_mac)) {
                        cout << " \[ARP成功] 目标 MAC: " << mac_to_string(next_hop_mac) << endl;
                    } else {
                        cout << " \[ARP失败] 无法获取目标 MAC，丢弃数据包。" << endl;
                        return;
                    }
                }
                // 设置新数据包的 MAC 地址并发送
                memcpy(new_eth->dest_mac, next_hop_mac, 6);
                memcpy(new_eth->src_mac, g_local_mac, 6);
                if (pcap_sendpacket(g_handle, new_packet.data(), new_packet.size()) == 0) {
                    cout << " \[转发] 数据包已发送" << endl;
                } else {
                    cerr << " \[转发] 发送失败: " << pcap_geterr(g_handle) << endl;
                }
            }
            else {
                cout << " (无路由，丢弃)" << endl;
            }
        }
    }
    else { // 非 IPv4 (即ARP)
        cout << "\[" << setw(4) << packet_count << "]\[" << get_ethertype_name(eth_header->ether_type) << "] ";
        cout << "源MAC: " << mac_to_string(eth_header->src_mac) << ", 目的MAC: " << mac_to_string(eth_header->dest_mac) << endl;

        if (ether_type == 0x0806) { // ARP
            if (header->caplen < sizeof(EthernetHeader) + sizeof(ArpPacket)) {
                cout << " \[ARP] 数据包太短，无法处理。" << endl;
                return;
            }
            const ArpPacket* arp = (const ArpPacket*)(packet_data + sizeof(EthernetHeader));

            // 1. 如果是 ARP Reply，更新我们的缓存
            if (ntohs(arp->oper) == 2) { // Reply
                cout << " \[ARP] 收到 ARP Reply。" << endl;
                update_or_add_cache_entry(arp->spa, arp->sha);
            }
            // 2. 如果是 ARP Request，并且是请求本机，则响应
            else if (ntohs(arp->oper) == 1) { // Request
                cout << " \[ARP] 收到 ARP Request: " << ip_to_string(arp->spa) << " 请求 " << ip_to_string(arp->tpa) << endl;

                // 检查请求的目标 IP 是否是本机的 IP 之一
                if (is_local_ip(arp->tpa)) {
                    cout << " \[ARP] 请求的目标是本机，正在构造 ARP Reply..." << endl;

                    // 构造 ARP Reply 报文
                    unsigned char reply_frame[42] = { 0 };
                    EthernetHeader* reply_eth = (EthernetHeader*)reply_frame;
                    ArpPacket* reply_arp = (ArpPacket*)(reply_frame + sizeof(EthernetHeader));

                    // 填充以太网头部
                    memcpy(reply_eth->dest_mac, eth_header->src_mac, 6); // 目的 MAC 是请求方的 MAC
                    memcpy(reply_eth->src_mac, g_local_mac, 6);         // 源 MAC 是本机 MAC
                    reply_eth->ether_type = htons(0x0806);

                    // 填充 ARP 报文
                    reply_arp->htype = htons(1);      // 硬件类型: 以太网
                    reply_arp->ptype = htons(0x0800); // 协议类型: IP
                    reply_arp->hlen = 6;              // 硬件地址长度
                    reply_arp->plen = 4;              // 协议地址长度
                    reply_arp->oper = htons(2);       // 操作: Reply

                    memcpy(reply_arp->sha, g_local_mac, 6);   // 发送方 MAC (本机)
                    memcpy(reply_arp->spa, arp->tpa, 4);      // 发送方 IP (被请求的本机 IP)
                    memcpy(reply_arp->tha, arp->sha, 6);      // 目标 MAC (请求方)
                    memcpy(reply_arp->tpa, arp->spa, 4);      // 目标 IP (请求方)

                    // 发送 ARP Reply
                    if (pcap_sendpacket(g_handle, reply_frame, sizeof(reply_frame)) != 0) {
                        cerr << " \[ARP] 发送 ARP Reply 失败: " << pcap_geterr(g_handle) << endl;
                    } else {
                        cout << " \[ARP] ARP Reply 已发送给 " << ip_to_string(arp->spa) << endl;
                    }
                } else {
                     cout << " \[ARP] 请求的目标非本机，忽略。" << endl;
                }
            }
        }
    }
}

// 解析 IP 字符串为字节数组
bool parse_ip(const string& ip, unsigned char out[4]) {
    int a, b, c, d;
    if (sscanf_s(ip.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4) return false;
    out[0] = (unsigned char)a;
    out[1] = (unsigned char)b;
    out[2] = (unsigned char)c;
    out[3] = (unsigned char)d;
    return true;
}

// 检查 IP 是否为本机 IP
bool is_local_ip(const unsigned char ip[4]) {
    for (const auto& local_ip : local_ips_all) {
        if (memcmp(local_ip.data(), ip, 4) == 0) {
            return true;
        }
    }
    return false;
}

// 添加路由条目
void add_route(const unsigned char network[4], const unsigned char netmask[4], const unsigned char gateway[4], bool is_default = false) {
    RouteEntry entry;
    memcpy(entry.network.data(), network, 4);
    memcpy(entry.netmask.data(), netmask, 4);
    memcpy(entry.gateway.data(), gateway, 4);
    entry.is_default = is_default;
    routing_table.push_back(entry);
    cout << "\[路由] 添加路由: " << entry.to_string() << endl;
}

// 删除路由条目
void del_route(const unsigned char network[4], const unsigned char netmask[4]) {
    for (auto it = routing_table.begin(); it != routing_table.end(); ) {
        if (it->is_default) {
            ++it;
            continue;
        }
        if (memcmp(it->network.data(), network, 4) == 0 && memcmp(it->netmask.data(), netmask, 4) == 0) {
            cout << "\[路由] 删除路由: " << it->to_string() << endl;
            it = routing_table.erase(it);
            return;
        }
        else {
            ++it;
        }
    }
    cout << "\[路由] 未找到匹配的路由项或路由项为默认路由,删除失败。" << endl;
}

// 显示路由表
void show_routing_table() {
    cout << "\n======= 路由表 =======\n";
    for (const auto& entry : routing_table) {
        cout << entry.to_string();
        if (entry.is_default) cout << " (直连路由(默认))";
        cout << endl;
    }
    cout << "=====================\n";
}

// 手动添加路由
void manual_add_route() {
    cout << "请输入要添加的路由信息（格式：网络/掩码/网关，例如 206.1.3.0/255.255.255.0/206.1.2.2）：" << endl;
    string input;
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    getline(cin, input);
    size_t pos1 = input.find('/');
    size_t pos2 = input.rfind('/');
    if (pos1 == string::npos || pos2 == string::npos || pos1 == pos2) {
        cout << "输入格式错误。" << endl; return;
    }
    string network_str = input.substr(0, pos1);
    string netmask_str = input.substr(pos1 + 1, pos2 - pos1 - 1);
    string gateway_str = input.substr(pos2 + 1);
    unsigned char network[4], netmask[4], gateway[4];
    if (!parse_ip(network_str, network) || !parse_ip(netmask_str, netmask) || !parse_ip(gateway_str, gateway)) {
        cout << "IP 地址格式不正确。" << endl; return;
    }
    add_route(network, netmask, gateway);
}

// 手动删除路由
void manual_del_route() {
    cout << "请输入要删除的路由信息（格式：网络/掩码，例如 206.1.3.0/255.255.255.0）：" << endl;
    string input;
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
    getline(cin, input);
    size_t pos = input.find('/');
    if (pos == string::npos) {
        cout << "输入格式错误。" << endl; return;
    }
    string network_str = input.substr(0, pos);
    string netmask_str = input.substr(pos + 1);
    unsigned char network[4], netmask[4];
    if (!parse_ip(network_str, network) || !parse_ip(netmask_str, netmask)) {
        cout << "IP 地址格式不正确。" << endl; return;
    }
    del_route(network, netmask);
}

// 主函数：程序入口，初始化并运行路由器
int main() {
    // 设置控制台输出为 UTF-8
    SetConsoleOutputCP(CP_UTF8);
    setlocale(LC_ALL, ".UTF-8");
    pcap_if_t* alldevs = nullptr;
    pcap_if_t* device = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    // 注册信号处理函数
    signal(SIGINT, signal_handler);
    cout << "=== NPcap 简化路由器程序 ===" << endl;
    // 获取所有网络设备
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "pcap_findalldevs 错误: " << errbuf << endl; return 1;
    }
    int device_count = 0;
    cout << "\n可用的网络设备:" << endl;
    for (device = alldevs; device != nullptr; device = device->next) {
        device_count++;
        cout << device_count << ". " << device->name;
        if (device->description) cout << " - " << device->description;
        cout << endl;
    }
    if (device_count == 0) {
        cerr << "错误: 未找到网络设备" << endl; pcap_freealldevs(alldevs); return 1;
    }
    // 选择设备
    int selected_index = 0;
    cout << "\n请选择要使用的设备编号 (1-" << device_count << "): ";
    cin >> selected_index;
    if (selected_index < 1 || selected_index > device_count) {
        cerr << "错误: 无效的设备编号" << endl; pcap_freealldevs(alldevs); return 1;
    }
    device = alldevs;
    for (int i = 1; i < selected_index; ++i) device = device->next;
    cout << "选择设备: " << (device->description ? device->description : device->name) << endl;
    // 打开设备
    char open_err[PCAP_ERRBUF_SIZE];
    g_handle = pcap_open_live(device->name, 65536, 1, 1000, open_err);
    if (!g_handle) {
        cerr << "打开设备失败: " << open_err << endl; pcap_freealldevs(alldevs); return 1;
    }
    // 获取本机 IP 地址
    bool ip_found = false;
    cout << "本机 IPv4 地址列表:" << endl;
    for (pcap_addr* a = device->addresses; a != nullptr; a = a->next) {
        if (a->addr && a->addr->sa_family == AF_INET) {
            sockaddr_in* sin = (sockaddr_in*)a->addr;
            array<unsigned char, 4> ip_bytes;
            memcpy(ip_bytes.data(), &sin->sin_addr, 4);
            local_ips_all.push_back(ip_bytes);
            cout << "  " << ip_to_string(ip_bytes.data()) << endl;
            ip_found = true;
        }
    }
    if (!ip_found) {
        cerr << "无法从网卡信息获取 IPv4 地址。" << endl;
    }
    // 添加默认路由
    for (const auto& ip : local_ips_all) {
        unsigned char net[4], mask[4] = { 255, 255, 255, 0 };
        memcpy(net, ip.data(), 4);
        net[3] = 0;
        add_route(net, mask, ip.data(), true);
    }
    // 获取本机 MAC 地址
    bool mac_found = false;
    IP_ADAPTER_INFO AdapterInfo[16];
    DWORD buflen = sizeof(AdapterInfo);
    if (GetAdaptersInfo(AdapterInfo, &buflen) == ERROR_SUCCESS) {
        for (PIP_ADAPTER_INFO p = AdapterInfo; p; p = p->Next) {
            if (strstr(device->name, p->AdapterName)) {
                memcpy(g_local_mac, p->Address, 6);
                mac_found = true;
                break;
            }
        }
    }
    if (!mac_found) {
        cerr << "警告: 无法获取本机 MAC。" << endl;
    }
    else {
        cout << "本机 MAC: " << mac_to_string(g_local_mac) << endl;
    }
    // 主菜单循环
    while (true) {
        cout << "\n====== 选择功能 ======\n";
        cout << "1. 启动路由器（抓包并转发）\n";
        cout << "2. 显示路由表\n";
        cout << "3. 显示 ARP 缓存\n";
        cout << "4. 手动添加路由\n";
        cout << "5. 手动删除路由\n";
        cout << "0. 退出程序\n";
        cout << "输入编号：";
        int choice = -1;
        cin >> choice;
        if (cin.fail()) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            choice = -1; // 无效输入
        }
        if (choice == 0) {
            cout << "程序退出..." << endl; break;
        }
        else if (choice == 1) {
            cout << "\n路由器启动，按 Ctrl+C 停止并返回菜单。\n";
            g_stop_capture = false;
            g_user_interrupted = 0;
            pcap_loop(g_handle, 0, packet_handler, nullptr);
            cout << "路由器已停止，返回菜单。\n";
        }
        else if (choice == 2) show_routing_table();
        else if (choice == 3) print_arp_cache();
        else if (choice == 4) manual_add_route();
        else if (choice == 5) manual_del_route();
        else cout << "无效输入，请重新选择。\n";
    }
    // 清理资源
    if (g_handle) pcap_close(g_handle);
    pcap_freealldevs(alldevs);
    return 0;
}

