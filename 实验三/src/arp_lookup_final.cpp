#include <iostream>
#include <cstring>
#include <cstdint>
#include <winsock2.h>
#include <chrono>
#include "pcap.h"

#pragma comment(lib, "ws2_32.lib")

struct ethernet_header {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
};

struct arp_header {
    uint16_t htype;     // 硬件类型：1 = 以太网
    uint16_t ptype;     // 协议类型：0x0800 = IPv4
    uint8_t hlen;       // 硬件地址长度：6（MAC 是 6 字节）
    uint8_t plen;       // 协议地址长度：4（IPv4 是 4 字节）
    uint16_t oper;      // 操作码：1=请求，2=响应
    uint8_t sender_mac[6];      // 发送方 MAC
    uint8_t sender_ip[4];       // 发送方 IP
    uint8_t target_mac[6];      // 目标 MAC（请求时填 0）
    uint8_t target_ip[4];       // 目标 IP
};

// 全局用于回调匹配
uint8_t g_target_ip[4] = {0};
bool g_found = false;
uint8_t g_result_mac[6] = {0};

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data) {
    if (header->caplen < sizeof(ethernet_header) + sizeof(arp_header)) return;

    const ethernet_header* eth = reinterpret_cast<const ethernet_header*>(pkt_data);
    if (ntohs(eth->ether_type) != 0x0806) return;

    const arp_header* arp = reinterpret_cast<const arp_header*>(pkt_data + sizeof(ethernet_header));
    if (ntohs(arp->oper) != 2) return;

    if (memcmp(arp->sender_ip, g_target_ip, 4) == 0) {
        memcpy(g_result_mac, arp->sender_mac, 6);
        g_found = true;
        std::cout << "\n 收到 ARP 响应！" << std::endl;
        printf("IP: %d.%d.%d.%d  -->  MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
               g_target_ip[0], g_target_ip[1], g_target_ip[2], g_target_ip[3],
               g_result_mac[0], g_result_mac[1], g_result_mac[2],
               g_result_mac[3], g_result_mac[4], g_result_mac[5]);
    }
}

bool parse_ip(const std::string& ip_str, uint8_t* ip) {
    int a, b, c, d;
    if (sscanf(ip_str.c_str(), "%d.%d.%d.%d", &a, &b, &c, &d) != 4) return false;
    if (a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255) return false;
    ip[0] = static_cast<uint8_t>(a);
    ip[1] = static_cast<uint8_t>(b);
    ip[2] = static_cast<uint8_t>(c);
    ip[3] = static_cast<uint8_t>(d);
    return true;
}

int main() {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    pcap_if_t* alldevs = nullptr;
    pcap_if_t* device = nullptr;
    pcap_t* handle = nullptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    std::cout << "=== ARP IP-MAC 映射查询工具 ===" << std::endl;

    // 获取设备列表
    if (pcap_findalldevs(&alldevs, errbuf) != 0) {
        std::cerr << "获取设备列表失败: " << errbuf << std::endl;
        WSACleanup();
        return 1;
    }

    // 显示设备
    int count = 0;
    for (device = alldevs; device; device = device->next) {
        std::cout << (++count) << ". " << device->name;
        if (device->description) std::cout << " - " << device->description;
        std::cout << std::endl;
    }

    if (count == 0) {
        std::cout << "未找到可用设备。" << std::endl;
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    // 选择设备
    int dev_index;
    std::cout << "请选择设备编号 (1-" << count << "): ";
    std::cin >> dev_index;
    if (dev_index < 1 || dev_index > count) {
        std::cout << "无效选择。" << std::endl;
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    device = alldevs;
    for (int i = 1; i < dev_index; i++) device = device->next;

    // 打开设备
    handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "打开设备失败: " << errbuf << std::endl;
        std::cout << "请以管理员身份运行！" << std::endl;
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    // 输入本机信息
    std::string local_ip_str, local_mac_str;
    uint8_t local_ip[4], local_mac[6];

    std::cout << "\n请输入本机 IP 地址: ";
    std::cin >> local_ip_str;
    if (!parse_ip(local_ip_str, local_ip)) {
        std::cout << "IP 格式错误！" << std::endl;
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    std::cout << "请输入本机 MAC 地址 (aa:bb:cc:dd:ee:ff): ";
    std::cin >> local_mac_str;
    int mac[6];
    if (sscanf(local_mac_str.c_str(), "%x:%x:%x:%x:%x:%x",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        std::cout << "MAC 格式错误！" << std::endl;
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }
    for (int i = 0; i < 6; i++) {
        if (mac[i] < 0 || mac[i] > 255) {
            std::cout << "MAC 值非法！" << std::endl;
            pcap_close(handle);
            pcap_freealldevs(alldevs);
            WSACleanup();
            return 1;
        }
        local_mac[i] = static_cast<uint8_t>(mac[i]);
    }

    // 输入目标 IP
    std::string target_ip_str;
    std::cout << "请输入要查询的目标 IP 地址: ";
    std::cin >> target_ip_str;
    if (!parse_ip(target_ip_str, g_target_ip)) {
        std::cout << "目标 IP 格式错误！" << std::endl;
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    // 构造并发送 ARP 请求
    uint8_t packet[60] = {0};
    ethernet_header* eth = reinterpret_cast<ethernet_header*>(packet);
    arp_header* arp = reinterpret_cast<arp_header*>(packet + sizeof(ethernet_header));

    memset(eth->dest_mac, 0xFF, 6);
    memcpy(eth->src_mac, local_mac, 6);
    eth->ether_type = htons(0x0806);

    arp->htype = htons(1);
    arp->ptype = htons(0x0800);
    arp->hlen = 6;
    arp->plen = 4;
    arp->oper = htons(1);
    memcpy(arp->sender_mac, local_mac, 6);
    memcpy(arp->sender_ip, local_ip, 4);
    memset(arp->target_mac, 0, 6);
    memcpy(arp->target_ip, g_target_ip, 4);

    std::cout << "\n正在发送 ARP 请求..." << std::endl;
    if (pcap_sendpacket(handle, packet, 60) != 0) {
        std::cout << " 发送失败: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        WSACleanup();
        return 1;
    }

    // === 使用 pcap_next_ex 主动轮询 ===
    std::cout << " ARP 请求已发送，等待响应（最多 5 秒）..." << std::endl;

    g_found = false;
    struct pcap_pkthdr* header;
    const u_char* pkt_data;

    auto start_time = std::chrono::steady_clock::now();
    const auto timeout_duration = std::chrono::seconds(5);

    // 注意：pcap_open_live 的第4个参数是 read_timeout（毫秒），设为 50ms 避免阻塞太久
    // 但我们已经在 open 时设为 1000ms，这里靠循环控制总时间即可

    while (!g_found) {
        int result = pcap_next_ex(handle, &header, &pkt_data);
        if (result == 1) {
            // 成功捕获一个数据包
            packet_handler(nullptr, header, pkt_data);
        } else if (result == 0) {
            // 超时（由 pcap_open_live 的 timeout 参数触发）
            // 继续循环，我们自己控制总超时
        } else {
            // 发生错误（如 -1）
            break;
        }

        // 检查是否超时（总时间超过 5 秒）
        auto now = std::chrono::steady_clock::now();
        if (now - start_time > timeout_duration) {
            break;
        }
    }
    // === 使用 pcap_next_ex 主动轮询 ===

    if (!g_found) {
        std::cout << "\n 超时：未收到目标 IP 的 ARP 响应。" << std::endl;
    }

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    WSACleanup();
    system("pause");
    return 0;
}