#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <pcap.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

// 以太网帧头结构
struct ethernet_header {
    u_char dest_mac[6];
    u_char src_mac[6];
    u_short ether_type;
};

// IP头部结构
#pragma pack(push, 1)
struct ip_header {
    u_char  version_ihl;
    u_char  tos;
    u_short total_length;
    u_short identification;
    u_short flags_fragment;
    u_char  ttl;
    u_char  protocol;
    u_short checksum;
    struct in_addr src_addr;
    struct in_addr dest_addr;
};
#pragma pack(pop)

class PacketCapture {
private:
    pcap_t* handle;
    
    // MAC地址转字符串
    std::string macToString(const u_char* mac) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < 6; ++i) {
            ss << std::setw(2) << static_cast<int>(mac[i]);
            if (i < 5) ss << ":";
        }
        return ss.str();
    }
    
    // IP地址转字符串
    std::string ipToString(const in_addr& ip) {
        char* ip_cstr = inet_ntoa(ip);
        return (ip_cstr != nullptr) ? std::string(ip_cstr) : std::string("0.0.0.0");
    }
    
    // 计算IP头部校验和
    u_short calculateChecksum(const ip_header* ipHdr) {
        u_long sum = 0;
        u_short* ptr = (u_short*)ipHdr;
        int headerLen = (ipHdr->version_ihl & 0x0F) * 4;
        
        for (int i = 0; i < headerLen / 2; ++i) {
            sum += ntohs(ptr[i]);
        }
        
        while (sum >> 16) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        return (u_short)~sum;
    }
    
    // 处理捕获的数据包
    static void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
        PacketCapture* self = (PacketCapture*)user;
        self->processPacket(header, packet);
    }
    
    void processPacket(const struct pcap_pkthdr* header, const u_char* packet) {
        // 检查数据包长度
        if (header->caplen < sizeof(ethernet_header) + sizeof(ip_header)) {
            return;
        }
        
        // 解析以太网头
        const ethernet_header* ethHdr = (const ethernet_header*)packet;
        
        // 只处理IP数据包
        if (ntohs(ethHdr->ether_type) != 0x0800) {
            return;
        }
        
        // 解析IP头
        const ip_header* ipHdr = (const ip_header*)(packet + sizeof(ethernet_header));
        
        // 检查IP版本
        if ((ipHdr->version_ihl >> 4) != 4) {
            return;
        }
        
        // 保存原始校验和
        u_short originalChecksum = ipHdr->checksum;
        
        // 计算校验和
        ip_header ipHdrCopy = *ipHdr;
        ipHdrCopy.checksum = 0;
        u_short calculatedChecksum = calculateChecksum(&ipHdrCopy);
        
        // 显示结果
        displayPacketInfo(ethHdr, ipHdr, originalChecksum, calculatedChecksum);
    }
    
    void displayPacketInfo(const ethernet_header* ethHdr, const ip_header* ipHdr, 
                          u_short originalChecksum, u_short calculatedChecksum) {
        std::cout << "\n=== IP数据报分析 ===" << std::endl;
        std::cout << "源MAC地址: " << macToString(ethHdr->src_mac) << std::endl;
        std::cout << "目的MAC地址: " << macToString(ethHdr->dest_mac) << std::endl;
        std::cout << "源IP地址: " << ipToString(ipHdr->src_addr) << std::endl;
        std::cout << "目的IP地址: " << ipToString(ipHdr->dest_addr) << std::endl;
        std::cout << "校验和字段值: 0x" << std::hex << ntohs(originalChecksum) << std::endl;
        std::cout << "计算校验和值: 0x" << std::hex << ntohs(calculatedChecksum) << std::endl;
        
        if (originalChecksum == calculatedChecksum) {
            std::cout << "校验结果: 正确" << std::endl;
        } else {
            std::cout << "校验结果: 错误" << std::endl;
        }
        std::cout << "====================" << std::endl;
    }

public:
    PacketCapture() : handle(nullptr) {}
    
    ~PacketCapture() {
        stop();
    }
    
    // 显示网络设备列表
    bool showDevices() {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t* alldevs;
        
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            std::cerr << "错误: " << errbuf << std::endl;
            return false;
        }
        
        std::cout << "可用网络设备:" << std::endl;
        int i = 0;
        for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) {
            std::cout << i++ << ". " << d->name;
            if (d->description) {
                std::cout << " (" << d->description << ")";
            }
            std::cout << std::endl;
        }
        
        if (i == 0) {
            std::cout << "未找到网络设备" << std::endl;
        }
        
        pcap_freealldevs(alldevs);
        return (i > 0);
    }
    
    // 打开网络设备
    bool openDevice(int deviceIndex) {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t* alldevs;
        
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            std::cerr << "错误: " << errbuf << std::endl;
            return false;
        }
        
        // 找到指定设备
        pcap_if_t* device = alldevs;
        for (int i = 0; i < deviceIndex && device != nullptr; i++) {
            device = device->next;
        }
        
        if (device == nullptr) {
            std::cerr << "无效的设备索引" << std::endl;
            pcap_freealldevs(alldevs);
            return false;
        }
        
        // 打开设备
        handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
        if (handle == nullptr) {
            std::cerr << "无法打开设备: " << errbuf << std::endl;
            pcap_freealldevs(alldevs);
            return false;
        }
        
        // 设置过滤器，只捕获IP数据包
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "过滤器错误: " << pcap_geterr(handle) << std::endl;
            pcap_close(handle);
            handle = nullptr;
            pcap_freealldevs(alldevs);
            return false;
        }
        
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "设置过滤器错误: " << pcap_geterr(handle) << std::endl;
            pcap_freecode(&fp);
            pcap_close(handle);
            handle = nullptr;
            pcap_freealldevs(alldevs);
            return false;
        }
        
        pcap_freecode(&fp);
        pcap_freealldevs(alldevs);
        
        std::cout << "成功打开设备: " << device->name << std::endl;
        return true;
    }
    
    // 开始捕获
    bool start() {
        if (handle == nullptr) {
            std::cerr << "设备未打开" << std::endl;
            return false;
        }
        
        std::cout << "开始捕获IP数据包..." << std::endl;
        std::cout << "按Ctrl+C停止捕获" << std::endl;
        
        // 开始捕获循环
        int result = pcap_loop(handle, 0, packetHandler, (u_char*)this);
        
        if (result == -1) {
            std::cerr << "捕获错误: " << pcap_geterr(handle) << std::endl;
            return false;
        }
        
        return true;
    }
    
    // 停止捕获
    void stop() {
        if (handle != nullptr) {
            pcap_breakloop(handle);  // 中断捕获循环
            pcap_close(handle);
            handle = nullptr;
        }
    }
};

int main() {
#ifdef _WIN32
    // 初始化Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Winsock初始化失败" << std::endl;
        return 1;
    }
#endif

    PacketCapture capture;
    
    // 显示设备列表
    if (!capture.showDevices()) {
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    
    // 选择设备
    int deviceIndex;
    std::cout << "\n请选择要监听的设备编号: ";
    std::cin >> deviceIndex;
    
    // 打开设备
    if (!capture.openDevice(deviceIndex)) {
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    
    // 开始捕获
    if (!capture.start()) {
#ifdef _WIN32
        WSACleanup();
#endif
        return 1;
    }
    
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}