#include <iostream>  // 输入输出流，用于控制台输出
#include <iomanip>   // 输入输出格式化，用于设置输出格式
#include <winsock2.h> // Windows Socket API，用于网络编程
#include "pcap.h"     // NPcap库头文件，用于数据包捕获

#pragma comment(lib, "ws2_32.lib")  // 链接Windows Socket库

// 以太网帧头结构定义（共14字节）
struct ethernet_header {
    u_char dest_mac[6];  // 目的MAC地址（6字节）
    u_char src_mac[6];   // 源MAC地址（6字节）
    u_short ether_type;  // 类型/长度字段（2字节），0x0800表示IPv4
};

// IP头部结构定义（标准20字节）
struct ip_header {
    u_char  ver_ihl;     // 版本(4位) + 头部长度(4位，单位：4字节)
    u_char  tos;         // 服务类型（8位）
    u_short total_len;   // 总长度（16位），整个IP数据包的长度
    u_short id;          // 标识（16位），用于分片重组
    u_short flags_off;   // 标志(3位) + 片偏移(13位)
    u_char  ttl;         // 生存时间（8位），防止数据包无限循环
    u_char  protocol;    // 协议类型（8位），1=ICMP, 6=TCP, 17=UDP
    u_short checksum;    // 头部校验和（16位），用于错误检测
    u_int   src_addr;    // 源IP地址（32位），网络字节序
    u_int   dst_addr;    // 目的IP地址（32位），网络字节序
};

// 通用校验和计算函数
// 参数：buffer-指向数据的指针，size-数据长度（字节）
// 返回值：计算出的16位校验和
u_short calculate_checksum(const u_short* buffer, int size) {
    uint32_t sum = 0;  // 使用32位变量防止溢出
    
    // 将每16位字相加（网络字节序）
    for (int i = 0; i < size / 2; i++) {
        sum += buffer[i];  // 累加每个16位字
    }
    
    // 处理奇数长度情况：如果数据长度为奇数，处理最后一个字节
    if (size % 2 == 1) {
        sum += ((u_char*)buffer)[size - 1] << 8;  // 最后一个字节左移8位后相加
    }
    
    // 处理进位：将高16位的进位加到低16位
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);  // 取低16位加上高16位
    }
    
    return (u_short)~sum;  // 取反码得到最终校验和
}

// IP头部专用校验和计算函数
// 参数：ip_hdr-指向IP头部的指针
// 返回值：IP头部校验和
u_short calculate_ip_checksum(const ip_header* ip_hdr) {
    // 创建临时副本，避免修改原始数据
    ip_header temp_hdr = *ip_hdr;
    temp_hdr.checksum = 0;  // 校验和字段清零（计算时不包含自身）
    
    // 调用通用校验和函数计算整个IP头部
    return calculate_checksum((u_short*)&temp_hdr, sizeof(ip_header));
}

// IP地址转换函数：将32位网络字节序IP地址转换为点分十进制字符串
// 参数：ip_addr-网络字节序的IP地址
// 返回值：点分十进制格式的IP地址字符串
std::string ip_to_string(u_int ip_addr) {
    struct in_addr addr;
    addr.s_addr = ip_addr;  // 设置IP地址
    char* ip_str = inet_ntoa(addr);  // 转换为字符串
    return ip_str ? std::string(ip_str) : "Invalid IP";  // 返回结果或错误信息
}

// 数据包处理回调函数（NPcap每捕获一个数据包调用一次）
// 参数：user-用户数据，header-数据包头信息，packet-数据包内容
void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    static int packet_count = 0;  // 静态变量，记录处理的IPv4数据包数量
    
    // 解析以太网帧头：将数据包开头转换为以太网帧头结构
    ethernet_header* eth_header = (ethernet_header*)packet;
    u_short ether_type = ntohs(eth_header->ether_type);  // 转换字节序并获取类型
    
    // 只处理IPv4数据包（以太网类型0x0800）
    if (ether_type != 0x0800) {
        return;  // 跳过非IPv4数据包
    }
    
    packet_count++;  // 增加IPv4数据包计数器
    
    // 解析IP头部：以太网帧头之后就是IP头部
    ip_header* ip_hdr = (ip_header*)(packet + sizeof(ethernet_header));
    
    // 验证数据包长度：确保包含完整的以太网帧头和IP头部
    if (header->len < sizeof(ethernet_header) + sizeof(ip_header)) {
        return;  // 数据包长度不足，跳过处理
    }
    
    // 输出数据包基本信息
    std::cout << "=== IP数据报 #" << packet_count << " ===" << std::endl;
    
    // 显示源MAC地址（6字节，十六进制格式）
    std::cout << "源MAC地址: ";
    for (int i = 0; i < 6; i++) {
        printf("%02x", eth_header->src_mac[i]);  // 两位十六进制显示
        if (i < 5) std::cout << ":";  // 字节间用冒号分隔
    }
    std::cout << std::endl;
    
    // 显示目的MAC地址
    std::cout << "目的MAC地址: ";
    for (int i = 0; i < 6; i++) {
        printf("%02x", eth_header->dest_mac[i]);
        if (i < 5) std::cout << ":";
    }
    std::cout << std::endl;
    
    // 显示IP地址（转换为点分十进制格式）
    std::cout << "源IP地址: " << ip_to_string(ip_hdr->src_addr) << std::endl;
    std::cout << "目的IP地址: " << ip_to_string(ip_hdr->dst_addr) << std::endl;
    
    // 显示协议类型
    std::cout << "协议类型: ";
    switch (ip_hdr->protocol) {
        case 1: std::cout << "ICMP"; break;   // Internet控制消息协议
        case 6: std::cout << "TCP"; break;    // 传输控制协议
        case 17: std::cout << "UDP"; break;   // 用户数据报协议
        default: std::cout << "其他(" << (int)ip_hdr->protocol << ")"; break;
    }
    std::cout << std::endl;
    
    // 显示数据包长度信息
    std::cout << "数据包总长度: " << ntohs(ip_hdr->total_len) << "字节" << std::endl;
    
    // 显示原始校验和（转换为主机字节序便于显示）
    u_short original_checksum = ntohs(ip_hdr->checksum);
    std::cout << "原始校验和: 0x" << std::hex << original_checksum << std::dec << std::endl;
    
    // 计算校验和
    u_short calculated_checksum = calculate_ip_checksum(ip_hdr);
    
    // 将计算出的校验和转换为网络字节序以便比较
    u_short calculated_network = htons(calculated_checksum);
    std::cout << "计算校验和: 0x" << std::hex << calculated_checksum 
              << " (网络字节序: 0x" << calculated_network << ")" << std::dec << std::endl;
    
    // 比较校验和（使用网络字节序）
    if (original_checksum == calculated_network) {
        std::cout << "校验结果: √ 匹配（数据包完整）" << std::endl;
    } else {
        std::cout << "校验结果: × 不匹配" << std::endl;
        // 显示详细的字节序信息用于调试
        std::cout << "  原始(网络字节序): 0x" << std::hex << original_checksum << std::dec << std::endl;
        std::cout << "  计算(网络字节序): 0x" << std::hex << calculated_network << std::dec << std::endl;
        std::cout << "  计算(主机字节序): 0x" << std::hex << calculated_checksum << std::dec << std::endl;
    }
    
    std::cout << std::endl;  // 数据包间空行分隔
}

// 主函数：程序入口点
int main() {
    pcap_if_t* alldevs;        // 设备列表头指针
    pcap_if_t* device;         // 当前设备指针
    pcap_t* device_handle;    // 设备句柄
    char errbuf[PCAP_ERRBUF_SIZE];  // 错误信息缓冲区
    int count = 0;            // 设备计数器
    int selected_device;      // 选择的设备编号（根据实际情况调整）
    
    // 程序标题和说明
    std::cout << "IP数据报捕获与校验和验证" << std::endl;
    std::cout << "=================================" << std::endl;
    std::cout << "说明:程序将尝试捕获IPv4数据包,网络流量会影响捕获数量" << std::endl;
    std::cout << "建议在运行程序的同时进行网络活动（如浏览网页）" << std::endl << std::endl;
    
    // 初始化Winsock库（版本2.2）
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    
    // 获取网络设备列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cout << "错误: " << errbuf << std::endl;
        WSACleanup();  // 清理Winsock资源
        return 1;      // 退出程序
    }

    // 显示设备列表
    for (device = alldevs; device != nullptr; device = device->next) {
        count++;
        std::cout << count << ". " << device->name;
        if (device->description) {
            std::cout << " - " << device->description;
        }
        std::cout << std::endl;
    }
    
    std::cout << "共找到 " << count << " 个设备" << std::endl;

    std::cout << "选择要使用的设备编号 (1-" << count << "): ";
    std::cin >> selected_device;  // 从用户输入获取设备编号
    
    // 选择指定编号的设备（这里选择第4个设备）
    device = alldevs;
    for (int i = 1; i < selected_device && device != nullptr; i++) {
        device = device->next;  // 遍历设备链表
    }
    
    // 检查设备选择是否有效
    if (device == nullptr) {
        std::cout << "设备选择无效" << std::endl;
        pcap_freealldevs(alldevs);  // 释放设备列表
        WSACleanup();               // 清理Winsock资源
        return 1;                   // 退出程序
    }
    
    // 显示选择的设备信息
    std::cout << "选择设备: " << (device->description ? device->description : "无描述") << std::endl;
    
    // 打开网络设备进行数据包捕获
    // 参数：设备名，最大捕获长度，混杂模式，超时时间，错误缓冲区
    device_handle = pcap_open_live(device->name, 65536, 1, 5000, errbuf);
    if (device_handle == nullptr) {
        std::cout << "打开设备失败: " << errbuf << std::endl;
        pcap_freealldevs(alldevs);  // 释放设备列表
        WSACleanup();               // 清理Winsock资源
        return 1;                   // 退出程序
    }
    
    // 开始捕获数据包
    std::cout << "开始捕获IPv4数据包(最多等待5秒)..." << std::endl;
    std::cout << "请进行网络活动以产生更多数据包..." << std::endl << std::endl;
    
    // 启动数据包捕获循环
    // 参数：设备句柄，捕获数量，回调函数，用户数据
    pcap_loop(device_handle, 5, packet_handler, nullptr);
    
    // 清理资源
    pcap_close(device_handle);    // 关闭设备
    pcap_freealldevs(alldevs);   // 释放设备列表
    WSACleanup();                // 清理Winsock资源
    
    std::cout << "程序结束" << std::endl;
    system("pause");  // 暂停等待用户按键
    return 0;         // 正常退出
}
