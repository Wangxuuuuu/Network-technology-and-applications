#include <iostream>
#include <iomanip>
#include "pcap.h"

// 以太网帧头结构
struct ethernet_header {
    u_char dest_mac[6];  // 目的MAC地址
    u_char src_mac[6];   // 源MAC地址
    u_short ether_type;  // 类型/长度字段
};

// 数据包处理回调函数
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    static int packet_count = 0;
    packet_count++;
    
    std::cout << "=== 数据包 #" << packet_count << " ===" << std::endl;
    std::cout << "时间戳: " << header->ts.tv_sec << "秒" << std::endl;
    std::cout << "数据包长度: " << header->len << "字节" << std::endl;
    
    // 解析以太网帧头
    ethernet_header *eth_header = (ethernet_header *)packet;
    
    // 打印源MAC地址
    std::cout << "源MAC地址: ";
    for (int i = 0; i < 6; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)eth_header->src_mac[i];
        if (i < 5) std::cout << ":";
    }
    std::cout << std::dec << std::endl;
    
    // 打印目的MAC地址
    std::cout << "目的MAC地址: ";
    for (int i = 0; i < 6; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)eth_header->dest_mac[i];
        if (i < 5) std::cout << ":";
    }
    std::cout << std::dec << std::endl;
    
    // 打印类型/长度字段
    u_short ether_type = ntohs(eth_header->ether_type);
    std::cout << "类型/长度: 0x" << std::hex << ether_type << std::dec;
    
    // 常见类型解释
    switch (ether_type) {
        case 0x0800:
            std::cout << " (IPv4)";
            break;
        case 0x0806:
            std::cout << " (ARP)";
            break;
        case 0x86DD:
            std::cout << " (IPv6)";
            break;
        default:
            std::cout << " (其他)";
            break;
    }
    std::cout << std::endl << std::endl;
}

int main() {
    pcap_if_t* alldevs;
    pcap_if_t* device;
    pcap_t* device_handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int count = 0;
    int selected_device = 4;  // 根据您的设备列表调整
    
    std::cout << "NPcap数据包捕获方法演示" << std::endl;
    std::cout << "======================" << std::endl;
    
    // 获取设备列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cout << "错误: " << errbuf << std::endl;
        return 1;
    }
    
    // 显示设备列表（简化显示）
    for (device = alldevs; device != nullptr; device = device->next) {
        count++;
    }
    
    if (count == 0) {
        std::cout << "未找到任何设备!" << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }
    
    // 选择设备（这里选择第4个设备）
    device = alldevs;
    for (int i = 1; i < selected_device; i++) {
        device = device->next;
    }
    
    std::cout << "选择设备: " << device->description << std::endl;
    
    // 打开设备
    device_handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
    if (device_handle == nullptr) {
        std::cout << "打开设备失败: " << errbuf << std::endl;
        std::cout << "提示：可能需要管理员权限运行程序" << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }
    
    std::cout << "设备打开成功，开始捕获数据包..." << std::endl;
    std::cout << "将捕获5个数据包，请稍候..." << std::endl << std::endl;
    
    // 开始捕获数据包（捕获5个后退出）
    int packet_count = 5;
    int result = pcap_loop(device_handle, packet_count, packet_handler, nullptr);
    
    if (result == -1) {
        std::cout << "捕获过程中出错: " << pcap_geterr(device_handle) << std::endl;
    } else if (result == 0) {
        std::cout << "成功捕获" << packet_count << "个数据包" << std::endl;
    } else {
        std::cout << "捕获被中断" << std::endl;
    }
    
    // 清理资源
    pcap_close(device_handle);
    pcap_freealldevs(alldevs);
    
    std::cout << "程序结束" << std::endl;
    system("pause");
    return 0;
}