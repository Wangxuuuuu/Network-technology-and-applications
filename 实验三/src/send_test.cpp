#include <iostream>
#include <cstring> // for memset
#include "pcap.h"

// 以太网帧头结构
struct ethernet_header {
    u_char dest_mac[6];   // 目的MAC
    u_char src_mac[6];    // 源MAC
    u_short ether_type;   // 类型
};

int main() {
    pcap_if_t* alldevs;
    pcap_if_t* device;
    pcap_t* device_handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int count = 0;
    int selected_device;

    std::cout << "=== NPcap 数据包发送测试 ===" << std::endl;
    
    // 1. 获取设备列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cout << "错误: " << errbuf << std::endl;
        return 1;
    }

    // 2. 显示设备列表
    for (device = alldevs; device != nullptr; device = device->next) {
        count++;
        std::cout << count << ". " << device->name;
        if (device->description) {
            std::cout << " - " << device->description;
        }
        std::cout << std::endl;
    }
    std::cout << "共找到 " << count << " 个设备" << std::endl;

    if (count == 0) {
        pcap_freealldevs(alldevs);
        return 1;
    }

    // 3. 用户选择设备
    std::cout << "请选择要使用的设备编号 (1-" << count << "): ";
    std::cin >> selected_device;

    if (selected_device < 1 || selected_device > count) {
        std::cout << "无效选择！" << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    // 定位到选中的设备
    device = alldevs;
    for (int i = 1; i < selected_device; i++) {
        device = device->next;
    }

    // 4. 打开设备（混杂模式，超时1秒）
    device_handle = pcap_open_live(device->name, 65536, 1, 1000, errbuf);
    if (device_handle == nullptr) {
        std::cout << "打开设备失败: " << errbuf << std::endl;
        std::cout << "提示：请尝试以管理员身份运行程序！" << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    std::cout << "设备打开成功，准备发送测试包..." << std::endl;

    // 5. 构造一个简单的以太网帧
    u_char packet[64]; // 最小以太网帧为64字节
    memset(packet, 0, sizeof(packet)); // 先清零

    ethernet_header* eth = (ethernet_header*)packet;

    // 设置目的MAC为广播地址 FF:FF:FF:FF:FF:FF
    memset(eth->dest_mac, 0xFF, 6);

    // 设置源MAC为伪造地址 11:22:33:44:55:66
    eth->src_mac[0] = 0x11;
    eth->src_mac[1] = 0x22;
    eth->src_mac[2] = 0x33;
    eth->src_mac[3] = 0x44;
    eth->src_mac[4] = 0x55;
    eth->src_mac[5] = 0x66;

    // 设置类型为IPv4 (0x0800)
    eth->ether_type = htons(0x0800);

    // 可选：在后面加点“假数据”
    const char* payload = "NPcap Send Test";
    memcpy(packet + sizeof(ethernet_header), payload, strlen(payload));

    // 6. 发送数据包！
    if (pcap_sendpacket(device_handle, packet, sizeof(packet)) == 0) {
        std::cout << "\n数据包发送成功！" << std::endl;
        std::cout << "已发送一个伪造的以太网帧（目的MAC=FF:FF:FF:FF:FF:FF(广播)，源MAC=11:22:33:44:55:66）" << std::endl;
    } else {
        std::cout << "\n 发送失败: " << pcap_geterr(device_handle) << std::endl;
    }

    // 7. 清理资源
    pcap_close(device_handle);
    pcap_freealldevs(alldevs);

    std::cout << "\n程序结束。" << std::endl;
    system("pause");
    return 0;
}