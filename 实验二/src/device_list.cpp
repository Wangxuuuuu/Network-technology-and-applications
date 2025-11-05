#include <iostream>
#include "pcap.h"

int main() {
    pcap_if_t* alldevs;
    pcap_if_t* device;
    char errbuf[PCAP_ERRBUF_SIZE];
    int count = 0;
    
    std::cout << "NPcap设备列表获取演示" << std::endl;
    std::cout << "====================" << std::endl;
    
    // 获取设备列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cout << "错误: " << errbuf << std::endl;
        return 1;
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
    
    // 释放资源
    pcap_freealldevs(alldevs);

    system("pause");
    return 0;
}