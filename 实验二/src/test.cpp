#include <iostream>
#include <winsock2.h>
#include "pcap.h"

#pragma comment(lib, "ws2_32.lib")

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    std::cout << "=== NPcap Detailed Test ===" << std::endl;
    
    // 测试1：基本功能
    std::cout << "1. Testing pcap_findalldevs..." << std::endl;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cout << "FAILED: " << errbuf << std::endl;
        std::cout << "This usually means NPcap is not properly installed." << std::endl;
    } else {
        std::cout << "SUCCESS: pcap_findalldevs worked!" << std::endl;
        
        int count = 0;
        for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
            count++;
            std::cout << "Device " << count << ": " << d->name << std::endl;
        }
        
        if (count == 0) {
            std::cout << "No network devices found." << std::endl;
            std::cout << "This might be normal if running without admin rights." << std::endl;
        }
        
        pcap_freealldevs(alldevs);
    }
    
    // 测试2：库版本
    std::cout << "\n2. Testing pcap_lib_version..." << std::endl;
    const char* version = pcap_lib_version();
    if (version) {
        std::cout << "NPcap version: " << version << std::endl;
    } else {
        std::cout << "Could not get NPcap version." << std::endl;
    }
    
    std::cout << "\nTest completed." << std::endl;
    system("pause");
    return 0;
}