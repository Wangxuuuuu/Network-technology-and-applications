#include <iostream>
#include "pcap.h"

int main() {
    pcap_if_t* alldevs;
    pcap_if_t* device;
    pcap_t* device_handle;  // 设备句柄
    char errbuf[PCAP_ERRBUF_SIZE];
    int count = 0;
    int selected_device = 0;
    
    std::cout << "NPcap网卡设备打开方法演示" << std::endl;
    std::cout << "=======================" << std::endl;
    
    // 1. 获取设备列表
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cout << "错误: " << errbuf << std::endl;
        return 1;
    }
    
    // 2. 显示设备列表
    std::cout << "可用设备列表:" << std::endl;
    for (device = alldevs; device != nullptr; device = device->next) {
        count++;
        std::cout << count << ". " << device->name;
        if (device->description) {
            std::cout << " - " << device->description;
        }
        std::cout << std::endl;
    }
    
    if (count == 0) {
        std::cout << "未找到任何设备!" << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }
    
    std::cout << "共找到 " << count << " 个设备" << std::endl;
    
    // 3. 选择要打开的设备（这里选择第4个设备，Realtek无线网卡）
    std::cout<< "选择要打开的设备（输入设备编号）: ";
    std::cin>>selected_device;

    if (selected_device < 1 || selected_device > count) {
        std::cout << "设备选择无效!" << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }
    
    // 找到选中的设备
    device = alldevs;
    for (int i = 1; i < selected_device; i++) {
        device = device->next;
    }
    
    std::cout << std::endl << "尝试打开设备"<< selected_device <<": "<< device->description << std::endl;
    
    // 4. 打开选中的设备
    device_handle = pcap_open_live(
        device->name,    // 设备名称
        65536,          // 捕获长度：64KB
        1,              // 混杂模式：开启
        1000,           // 超时时间：1秒
        errbuf          // 错误缓冲区
    );
    
    if (device_handle == nullptr) {
        std::cout << "打开设备失败: " << errbuf << std::endl;
        std::cout << "提示：可能需要管理员权限运行程序" << std::endl;
    } else {
        std::cout << "设备打开成功!" << std::endl;
        std::cout << "设备句柄: " << device_handle << std::endl;
        
        // 5. 关闭设备
        pcap_close(device_handle);
        std::cout << "设备已关闭" << std::endl;
    }
    
    // 6. 释放设备列表
    pcap_freealldevs(alldevs);
    
    std::cout << "程序结束" << std::endl;
    system("pause");
    return 0;
}