#include "RawHidMouse.h"
#include <setupapi.h>
#include <hidsdi.h>
#include <iostream>
#include <vector>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "hid.lib")

RawHidMouse::RawHidMouse(USHORT vid, USHORT pid) {
    deviceHandle = openHidDevice(vid, pid);
    connected = (deviceHandle != INVALID_HANDLE_VALUE);
    if (connected)
        std::cout << "[RawHID] Device connected via VID:PID " << std::hex << vid << ":" << pid << std::dec << std::endl;
}

RawHidMouse::~RawHidMouse() {
    if (deviceHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(deviceHandle);
    }
}

bool RawHidMouse::isOpen() const {
    return connected;
}

void RawHidMouse::move(int buttons, int x, int y, int scroll, int tilt) {
    if (!connected) return;

    std::vector<unsigned char> report(65, 0);

    report[1] = static_cast<uint8_t>(buttons);
    report[2] = static_cast<uint8_t>(x & 0xFF);
    report[3] = static_cast<uint8_t>(y & 0xFF);
    report[4] = static_cast<uint8_t>(scroll & 0xFF);
    report[5] = static_cast<uint8_t>(tilt & 0xFF);

    DWORD written = 0;
    WriteFile(deviceHandle, report.data(), static_cast<DWORD>(report.size()), &written, NULL);
}

HANDLE RawHidMouse::openHidDevice(USHORT vid, USHORT pid) {
    GUID hidGuid;
    HidD_GetHidGuid(&hidGuid);

    HDEVINFO deviceInfoSet = SetupDiGetClassDevs(&hidGuid, NULL, NULL, DIGCF_PRESENT | DIGCF_DEVICEINTERFACE);
    if (deviceInfoSet == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;

    SP_DEVICE_INTERFACE_DATA interfaceData;
    interfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    for (DWORD i = 0; SetupDiEnumDeviceInterfaces(deviceInfoSet, NULL, &hidGuid, i, &interfaceData); ++i) {
        DWORD requiredSize = 0;
        SetupDiGetDeviceInterfaceDetailW(deviceInfoSet, &interfaceData, NULL, 0, &requiredSize, NULL);

        std::vector<wchar_t> buffer(requiredSize / sizeof(wchar_t));
        auto detailData = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA_W>(buffer.data());
        detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

        if (SetupDiGetDeviceInterfaceDetailW(deviceInfoSet, &interfaceData, detailData, requiredSize, NULL, NULL)) {
            HANDLE handle = CreateFileW(detailData->DevicePath, GENERIC_WRITE | GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            if (handle != INVALID_HANDLE_VALUE) {
                HIDD_ATTRIBUTES attributes;
                attributes.Size = sizeof(attributes);
                if (HidD_GetAttributes(handle, &attributes) &&
                    attributes.VendorID == vid && attributes.ProductID == pid) {
                    SetupDiDestroyDeviceInfoList(deviceInfoSet);
                    return handle;
                }
                CloseHandle(handle);
            }
        }
    }

    SetupDiDestroyDeviceInfoList(deviceInfoSet);
    return INVALID_HANDLE_VALUE;
}
