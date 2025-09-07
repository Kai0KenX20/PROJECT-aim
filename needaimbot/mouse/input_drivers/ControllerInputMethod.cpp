#include "ControllerInputMethod.h"
#include <iostream>
#include <cstring>

ControllerInputMethod::ControllerInputMethod()
    : client_(nullptr), target_(nullptr), connected_(false)
{
    client_ = vigem_alloc();
    if (!client_)
    {
        std::cerr << "[Controller] Failed to allocate ViGEm client." << std::endl;
        return;
    }

    if (!VIGEM_SUCCESS(vigem_connect(client_)))
    {
        std::cerr << "[Controller] Failed to connect to ViGEm bus." << std::endl;
        vigem_free(client_);
        client_ = nullptr;
        return;
    }

    target_ = vigem_target_x360_alloc();
    if (!target_)
    {
        std::cerr << "[Controller] Failed to allocate X360 target." << std::endl;
        vigem_disconnect(client_);
        vigem_free(client_);
        client_ = nullptr;
        return;
    }

    if (!VIGEM_SUCCESS(vigem_target_add(client_, target_)))
    {
        std::cerr << "[Controller] Failed to add X360 target." << std::endl;
        vigem_target_free(target_);
        vigem_disconnect(client_);
        vigem_free(client_);
        target_ = nullptr;
        client_ = nullptr;
        return;
    }

    std::memset(&report_, 0, sizeof(report_));
    connected_ = true;
}

ControllerInputMethod::~ControllerInputMethod()
{
    if (connected_)
    {
        vigem_target_remove(client_, target_);
    }
    if (target_)
    {
        vigem_target_free(target_);
    }
    if (client_)
    {
        vigem_disconnect(client_);
        vigem_free(client_);
    }
}

void ControllerInputMethod::move(int x, int y)
{
    if (!connected_) return;
    report_.sThumbRX = static_cast<SHORT>(std::clamp(x, -32768, 32767));
    report_.sThumbRY = static_cast<SHORT>(std::clamp(y, -32768, 32767));
    vigem_target_x360_update(client_, target_, report_);
}

void ControllerInputMethod::press()
{
    if (!connected_) return;
    report_.bRightTrigger = 0xFF; // fully pressed
    vigem_target_x360_update(client_, target_, report_);
}

void ControllerInputMethod::release()
{
    if (!connected_) return;
    report_.bRightTrigger = 0x00;
    vigem_target_x360_update(client_, target_, report_);
}

bool ControllerInputMethod::isValid() const
{
    return connected_;
}
