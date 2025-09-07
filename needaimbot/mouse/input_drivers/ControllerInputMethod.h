#pragma once

#include "InputMethod.h"
#include <ViGEm/Client.h>
#include <algorithm>

// Input method that sends aiming data through a virtual Xbox 360 controller
// using the ViGEmClient driver. Mouse movement is mapped to the right stick and
// shooting is mapped to the right trigger.
class ControllerInputMethod : public InputMethod {
public:
    ControllerInputMethod();
    ~ControllerInputMethod() override;

    void move(int x, int y) override;
    void press() override;
    void release() override;
    bool isValid() const override;

private:
    PVIGEM_CLIENT client_;
    PVIGEM_TARGET target_;
    XUSB_REPORT report_{};
    bool connected_;
};
