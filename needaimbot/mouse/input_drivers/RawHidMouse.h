#pragma once

#include <windows.h>
#include <vector>

class RawHidMouse {
public:
    RawHidMouse(USHORT vid, USHORT pid);
    ~RawHidMouse();

    bool isOpen() const;
    void move(int buttons, int x, int y, int scroll = 0, int tilt = 0);

private:
    HANDLE deviceHandle = INVALID_HANDLE_VALUE;
    bool connected = false;

    HANDLE openHidDevice(USHORT vid, USHORT pid);
};
