// TCC reads the usage descriptions from the executable before capture starts.
__attribute__((used, section("__TEXT,__info_plist")))
static const char doubletakeInfo[] =
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    "<plist version=\"1.0\"><dict>"
    "<key>CFBundleIdentifier</key><string>yt.omar.doubletake</string>"
    "<key>CFBundleName</key><string>doubletake</string>"
    "<key>NSScreenCaptureUsageDescription</key><string>doubletake captures your screen for AirPlay streaming.</string>"
    "<key>NSAudioCaptureUsageDescription</key><string>doubletake captures system audio for AirPlay streaming.</string>"
    "</dict></plist>";
