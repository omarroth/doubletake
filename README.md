2026/03/27 23:59:38 [ENC-READ] status=200 content-length=0 remaining=0
2026/03/27 23:59:38 [RTSP] <- response body 0 bytes
2026/03/27 23:59:38 mirror session ready (data port: 50971)
2026/03/27 23:59:39 pipewire node ID: 123
2026/03/27 23:59:39 [CAPTURE] launching gst-launch-1.0 pipewiresrc fd=3 path=123 do-timestamp=true ! queue ! videoconvert ! videoscale ! video/x-raw,format=I420,width=1920,height=1080,framerate=30/1 ! openh264enc usage-type=screen rate-control=bitrate complexity=0 gop-size=30 bitrate=4000000 ! h264parse config-interval=-1 ! video/x-h264,stream-format=byte-stream,alignment=au ! fdsink fd=1 sync=false async=false
2026/03/27 23:59:39 screen capture started
2026/03/27 23:59:39 [CAPTURE] read 31 bytes start=53 65 74 74 69 6e 67 20 70 69 70 65 6c 69 6e 65
2026/03/27 23:59:39 [STREAM] invalid AVCC NAL length 1399157876, dropping 31 buffered bytes
2026/03/27 23:59:40 [NTP] received 32 bytes from 192.168.1.77:56834
2026/03/27 23:59:40 [NTP] sent timing reply to 192.168.1.77:56834
