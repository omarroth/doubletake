#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "../../third_party/alac/codec/ALACAudioTypes.h"
#include "../../third_party/alac/codec/ALACEncoder.h"

namespace {

constexpr int kChannels = 2;
constexpr int kSampleRate = 44100;
constexpr int kBitDepth = 16;
constexpr int kFrameSize = 352;
constexpr int kPCMBytesPerFrame = kChannels * (kBitDepth / 8);
constexpr int kPCMChunkSize = kFrameSize * kPCMBytesPerFrame;

bool readExact(FILE* file, unsigned char* buf, size_t size) {
	size_t total = 0;
	while (total < size) {
		size_t n = fread(buf + total, 1, size - total, file);
		if (n == 0) {
			if (feof(file)) {
				return total == 0;
			}
			std::fprintf(stderr, "alac-enc: stdin read failed: %s\n", std::strerror(errno));
			std::exit(1);
		}
		total += n;
	}
	return true;
}

AudioFormatDescription pcmFormat() {
	AudioFormatDescription format = {};
	format.mSampleRate = kSampleRate;
	format.mFormatID = kALACFormatLinearPCM;
	format.mFormatFlags = kALACFormatFlagIsSignedInteger | kALACFormatFlagIsPacked;
	format.mBytesPerPacket = kPCMBytesPerFrame;
	format.mFramesPerPacket = 1;
	format.mBytesPerFrame = kPCMBytesPerFrame;
	format.mChannelsPerFrame = kChannels;
	format.mBitsPerChannel = kBitDepth;
	return format;
}

AudioFormatDescription alacFormat() {
	AudioFormatDescription format = {};
	format.mSampleRate = kSampleRate;
	format.mFormatID = kALACFormatAppleLossless;
	format.mFormatFlags = 1;  // 16-bit source
	format.mFramesPerPacket = kFrameSize;
	format.mChannelsPerFrame = kChannels;
	return format;
}

}  // namespace

int main(int argc, char** argv) {
	if (argc != 2) {
		std::fprintf(stderr, "usage: %s <udp-port>\n", argv[0]);
		return 2;
	}

	char* end = nullptr;
	long port = std::strtol(argv[1], &end, 10);
	if (end == argv[1] || *end != '\0' || port <= 0 || port > 65535) {
		std::fprintf(stderr, "alac-enc: invalid UDP port %q\n", argv[1]);
		return 2;
	}

	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		std::fprintf(stderr, "alac-enc: socket failed: %s\n", std::strerror(errno));
		return 1;
	}

	sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(static_cast<uint16_t>(port));
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	ALACEncoder encoder;
	encoder.SetFrameSize(kFrameSize);
	encoder.InitializeEncoder(alacFormat());

	std::vector<unsigned char> pcm(kPCMChunkSize);
	std::vector<unsigned char> encoded(encoder.maxOutputBytes());

	while (readExact(stdin, pcm.data(), pcm.size())) {
		int32_t encodedSize = kPCMChunkSize;
		int32_t err = encoder.Encode(pcmFormat(), alacFormat(), pcm.data(), encoded.data(), &encodedSize);
		if (err != 0) {
			std::fprintf(stderr, "alac-enc: encode failed: %d\n", err);
			close(sock);
			return 1;
		}
		if (sendto(sock, encoded.data(), encodedSize, 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
			std::fprintf(stderr, "alac-enc: sendto failed: %s\n", std::strerror(errno));
			close(sock);
			return 1;
		}
	}

	close(sock);
	return 0;
}