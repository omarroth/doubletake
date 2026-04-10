/*
 * aaceld-enc: AAC-ELD encoder helper for AirPlay audio streaming.
 *
 * Reads raw S16LE stereo 44100 Hz PCM from stdin, encodes to AAC-ELD
 * (AOT 39, 480 samples/frame), and sends each raw AAC frame as a
 * separate UDP datagram to 127.0.0.1:<port>.
 *
 * Usage: aaceld-enc <udp_port> [bitrate]
 *
 * Build: cc -O2 -o aaceld-enc main.c -lfdk-aac
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fdk-aac/aacenc_lib.h>

#define SAMPLE_RATE 44100
#define CHANNELS    2
#define FRAME_SIZE  480  /* AAC-ELD frame length */
#define PCM_FRAME_BYTES (FRAME_SIZE * CHANNELS * 2) /* S16LE */

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: aaceld-enc <udp_port> [bitrate]\n");
        return 1;
    }

    int port = atoi(argv[1]);
    int bitrate = (argc >= 3) ? atoi(argv[2]) : 256000;

    /* Create UDP socket */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    /* Initialize FDK-AAC encoder */
    HANDLE_AACENCODER enc = NULL;
    AACENC_ERROR err;

    err = aacEncOpen(&enc, 0, CHANNELS);
    if (err != AACENC_OK) {
        fprintf(stderr, "aacEncOpen failed: %d\n", err);
        return 1;
    }

    /* Configure for AAC-ELD (AOT 39) */
    aacEncoder_SetParam(enc, AACENC_AOT, 39); /* AOT_ER_AAC_ELD */
    aacEncoder_SetParam(enc, AACENC_SAMPLERATE, SAMPLE_RATE);
    aacEncoder_SetParam(enc, AACENC_CHANNELMODE, MODE_2); /* stereo */
    aacEncoder_SetParam(enc, AACENC_BITRATE, bitrate);
    aacEncoder_SetParam(enc, AACENC_TRANSMUX, TT_MP4_RAW); /* raw frames */
    aacEncoder_SetParam(enc, AACENC_GRANULE_LENGTH, FRAME_SIZE);
    aacEncoder_SetParam(enc, AACENC_AFTERBURNER, 1);

    err = aacEncEncode(enc, NULL, NULL, NULL, NULL); /* initialize */
    if (err != AACENC_OK) {
        fprintf(stderr, "aacEncEncode init failed: %d\n", err);
        aacEncClose(&enc);
        return 1;
    }

    /* Get encoder info to verify configuration */
    AACENC_InfoStruct info;
    err = aacEncInfo(enc, &info);
    if (err != AACENC_OK) {
        fprintf(stderr, "aacEncInfo failed: %d\n", err);
        aacEncClose(&enc);
        return 1;
    }
    fprintf(stderr, "aaceld-enc: AAC-ELD encoder ready: frameLength=%d, "
            "maxOutBufBytes=%d, confSize=%d, bitrate=%d\n",
            info.frameLength, info.maxOutBufBytes, info.confSize, bitrate);

    /* Encoding loop */
    unsigned char pcm_buf[PCM_FRAME_BYTES];
    unsigned char out_buf[8192];

    for (;;) {
        /* Read one frame of PCM */
        size_t total = 0;
        while (total < PCM_FRAME_BYTES) {
            ssize_t n = read(STDIN_FILENO, pcm_buf + total,
                             PCM_FRAME_BYTES - total);
            if (n <= 0) {
                goto done;
            }
            total += n;
        }

        /* Set up input buffer descriptor */
        AACENC_BufDesc in_desc = {0};
        AACENC_BufDesc out_desc = {0};
        AACENC_InArgs in_args = {0};
        AACENC_OutArgs out_args = {0};

        void *in_ptr = pcm_buf;
        int in_id = IN_AUDIO_DATA;
        int in_size = PCM_FRAME_BYTES;
        int in_elem_size = 2; /* S16LE */

        in_desc.numBufs = 1;
        in_desc.bufs = &in_ptr;
        in_desc.bufferIdentifiers = &in_id;
        in_desc.bufSizes = &in_size;
        in_desc.bufElSizes = &in_elem_size;

        void *out_ptr = out_buf;
        int out_id = OUT_BITSTREAM_DATA;
        int out_size = sizeof(out_buf);
        int out_elem_size = 1;

        out_desc.numBufs = 1;
        out_desc.bufs = &out_ptr;
        out_desc.bufferIdentifiers = &out_id;
        out_desc.bufSizes = &out_size;
        out_desc.bufElSizes = &out_elem_size;

        in_args.numInSamples = FRAME_SIZE * CHANNELS;

        err = aacEncEncode(enc, &in_desc, &out_desc, &in_args, &out_args);
        if (err != AACENC_OK) {
            fprintf(stderr, "aacEncEncode failed: %d\n", err);
            break;
        }

        if (out_args.numOutBytes > 0) {
            sendto(sock, out_buf, out_args.numOutBytes, 0,
                   (struct sockaddr *)&dest, sizeof(dest));
        }
    }

done:
    aacEncClose(&enc);
    close(sock);
    return 0;
}
