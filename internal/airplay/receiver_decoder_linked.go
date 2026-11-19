//go:build gstreamer_cgo && cgo && linux

package airplay

/*
#cgo pkg-config: gstreamer-1.0 gstreamer-app-1.0 gstreamer-video-1.0
#include <gst/gst.h>
#include <gst/app/gstappsrc.h>
#include <gst/app/gstappsink.h>
#include <gst/video/video.h>
#include <stdlib.h>

typedef struct {
    GstElement *pipeline;
    GstAppSrc *source;
    GstAppSink *sink;
    GstBus *bus;
} DTReceiverDecoder;

static char *dt_receiver_decode_error(DTReceiverDecoder *p) {
    GstMessage *m = gst_bus_pop_filtered(p->bus, GST_MESSAGE_ERROR);
    if (!m) return NULL;
    GError *e = NULL;
    gst_message_parse_error(m, &e, NULL);
    char *result = g_strdup(e ? e->message : "decoder pipeline error");
    if (e) g_error_free(e);
    gst_message_unref(m);
    return result;
}

static int dt_receiver_has_decoder(const char *name) {
    gst_init(NULL, NULL);
    GstElementFactory *factory = gst_element_factory_find(name);
    if (!factory) return 0;
    gst_object_unref(factory);
    return 1;
}

static DTReceiverDecoder *dt_receiver_decoder_new(const char *description,
    const char *caps_string, const void *config, size_t config_size, char **error) {
    GError *e = NULL;
    if (!gst_init_check(NULL, NULL, &e)) {
        *error = g_strdup(e ? e->message : "initialize GStreamer");
        if (e) g_error_free(e);
        return NULL;
    }
    GstElement *pipeline = gst_parse_launch(description, &e);
    if (e || !pipeline) {
        *error = g_strdup(e ? e->message : "create decoder pipeline");
        if (e) g_error_free(e);
        if (pipeline) gst_object_unref(pipeline);
        return NULL;
    }
    DTReceiverDecoder *p = g_new0(DTReceiverDecoder, 1);
    p->pipeline = pipeline;
    p->source = GST_APP_SRC(gst_bin_get_by_name(GST_BIN(pipeline), "input"));
    p->sink = GST_APP_SINK(gst_bin_get_by_name(GST_BIN(pipeline), "output"));
    p->bus = gst_element_get_bus(pipeline);
    GstElement *decoder = gst_bin_get_by_name(GST_BIN(pipeline), "decoder");
    if (decoder) {
        // Newer audio decoders expose this strictness control. GStreamer 1.16
        // still reports unrecoverable stream/EOS errors without the property.
        if (g_object_class_find_property(G_OBJECT_GET_CLASS(decoder), "max-errors"))
            g_object_set(decoder, "max-errors", 0, NULL);
        gst_object_unref(decoder);
    }
    GstCaps *caps = gst_caps_from_string(caps_string);
    if (config_size) {
        GstBuffer *buffer = gst_buffer_new_allocate(NULL, config_size, NULL);
        gst_buffer_fill(buffer, 0, config, config_size);
        gst_structure_set(gst_caps_get_structure(caps, 0), "codec_data", GST_TYPE_BUFFER, buffer, NULL);
        gst_buffer_unref(buffer);
    }
    gst_app_src_set_caps(p->source, caps);
    gst_caps_unref(caps);
    if (gst_element_set_state(pipeline, GST_STATE_PLAYING) == GST_STATE_CHANGE_FAILURE) {
        *error = dt_receiver_decode_error(p);
        if (!*error) *error = g_strdup("start decoder pipeline");
        gst_element_set_state(pipeline, GST_STATE_NULL);
        gst_object_unref(p->source); gst_object_unref(p->sink);
        gst_object_unref(p->bus); gst_object_unref(pipeline); g_free(p);
        return NULL;
    }
    return p;
}

static int dt_receiver_decoder_push(DTReceiverDecoder *p, const void *data, size_t size, guint64 pts) {
    guint64 queued = 0;
    g_object_get(p->source, "current-level-bytes", &queued, NULL);
    if (queued > 4*1024*1024) return 0;
    GstBuffer *buffer = gst_buffer_new_allocate(NULL, size, NULL);
    gst_buffer_fill(buffer, 0, data, size);
    GST_BUFFER_PTS(buffer) = pts;
    return gst_app_src_push_buffer(p->source, buffer) == GST_FLOW_OK;
}

static GstSample *dt_receiver_decoder_pull(DTReceiverDecoder *p) {
    return gst_app_sink_try_pull_sample(p->sink, 100 * GST_MSECOND);
}
static int dt_receiver_decoder_eos(DTReceiverDecoder *p) { return gst_app_sink_is_eos(p->sink); }
static void dt_receiver_decoder_finish(DTReceiverDecoder *p) { gst_app_src_end_of_stream(p->source); }
static void dt_receiver_decoder_stop(DTReceiverDecoder *p) { gst_element_set_state(p->pipeline, GST_STATE_NULL); }
static void dt_receiver_decoder_free(DTReceiverDecoder *p) {
    dt_receiver_decoder_stop(p);
    gst_object_unref(p->source); gst_object_unref(p->sink);
    gst_object_unref(p->bus); gst_object_unref(p->pipeline); g_free(p);
}
static int dt_receiver_decode_sample(GstSample *sample, const void **data, size_t *size,
    guint64 *pts, int *width, int *height, int *stride, GstMapInfo *map) {
    GstBuffer *buffer = gst_sample_get_buffer(sample);
    if (!buffer || !gst_buffer_map(buffer, map, GST_MAP_READ)) return 0;
    *data = map->data; *size = map->size; *pts = GST_BUFFER_PTS(buffer);
    GstStructure *caps = gst_caps_get_structure(gst_sample_get_caps(sample), 0);
    *width = 0; *height = 0;
    gst_structure_get_int(caps, "width", width);
    gst_structure_get_int(caps, "height", height);
    *stride = 0;
    if (*width > 0 && *height > 0) {
        GstVideoInfo info;
        if (gst_video_info_from_caps(&info, gst_sample_get_caps(sample))) *stride = info.stride[0];
        GstVideoMeta *meta = gst_buffer_get_video_meta(buffer);
        if (meta && meta->offset[0] <= map->size) {
            *stride = meta->stride[0];
            *data = map->data + meta->offset[0]; *size = map->size - meta->offset[0];
        }
    }
    return 1;
}
static void dt_receiver_release_sample(GstSample *sample, GstMapInfo *map) {
    gst_buffer_unmap(gst_sample_get_buffer(sample), map);
    gst_sample_unref(sample);
}
*/
import "C"

import (
	"fmt"
	"sync"
	"time"
	"unsafe"
)

type receiverGstDecoder struct {
	p         *C.DTReceiverDecoder
	mu        sync.Mutex
	closed    bool
	done      chan struct{}
	closeOnce sync.Once
}

func receiverDecoderAvailable() bool { return true }

func receiverHasDecoder(name string) bool {
	s := C.CString(name)
	defer C.free(unsafe.Pointer(s))
	return C.dt_receiver_has_decoder(s) != 0
}

func newReceiverMediaDecoder(codec string, config []byte, callbacks receiverDecodeCallbacks) (receiverDecoder, error) {
	var caps, chain string
	switch codec {
	case "h264":
		decoder := "avdec_h264 max-threads=1"
		if !receiverHasDecoder("avdec_h264") {
			decoder = "openh264dec"
		}
		caps = "video/x-h264,stream-format=avc,alignment=au"
		chain = "h264parse ! " + decoder + " ! videoconvert ! video/x-raw,format=GRAY8"
	case "hevc":
		decoder := "avdec_h265 max-threads=1"
		if !receiverHasDecoder("avdec_h265") {
			decoder = "libde265dec"
		}
		caps = "video/x-h265,stream-format=hvc1,alignment=au"
		chain = "h265parse ! " + decoder + " ! videoconvert ! video/x-raw,format=GRAY8"
	case "alac":
		caps = "audio/x-alac,rate=44100,channels=2"
		chain = "avdec_alac name=decoder ! audioconvert ! audio/x-raw,format=S16LE,layout=interleaved,rate=44100,channels=2"
	default:
		return nil, fmt.Errorf("unsupported receiver decoder %q", codec)
	}
	description := "appsrc name=input is-live=true format=time block=false max-bytes=4194304 ! " + chain + " ! appsink name=output sync=false async=false max-buffers=8 drop=false"
	desc, cs := C.CString(description), C.CString(caps)
	defer C.free(unsafe.Pointer(desc))
	defer C.free(unsafe.Pointer(cs))
	var ptr unsafe.Pointer
	if len(config) > 0 {
		ptr = unsafe.Pointer(&config[0])
	}
	var message *C.char
	p := C.dt_receiver_decoder_new(desc, cs, ptr, C.size_t(len(config)), &message)
	if p == nil {
		if message == nil {
			return nil, fmt.Errorf("create receiver %s decoder", codec)
		}
		defer C.g_free(C.gpointer(message))
		return nil, fmt.Errorf("create receiver %s decoder: %s", codec, C.GoString(message))
	}
	d := &receiverGstDecoder{p: p, done: make(chan struct{})}
	go d.read(callbacks)
	return d, nil
}

func (d *receiverGstDecoder) Push(data []byte, pts int64) error {
	if len(data) == 0 || pts < 0 {
		return fmt.Errorf("invalid decoder sample")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return fmt.Errorf("receiver decoder is closed")
	}
	if C.dt_receiver_decoder_push(d.p, unsafe.Pointer(&data[0]), C.size_t(len(data)), C.guint64(pts)) == 0 {
		return fmt.Errorf("receiver decoder rejected sample or exceeded its bounded queue")
	}
	return nil
}

func (d *receiverGstDecoder) read(callbacks receiverDecodeCallbacks) {
	defer close(d.done)
	for {
		sample := C.dt_receiver_decoder_pull(d.p)
		if sample == nil {
			if message := C.dt_receiver_decode_error(d.p); message != nil {
				callbacks.Error(fmt.Errorf("receiver decode: %s", C.GoString(message)))
				C.g_free(C.gpointer(message))
				return
			}
			if C.dt_receiver_decoder_eos(d.p) != 0 {
				return
			}
			continue
		}
		var ptr unsafe.Pointer
		var size C.size_t
		var pts C.guint64
		var width, height, stride C.int
		var mapping C.GstMapInfo
		if C.dt_receiver_decode_sample(sample, &ptr, &size, &pts, &width, &height, &stride, &mapping) == 0 {
			C.gst_sample_unref(sample)
			callbacks.Error(fmt.Errorf("map decoded receiver sample"))
			return
		}
		// No decoded buffers are retained by the headless sink.
		callbacks.Sample(receiverDecodedSample{Data: unsafe.Slice((*byte)(ptr), int(size)), PTS: int64(pts), Width: int(width), Height: int(height), Stride: int(stride)})
		C.dt_receiver_release_sample(sample, &mapping)
	}
}

func (d *receiverGstDecoder) Close() error {
	d.closeOnce.Do(func() {
		d.mu.Lock()
		d.closed = true
		C.dt_receiver_decoder_finish(d.p)
		d.mu.Unlock()
		select {
		case <-d.done:
		case <-time.After(2 * time.Second):
			C.dt_receiver_decoder_stop(d.p)
			<-d.done
		}
		C.dt_receiver_decoder_free(d.p)
	})
	return nil
}
