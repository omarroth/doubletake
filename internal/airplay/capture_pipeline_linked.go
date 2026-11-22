//go:build cgo && (linux || darwin || windows)

package airplay

/*
#cgo pkg-config: gstreamer-1.0 gstreamer-app-1.0 gstreamer-video-1.0
#include <gst/gst.h>
#include <gst/app/gstappsink.h>
#include <gst/app/gstappsrc.h>
#include <gst/video/video-event.h>
#include <stdlib.h>

#if !GST_CHECK_VERSION(1, 16, 0)
#error "doubletake requires GStreamer 1.16 or newer"
#endif

typedef struct {
	GstElement *pipeline;
	GstElement *encoder;
	GstElement *rate;
	GstAppSink *sink;
	GstAppSink *audio_sink;
	GstBus *bus;
} DTGstPipeline;

static void dt_set_error(char **out, const char *message) {
	if (out != NULL) {
		*out = g_strdup(message != NULL ? message : "unknown GStreamer error");
	}
}

static void dt_set_gerror(char **out, const char *prefix, GError *error) {
	if (out == NULL) return;
	if (error != NULL && error->message != NULL) {
		*out = g_strdup_printf("%s: %s", prefix, error->message);
	} else {
		*out = g_strdup(prefix);
	}
}

static char *dt_bus_error(DTGstPipeline *p) {
	if (p == NULL || p->bus == NULL) return NULL;
	GstMessage *message = gst_bus_pop_filtered(p->bus, GST_MESSAGE_ERROR);
	if (message == NULL) return NULL;
	GError *error = NULL;
	gchar *debug = NULL;
	gst_message_parse_error(message, &error, &debug);
	char *result = g_strdup_printf("%s%s%s",
		error != NULL && error->message != NULL ? error->message : "GStreamer pipeline error",
		debug != NULL ? "; " : "", debug != NULL ? debug : "");
	if (error != NULL) g_error_free(error);
	g_free(debug);
	gst_message_unref(message);
	return result;
}

static void dt_gst_pipeline_free(DTGstPipeline *p);

static char *dt_gst_init(void) {
	GError *error = NULL;
	if (gst_init_check(NULL, NULL, &error)) return NULL;
	char *message = g_strdup(error != NULL ? error->message : "initialize GStreamer");
	if (error != NULL) g_error_free(error);
	return message;
}

static int dt_gst_has_element(const char *name, const char *property) {
	GstElementFactory *factory = gst_element_factory_find(name);
	if (!factory) return 0;
	int found = 1;
	if (property != NULL) {
		GstElement *element = gst_element_factory_create(factory, NULL);
		found = element != NULL && g_object_class_find_property(G_OBJECT_GET_CLASS(element), property) != NULL;
		if (element) gst_object_unref(element);
	}
	gst_object_unref(factory);
	return found;
}

static GstAppSink *dt_find_sink(GstElement *bin, const char *name) {
	if (bin == NULL) return NULL;
	GstElement *sink = GST_IS_BIN(bin) ? gst_bin_get_by_name(GST_BIN(bin), name) : gst_object_ref(bin);
	if (sink == NULL) return NULL;
	if (!GST_IS_APP_SINK(sink)) {
		gst_object_unref(sink);
		return NULL;
	}
	return GST_APP_SINK(sink);
}

static DTGstPipeline *dt_gst_pipeline_new(char **argv, gboolean playback, gboolean output, char **error_out) {
	GError *error = NULL;
	GstElement *pipeline = gst_parse_launchv((const gchar **)argv, &error);
	if (pipeline == NULL || error != NULL || !GST_IS_BIN(pipeline)) {
		dt_set_gerror(error_out, "parse GStreamer pipeline", error);
		if (error != NULL) g_error_free(error);
		if (pipeline != NULL) gst_object_unref(pipeline);
		return NULL;
	}

	DTGstPipeline *result = g_new0(DTGstPipeline, 1);
	result->pipeline = pipeline;
	GstElement *video = pipeline;
	if (playback) {
		GstElement *audio = NULL;
		g_object_get(pipeline, "video-sink", &video, "audio-sink", &audio, NULL);
		result->audio_sink = dt_find_sink(audio, "doubletake-audio-output");
		if (audio != NULL) gst_object_unref(audio);
	}
	if (video != NULL && GST_IS_BIN(video)) {
		result->encoder = gst_bin_get_by_name(GST_BIN(video), "doubletake-encoder");
		result->rate = gst_bin_get_by_name(GST_BIN(video), "doubletake-rate");
	}
	if (output) result->sink = dt_find_sink(video, "doubletake-output");
	if (playback && video != NULL) gst_object_unref(video);
	if ((output && result->sink == NULL) || (playback && result->audio_sink == NULL)) {
		dt_set_error(error_out, "GStreamer graph is missing an appsink");
		dt_gst_pipeline_free(result);
		return NULL;
	}
	result->bus = gst_element_get_bus(pipeline);
	if (gst_element_set_state(pipeline, GST_STATE_PLAYING) == GST_STATE_CHANGE_FAILURE) {
		char *bus_error = dt_bus_error(result);
		dt_set_error(error_out, bus_error != NULL ? bus_error : "put GStreamer pipeline in PLAYING state");
		g_free(bus_error);
		dt_gst_pipeline_free(result);
		return NULL;
	}
	return result;
}

static void dt_gst_wait(DTGstPipeline *p, char **error_out) {
	for (;;) {
		GstMessage *message = gst_bus_timed_pop_filtered(p->bus, 25 * GST_MSECOND,
			GST_MESSAGE_EOS | GST_MESSAGE_ERROR);
		if (message != NULL) {
			if (GST_MESSAGE_TYPE(message) == GST_MESSAGE_ERROR) {
				GError *error = NULL;
				gst_message_parse_error(message, &error, NULL);
				dt_set_gerror(error_out, "GStreamer pipeline", error);
				if (error != NULL) g_error_free(error);
			}
			gst_message_unref(message);
			return;
		}
		GstState state, pending;
		gst_element_get_state(p->pipeline, &state, &pending, 0);
		if (state == GST_STATE_NULL && pending == GST_STATE_VOID_PENDING) return;
	}
}

// Returns one for a mapped sample, zero for no sample, or minus one for a
// bad buffer.
static int dt_gst_pull(GstAppSink *sink, GstSample **sample_out, GstMapInfo *map) {
	GstSample *sample = gst_app_sink_try_pull_sample(sink, 25 * GST_MSECOND);
	if (sample == NULL) return 0;
	GstBuffer *buffer = gst_sample_get_buffer(sample);
	if (buffer == NULL || !gst_buffer_map(buffer, map, GST_MAP_READ)) {
		gst_sample_unref(sample);
		return -1;
	}
	*sample_out = sample;
	return 1;
}

static void dt_gst_release(GstSample *sample, GstMapInfo *map) {
	gst_buffer_unmap(gst_sample_get_buffer(sample), map);
	gst_sample_unref(sample);
}

static int dt_gst_element_set_uint(GstElement *element, const char *property, guint64 value, gboolean require_mutable, char **error_out) {
	if (element == NULL || property == NULL) {
		dt_set_error(error_out, "invalid linked-pipeline property request");
		return 0;
	}
	GParamSpec *spec = g_object_class_find_property(G_OBJECT_GET_CLASS(element), property);
	if (spec == NULL) {
		dt_set_error(error_out, "encoder does not expose the requested property");
		return 0;
	}
	if ((spec->flags & G_PARAM_WRITABLE) == 0 ||
		(require_mutable && (spec->flags & GST_PARAM_MUTABLE_PLAYING) == 0)) {
		dt_set_error(error_out, "encoder property is not mutable while PLAYING");
		return 0;
	}
	GValue setting = G_VALUE_INIT;
	g_value_init(&setting, G_PARAM_SPEC_VALUE_TYPE(spec));
	if (G_VALUE_HOLDS_UINT(&setting)) {
		g_value_set_uint(&setting, value > G_MAXUINT ? G_MAXUINT : (guint)value);
	} else if (G_VALUE_HOLDS_INT(&setting)) {
		g_value_set_int(&setting, value > G_MAXINT ? G_MAXINT : (gint)value);
	} else if (G_VALUE_HOLDS_UINT64(&setting)) {
		g_value_set_uint64(&setting, value);
	} else if (G_VALUE_HOLDS_INT64(&setting)) {
		g_value_set_int64(&setting, value > G_MAXINT64 ? G_MAXINT64 : (gint64)value);
	} else {
		g_value_unset(&setting);
		dt_set_error(error_out, "encoder property is not an integer");
		return 0;
	}
	if (g_param_value_validate(spec, &setting)) {
		g_value_unset(&setting);
		dt_set_error(error_out, "requested encoder value is outside the supported range");
		return 0;
	}
	g_object_set_property(G_OBJECT(element), property, &setting);
	g_value_unset(&setting);
	return 1;
}

static int dt_gst_pipeline_set_encoder_bitrate(DTGstPipeline *p, guint64 value, char **error_out) {
	if (p == NULL || p->encoder == NULL) {
		dt_set_error(error_out, "invalid linked-pipeline bitrate request");
		return 0;
	}
	return dt_gst_element_set_uint(p->encoder, "bitrate", value, TRUE, error_out);
}

static int dt_gst_pipeline_set_v4l2_bitrate(DTGstPipeline *p, guint value, char **error_out) {
	if (p == NULL || p->encoder == NULL) {
		dt_set_error(error_out, "invalid linked-pipeline V4L2 bitrate request");
		return 0;
	}
	GParamSpec *spec = g_object_class_find_property(G_OBJECT_GET_CLASS(p->encoder), "extra-controls");
	if (spec == NULL || (spec->flags & G_PARAM_WRITABLE) == 0) {
		dt_set_error(error_out, "V4L2 encoder does not expose writable extra-controls");
		return 0;
	}
	GstStructure *existing = NULL;
	g_object_get(G_OBJECT(p->encoder), "extra-controls", &existing, NULL);
	GstStructure *controls = existing != NULL ? gst_structure_copy(existing) : gst_structure_new_empty("controls");
	if (existing != NULL) gst_structure_free(existing);
	if (controls == NULL) {
		dt_set_error(error_out, "allocate V4L2 extra-controls");
		return 0;
	}
	// Preserve the encoder's mode, GOP, B-frame, and sequence-header controls;
	// only replace the stateful driver's bitrate control while it is streaming.
	gst_structure_set(controls, "video_bitrate", G_TYPE_INT, (gint)value, NULL);
	g_object_set(G_OBJECT(p->encoder), "extra-controls", controls, NULL);
	gst_structure_free(controls);
	return 1;
}

static int dt_gst_pipeline_set_frame_rate(DTGstPipeline *p, guint value, char **error_out) {
	if (p == NULL || p->rate == NULL) {
		dt_set_error(error_out, "invalid linked-pipeline frame-rate request");
		return 0;
	}
	// videorate protects max-rate internally but does not annotate it with
	// GST_PARAM_MUTABLE_PLAYING. It is specifically intended for live updates.
	return dt_gst_element_set_uint(p->rate, "max-rate", value, FALSE, error_out);
}

static int dt_gst_pipeline_request_key_frame(DTGstPipeline *p, char **error_out) {
	if (p == NULL || p->encoder == NULL) {
		dt_set_error(error_out, "invalid linked-pipeline key-frame request");
		return 0;
	}
	GstPad *src_pad = gst_element_get_static_pad(p->encoder, "src");
	if (src_pad == NULL) {
		dt_set_error(error_out, "encoder has no static source pad");
		return 0;
	}
	GstEvent *event = gst_video_event_new_upstream_force_key_unit(GST_CLOCK_TIME_NONE, TRUE, 0);
	gboolean accepted = gst_pad_send_event(src_pad, event);
	gst_object_unref(src_pad);
	if (!accepted) {
		dt_set_error(error_out, "encoder rejected the force-key-unit event");
		return 0;
	}
	return 1;
}

static void dt_gst_pipeline_stop(DTGstPipeline *p) {
	if (p != NULL && p->pipeline != NULL) {
		gst_element_set_state(p->pipeline, GST_STATE_NULL);
	}
}

static void dt_gst_pipeline_free(DTGstPipeline *p) {
	if (p == NULL) return;
	dt_gst_pipeline_stop(p);
	if (p->bus != NULL) gst_object_unref(p->bus);
	if (p->sink != NULL) gst_object_unref(p->sink);
	if (p->audio_sink != NULL) gst_object_unref(p->audio_sink);
	if (p->rate != NULL) gst_object_unref(p->rate);
	if (p->encoder != NULL) gst_object_unref(p->encoder);
	if (p->pipeline != NULL) gst_object_unref(p->pipeline);
	g_free(p);
}

static void dt_gst_free(void *p) {
	g_free(p);
}
*/
import "C"

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"
	"unsafe"
)

const (
	linkedEncoderName = "doubletake-encoder"
	linkedOutputName  = "doubletake-output"
)

// HasInProcessGStreamer reports whether this binary owns its video pipeline
// through libgstreamer and can change encoder properties while streaming.
func HasInProcessGStreamer() bool { return true }

type linkedGStreamerPipeline struct {
	mu       sync.Mutex
	handle   *C.DTGstPipeline
	video    *io.PipeWriter
	audio    *io.PipeWriter
	wait     chan error
	stopOnce sync.Once
	encoder  string
	cleanup  func()
}

func linkedPipelineArguments(args []string, encoderName string) ([]string, error) {
	return linkedOutputArguments(args, encoderName, linkedOutputName)
}

func linkedOutputArguments(args []string, encoderName, sinkName string) ([]string, error) {
	result := make([]string, 0, len(args)+4)
	namedEncoder := encoderName == ""
	for _, arg := range args {
		if arg == "--quiet" {
			continue
		}
		if arg == "fdsink" {
			if !namedEncoder {
				return nil, fmt.Errorf("GStreamer graph does not contain selected encoder %q", encoderName)
			}
			return append(result, "appsink", "name="+sinkName, "sync=false", "async=false", "max-buffers=8", "drop=false", "wait-on-eos=false"), nil
		}
		result = append(result, arg)
		if arg == encoderName && !namedEncoder {
			result = append(result, "name="+linkedEncoderName)
			namedEncoder = true
		}
	}
	return nil, fmt.Errorf("GStreamer graph is missing its output")
}

func hasGstElement(name string) bool { return hasGstProperty(name, "") }

func hasGstProperty(name, property string) bool {
	if initializeGStreamer() != nil {
		return false
	}
	factory := C.CString(name)
	defer C.free(unsafe.Pointer(factory))
	var field *C.char
	if property != "" {
		field = C.CString(property)
		defer C.free(unsafe.Pointer(field))
	}
	return C.dt_gst_has_element(factory, field) != 0
}

func replacePipelineFD(args []string, inheritedFD, linkedFD int) []string {
	result := append([]string(nil), args...)
	want := "fd=" + strconv.Itoa(inheritedFD)
	replacement := "fd=" + strconv.Itoa(linkedFD)
	for index, arg := range result {
		if arg == want {
			result[index] = replacement
		}
	}
	return result
}

func cError(message *C.char) error {
	if message == nil {
		return nil
	}
	defer C.dt_gst_free(unsafe.Pointer(message))
	return fmt.Errorf("%s", C.GoString(message))
}

var initializeGStreamer = sync.OnceValue(func() error {
	return cError(C.dt_gst_init())
})

func openLinkedGStreamerGraph(args []string, playback, output bool) (*C.DTGstPipeline, error) {
	if err := initializeGStreamer(); err != nil {
		return nil, err
	}
	cArgs := make([]*C.char, len(args)+1)
	for index, arg := range args {
		cArgs[index] = C.CString(arg)
		defer C.free(unsafe.Pointer(cArgs[index]))
	}
	var playbackFlag, outputFlag C.gboolean
	if playback {
		playbackFlag = 1
	}
	if output {
		outputFlag = 1
	}
	var message *C.char
	handle := C.dt_gst_pipeline_new((**C.char)(unsafe.Pointer(&cArgs[0])), playbackFlag, outputFlag, &message)
	if handle == nil {
		return nil, cError(message)
	}
	return handle, nil
}

func probeGstPipeline(ctx context.Context, args []string) error {
	handle, err := openLinkedGStreamerGraph(args, false, false)
	if err != nil {
		return fmt.Errorf("start GStreamer source probe: %w", err)
	}
	p := &linkedGStreamerPipeline{handle: handle, wait: make(chan error, 1)}
	p.run(ctx, handle)
	if err := ctx.Err(); err != nil {
		return err
	}
	return <-p.wait
}

func startLinkedGraph(ctx context.Context, handle *C.DTGstPipeline, encoder string, audio bool, cleanup func()) (*runningGStreamerPipeline, io.ReadCloser) {
	reader, writer := io.Pipe()
	p := &linkedGStreamerPipeline{handle: handle, video: writer, encoder: encoder, wait: make(chan error, 1), cleanup: cleanup}
	var pcm io.ReadCloser
	if audio {
		pcm, p.audio = io.Pipe()
	}
	go p.run(ctx, handle)
	return &runningGStreamerPipeline{stdout: reader, waitResult: p.wait, runtime: p}, pcm
}

func launchLinkedMediaGraph(ctx context.Context, uri string, encoder encoderResult, videoArgs, audioArgs []string) (*runningGStreamerPipeline, io.ReadCloser, error) {
	video, err := linkedPipelineArguments(videoArgs, encoder.name)
	if err != nil {
		return nil, nil, err
	}
	audio, err := linkedOutputArguments(audioArgs, "", "doubletake-audio-output")
	if err != nil {
		return nil, nil, err
	}
	handle, err := openLinkedGStreamerGraph(mediaGraphArgs(uri, video, audio), true, true)
	if err != nil {
		return nil, nil, err
	}
	pipeline, pcm := startLinkedGraph(ctx, handle, encoder.name, true, nil)
	return pipeline, pcm, nil
}

func (p *linkedGStreamerPipeline) run(ctx context.Context, handle *C.DTGstPipeline) {
	stop := context.AfterFunc(ctx, p.stop)
	defer stop()
	ended := make(chan struct{})
	var pumps sync.WaitGroup
	if p.video != nil {
		pumps.Go(func() { p.pump(handle.sink, p.video, ended) })
	}
	if p.audio != nil {
		pumps.Go(func() { p.pump(handle.audio_sink, p.audio, ended) })
	}
	var message *C.char
	C.dt_gst_wait(handle, &message)
	err := cError(message)
	if err != nil {
		p.abort(err)
	}
	close(ended)
	pumps.Wait()
	p.mu.Lock()
	p.handle = nil
	p.mu.Unlock()
	C.dt_gst_pipeline_free(handle)
	if p.cleanup != nil {
		p.cleanup()
	}
	p.wait <- err
	close(p.wait)
}

func (p *linkedGStreamerPipeline) pump(sink *C.GstAppSink, writer *io.PipeWriter, ended <-chan struct{}) {
	defer writer.Close()
	received := false
	for {
		var sample *C.GstSample
		var mapped C.GstMapInfo
		switch C.dt_gst_pull(sink, &sample, &mapped) {
		case -1:
			p.abort(fmt.Errorf("map GStreamer appsink buffer"))
			return
		case 0:
			select {
			case <-ended:
				return
			default:
			}
			if received && C.gst_app_sink_is_eos(sink) != 0 {
				return
			}
			// An inactive playbin sink can appear to be at EOS before
			// track selection and return immediately without a sample.
			if !received && C.gst_app_sink_is_eos(sink) != 0 {
				time.Sleep(2 * time.Millisecond)
			}
		case 1:
			received = true
			payload := C.GoBytes(unsafe.Pointer(mapped.data), C.int(mapped.size))
			C.dt_gst_release(sample, &mapped)
			if len(payload) == 0 {
				continue
			}
			if _, err := writer.Write(payload); err != nil {
				p.stop()
				return
			}
		}
	}
}

func (p *linkedGStreamerPipeline) withHandle(action func(*C.DTGstPipeline, **C.char) C.int) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.handle == nil {
		return fmt.Errorf("linked GStreamer pipeline has stopped")
	}
	var message *C.char
	if action(p.handle, &message) == 0 {
		if err := cError(message); err != nil {
			return err
		}
		return fmt.Errorf("linked GStreamer operation failed")
	}
	return nil
}

func (p *linkedGStreamerPipeline) setBitrateKbps(bitrate int) error {
	value, v4l2, err := linkedEncoderBitrateValue(p.encoder, bitrate)
	if err != nil {
		return err
	}
	if v4l2 {
		if value > uint64(^uint32(0)) {
			return fmt.Errorf("V4L2 bitrate is outside the supported range")
		}
		return p.withHandle(func(handle *C.DTGstPipeline, message **C.char) C.int {
			return C.dt_gst_pipeline_set_v4l2_bitrate(handle, C.guint(value), message)
		})
	}
	return p.withHandle(func(handle *C.DTGstPipeline, message **C.char) C.int {
		return C.dt_gst_pipeline_set_encoder_bitrate(handle, C.guint64(value), message)
	})
}

func linkedEncoderBitrateValue(encoder string, bitrateKbps int) (value uint64, v4l2 bool, err error) {
	if bitrateKbps <= 0 {
		return 0, false, fmt.Errorf("bitrate must be positive")
	}
	value = uint64(bitrateKbps)
	switch encoder {
	case "openh264enc", "v4l2h264enc":
		if value > ^uint64(0)/1000 {
			return 0, false, fmt.Errorf("bitrate is outside the supported range")
		}
		return value * 1000, encoder == "v4l2h264enc", nil
	default:
		// x264/x265, VA, NVENC, and Vulkan encoders expose kbit/s.
		return value, false, nil
	}
}

func (p *linkedGStreamerPipeline) setFrameRate(fps int) error {
	if fps <= 0 {
		return fmt.Errorf("frame rate must be positive")
	}
	return p.withHandle(func(handle *C.DTGstPipeline, message **C.char) C.int {
		return C.dt_gst_pipeline_set_frame_rate(handle, C.guint(fps), message)
	})
}

func (p *linkedGStreamerPipeline) requestKeyFrame() error {
	return p.withHandle(func(handle *C.DTGstPipeline, message **C.char) C.int {
		return C.dt_gst_pipeline_request_key_frame(handle, message)
	})
}

func (p *linkedGStreamerPipeline) stop() { p.abort(nil) }

func (p *linkedGStreamerPipeline) abort(err error) {
	p.stopOnce.Do(func() {
		if p.video != nil {
			_ = p.video.CloseWithError(err)
		}
		if p.audio != nil {
			_ = p.audio.CloseWithError(err)
		}
		p.mu.Lock()
		if p.handle != nil {
			C.dt_gst_pipeline_stop(p.handle)
		}
		p.mu.Unlock()
	})
}

func launchGStreamerPipeline(ctx context.Context, args []string, encoder encoderResult, portal *os.File) (*runningGStreamerPipeline, error) {
	linked, err := linkedPipelineArguments(args, encoder.name)
	if err != nil {
		return nil, err
	}
	var cleanup func()
	if portal != nil {
		linked, cleanup, err = linkedPortalArguments(linked, portal)
		if err != nil {
			return nil, err
		}
	}
	handle, err := openLinkedGStreamerGraph(linked, false, true)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return nil, fmt.Errorf("start GStreamer pipeline: %w", err)
	}
	pipeline, _ := startLinkedGraph(ctx, handle, encoder.name, false, cleanup)
	return pipeline, nil
}

func launchAudioPipeline(ctx context.Context, args []string, native bool) (*runningGStreamerPipeline, error) {
	linked, err := linkedPipelineArguments(args, "")
	if err != nil {
		return nil, err
	}
	handle, err := openLinkedGStreamerGraph(linked, false, true)
	if err != nil {
		return nil, err
	}
	var cleanup func()
	if native {
		cleanup, err = startSystemAudio(unsafe.Pointer(handle.pipeline))
		if err != nil {
			C.dt_gst_pipeline_free(handle)
			return nil, err
		}
	}
	pipeline, _ := startLinkedGraph(ctx, handle, "", false, cleanup)
	return pipeline, nil
}
