//go:build gstreamer_cgo && cgo && linux

package airplay

/*
#cgo pkg-config: gstreamer-1.0 gstreamer-app-1.0 gstreamer-video-1.0
#include <gst/gst.h>
#include <gst/app/gstappsink.h>
#include <gst/video/video-event.h>
#include <stdlib.h>

typedef struct {
	GstElement *pipeline;
	GstElement *encoder;
	GstAppSink *sink;
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

static DTGstPipeline *dt_gst_pipeline_new(char **argv, char **error_out) {
	GError *error = NULL;
	if (!gst_init_check(NULL, NULL, &error)) {
		dt_set_gerror(error_out, "initialize GStreamer", error);
		if (error != NULL) g_error_free(error);
		return NULL;
	}

	GstElement *pipeline = gst_parse_launchv((const gchar **)argv, &error);
	if (pipeline == NULL) {
		dt_set_gerror(error_out, "parse GStreamer pipeline", error);
		if (error != NULL) g_error_free(error);
		return NULL;
	}
	if (error != NULL) {
		dt_set_gerror(error_out, "parse GStreamer pipeline", error);
		g_error_free(error);
		gst_object_unref(pipeline);
		return NULL;
	}
	if (!GST_IS_BIN(pipeline)) {
		dt_set_error(error_out, "parsed GStreamer graph is not a bin");
		gst_object_unref(pipeline);
		return NULL;
	}

	DTGstPipeline *result = g_new0(DTGstPipeline, 1);
	result->pipeline = pipeline;
	result->encoder = gst_bin_get_by_name(GST_BIN(pipeline), "doubletake-encoder");
	GstElement *sink = gst_bin_get_by_name(GST_BIN(pipeline), "doubletake-output");
	if (result->encoder == NULL || sink == NULL || !GST_IS_APP_SINK(sink)) {
		dt_set_error(error_out, "linked pipeline is missing its named encoder or appsink");
		if (sink != NULL) gst_object_unref(sink);
		if (result->encoder != NULL) gst_object_unref(result->encoder);
		gst_object_unref(pipeline);
		g_free(result);
		return NULL;
	}
	result->sink = GST_APP_SINK(sink);
	result->bus = gst_element_get_bus(pipeline);
	gst_app_sink_set_emit_signals(result->sink, FALSE);
	gst_app_sink_set_drop(result->sink, FALSE);
	gst_app_sink_set_max_buffers(result->sink, 8);

	GstStateChangeReturn state = gst_element_set_state(pipeline, GST_STATE_PLAYING);
	if (state == GST_STATE_CHANGE_FAILURE) {
		char *bus_error = dt_bus_error(result);
		dt_set_error(error_out, bus_error != NULL ? bus_error : "put GStreamer pipeline in PLAYING state");
		g_free(bus_error);
		gst_element_set_state(pipeline, GST_STATE_NULL);
		gst_object_unref(result->bus);
		gst_object_unref(result->sink);
		gst_object_unref(result->encoder);
		gst_object_unref(result->pipeline);
		g_free(result);
		return NULL;
	}
	return result;
}

// Returns one for a sample, zero for EOS/stop, and minus one for an error.
static int dt_gst_pipeline_pull(DTGstPipeline *p, unsigned char **data_out, size_t *size_out, char **error_out) {
	if (p == NULL || data_out == NULL || size_out == NULL) {
		dt_set_error(error_out, "invalid linked-pipeline pull arguments");
		return -1;
	}
	*data_out = NULL;
	*size_out = 0;
	GstSample *sample = gst_app_sink_pull_sample(p->sink);
	if (sample == NULL) {
		char *bus_error = dt_bus_error(p);
		if (bus_error != NULL) {
			dt_set_error(error_out, bus_error);
			g_free(bus_error);
			return -1;
		}
		return 0;
	}
	GstBuffer *buffer = gst_sample_get_buffer(sample);
	GstMapInfo map;
	if (buffer == NULL || !gst_buffer_map(buffer, &map, GST_MAP_READ)) {
		dt_set_error(error_out, "map GStreamer appsink buffer");
		gst_sample_unref(sample);
		return -1;
	}
	if (map.size != 0) {
		*data_out = g_memdup2(map.data, map.size);
		*size_out = map.size;
	}
	gst_buffer_unmap(buffer, &map);
	gst_sample_unref(sample);
	return 1;
}

static int dt_gst_pipeline_set_uint(DTGstPipeline *p, const char *property, guint64 value, char **error_out) {
	if (p == NULL || p->encoder == NULL || property == NULL) {
		dt_set_error(error_out, "invalid linked-pipeline property request");
		return 0;
	}
	GParamSpec *spec = g_object_class_find_property(G_OBJECT_GET_CLASS(p->encoder), property);
	if (spec == NULL) {
		dt_set_error(error_out, "encoder does not expose the requested property");
		return 0;
	}
	if ((spec->flags & G_PARAM_WRITABLE) == 0 || (spec->flags & GST_PARAM_MUTABLE_PLAYING) == 0) {
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
	g_object_set_property(G_OBJECT(p->encoder), property, &setting);
	g_value_unset(&setting);
	return 1;
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
	"syscall"
	"unsafe"
)

const (
	linkedEncoderName = "doubletake-encoder"
	linkedOutputName  = "doubletake-output"
)

type linkedGStreamerPipeline struct {
	mu       sync.Mutex
	handle   *C.DTGstPipeline
	reader   *io.PipeReader
	writer   *io.PipeWriter
	wait     chan error
	done     chan struct{}
	stopOnce sync.Once
	encoder  string
}

func linkedPipelineArguments(args []string, encoderName string) ([]string, error) {
	result := make([]string, 0, len(args)+4)
	namedEncoder := false
	replacedSink := false
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if arg == "--quiet" {
			continue
		}
		if arg == "fdsink" {
			result = append(result, "appsink", "name="+linkedOutputName, "sync=false", "async=false", "max-buffers=8", "drop=false")
			replacedSink = true
			break
		}
		result = append(result, arg)
		if arg == encoderName {
			result = append(result, "name="+linkedEncoderName)
			namedEncoder = true
		}
	}
	if !namedEncoder {
		return nil, fmt.Errorf("GStreamer graph does not contain selected encoder %q", encoderName)
	}
	if !replacedSink {
		return nil, fmt.Errorf("GStreamer graph does not end in fdsink")
	}
	return result, nil
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

func newLinkedGStreamerPipeline(ctx context.Context, args []string, encoder encoderResult, extraFiles []*os.File) (*linkedGStreamerPipeline, error) {
	linkedArgs, err := linkedPipelineArguments(args, encoder.name)
	if err != nil {
		return nil, err
	}
	if len(extraFiles) > 1 {
		return nil, fmt.Errorf("linked GStreamer supports at most one inherited PipeWire descriptor")
	}
	if len(extraFiles) == 1 {
		fd, err := syscall.Dup(int(extraFiles[0].Fd()))
		if err != nil {
			return nil, fmt.Errorf("duplicate PipeWire descriptor: %w", err)
		}
		// gst-launch receives the first ExtraFiles descriptor as fd 3. The
		// in-process pipewiresrc instead owns this duplicate directly.
		linkedArgs = replacePipelineFD(linkedArgs, 3, fd)
	}

	cArgs := make([]*C.char, len(linkedArgs)+1)
	for index, arg := range linkedArgs {
		cArgs[index] = C.CString(arg)
	}
	defer func() {
		for _, arg := range cArgs[:len(linkedArgs)] {
			C.free(unsafe.Pointer(arg))
		}
	}()
	var message *C.char
	handle := C.dt_gst_pipeline_new((**C.char)(unsafe.Pointer(&cArgs[0])), &message)
	if handle == nil {
		if err := cError(message); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("create linked GStreamer pipeline")
	}

	reader, writer := io.Pipe()
	pipeline := &linkedGStreamerPipeline{
		handle: handle, reader: reader, writer: writer,
		wait: make(chan error, 1), done: make(chan struct{}), encoder: encoder.name,
	}
	go pipeline.run()
	go func() {
		select {
		case <-ctx.Done():
			pipeline.stop()
		case <-pipeline.done:
		}
	}()
	return pipeline, nil
}

func (p *linkedGStreamerPipeline) run() {
	var result error
	defer func() {
		p.mu.Lock()
		handle := p.handle
		p.handle = nil
		p.mu.Unlock()
		if handle != nil {
			C.dt_gst_pipeline_free(handle)
		}
		_ = p.writer.CloseWithError(result)
		close(p.done)
		p.wait <- result
		close(p.wait)
	}()

	for {
		var data *C.uchar
		var size C.size_t
		var message *C.char
		status := C.dt_gst_pipeline_pull(p.handle, &data, &size, &message)
		if status < 0 {
			result = cError(message)
			return
		}
		if status == 0 {
			return
		}
		payload := C.GoBytes(unsafe.Pointer(data), C.int(size))
		C.dt_gst_free(unsafe.Pointer(data))
		if len(payload) == 0 {
			continue
		}
		if _, err := p.writer.Write(payload); err != nil {
			return
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
	value := uint64(bitrate)
	if p.encoder == "openh264enc" {
		value *= 1000
	}
	if p.encoder == "v4l2h264enc" {
		return fmt.Errorf("v4l2h264enc runtime bitrate control requires changing its V4L2 extra-controls structure")
	}
	return p.withHandle(func(handle *C.DTGstPipeline, message **C.char) C.int {
		property := C.CString("bitrate")
		defer C.free(unsafe.Pointer(property))
		return C.dt_gst_pipeline_set_uint(handle, property, C.guint64(value), message)
	})
}

func (p *linkedGStreamerPipeline) requestKeyFrame() error {
	return p.withHandle(func(handle *C.DTGstPipeline, message **C.char) C.int {
		return C.dt_gst_pipeline_request_key_frame(handle, message)
	})
}

func (p *linkedGStreamerPipeline) stop() {
	p.stopOnce.Do(func() {
		p.mu.Lock()
		if p.handle != nil {
			C.dt_gst_pipeline_stop(p.handle)
		}
		p.mu.Unlock()
	})
}

func launchLinkedGStreamerPipeline(ctx context.Context, args []string, encoder encoderResult, extraFiles []*os.File) (*runningGStreamerPipeline, bool, error) {
	pipeline, err := newLinkedGStreamerPipeline(ctx, args, encoder, extraFiles)
	if err != nil {
		return nil, true, err
	}
	return &runningGStreamerPipeline{
		stdout: pipeline.reader, waitResult: pipeline.wait, runtime: pipeline,
	}, true, nil
}
