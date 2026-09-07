package airplay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

func TestCapturePreparationCloseReleasesUnstartedResources(t *testing.T) {
	portalFD, peerFD, err := os.Pipe()
	if err != nil {
		t.Fatalf("create portal pipe: %v", err)
	}
	defer peerFD.Close()

	preparation := &CapturePreparation{
		kind: capturePreparationWayland,
		pwFd: portalFD,
	}
	preparation.Close()
	preparation.Close() // cleanup must remain idempotent

	if _, err := portalFD.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("portal FD after Close: %v, want os.ErrClosed", err)
	}
	if preparation.pwFd != nil {
		t.Fatal("closed preparation retained its portal FD")
	}
	if _, err := preparation.Start(1920, 1080); err == nil || !strings.Contains(err.Error(), "already been used") {
		t.Fatalf("Start after Close error = %v, want single-use rejection", err)
	}
}

func TestCapturePreparationFailedStartReleasesTransferredResources(t *testing.T) {
	portalFD, peerFD, err := os.Pipe()
	if err != nil {
		t.Fatalf("create portal pipe: %v", err)
	}
	defer peerFD.Close()

	preparation := &CapturePreparation{
		cfg:  CaptureConfig{HWAccel: "invalid-for-test"},
		kind: capturePreparationWayland,
		pwFd: portalFD,
	}
	if _, err := preparation.Start(1920, 1080); err == nil || !strings.Contains(err.Error(), "unknown encoder") {
		t.Fatalf("failed Start error = %v, want deterministic encoder validation error", err)
	}
	if _, err := portalFD.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("transferred portal FD after failed Start: %v, want os.ErrClosed", err)
	}
	if preparation.pwFd != nil {
		t.Fatal("failed Start retained its transferred portal FD")
	}
	preparation.Close() // Start owns cleanup after the ownership transfer.
	if _, err := preparation.Start(1280, 720); err == nil || !strings.Contains(err.Error(), "already been used") {
		t.Fatalf("second Start error = %v, want single-use rejection", err)
	}
}

func TestAutomaticCapturePreparationRequiresResolvedCodec(t *testing.T) {
	preparation := &CapturePreparation{cfg: CaptureConfig{VideoCodec: VideoCodecAuto}}
	if _, err := preparation.Start(1920, 1080); err == nil || !strings.Contains(err.Error(), "has not been resolved") {
		t.Fatalf("unresolved automatic Start error = %v", err)
	}
	if preparation.used {
		t.Fatal("unresolved automatic Start consumed the preparation")
	}
}

func TestAutomaticCodecRejectsUnresolvedConvenienceCapture(t *testing.T) {
	if _, err := StartTestCapture(context.Background(), CaptureConfig{VideoCodec: VideoCodecAuto}); err == nil || !strings.Contains(err.Error(), "StartWithCodec") {
		t.Fatalf("StartTestCapture(auto) error = %v", err)
	}
}

func TestAutomaticHEVCAvailabilityRequiresHardwareAndFullTimestampStack(t *testing.T) {
	elements := map[string]bool{
		"nvh265enc":         true,
		"h265parse":         true,
		"rtph265pay":        true,
		"rtponviftimestamp": true,
		"rtpstreampay":      true,
	}
	probe := func(name string) bool { return elements[name] }
	for _, hwaccel := range []string{"", "auto", "nvenc"} {
		if !automaticHEVCAvailableWithProbe(hwaccel, probe) {
			t.Errorf("automatic HEVC unavailable for hwaccel %q with complete hardware stack", hwaccel)
		}
	}
	for _, hwaccel := range []string{"none", "vaapi", "openh264"} {
		if automaticHEVCAvailableWithProbe(hwaccel, probe) {
			t.Errorf("automatic HEVC accepted non-hardware-HEVC hwaccel %q", hwaccel)
		}
	}
	for _, missing := range []string{"nvh265enc", "h265parse", "rtph265pay", "rtponviftimestamp", "rtpstreampay"} {
		elements[missing] = false
		if automaticHEVCAvailableWithProbe("auto", probe) {
			t.Errorf("automatic HEVC accepted stack missing %s", missing)
		}
		elements[missing] = true
	}
}

func TestRecommendedAutomaticVideoLatencyUsesP95AndDeliveryMargin(t *testing.T) {
	if _, ok := recommendedAutomaticVideoLatency(nil, 30); ok {
		t.Fatal("empty latency sample set was accepted")
	}
	if got, ok := recommendedAutomaticVideoLatency([]time.Duration{5 * time.Millisecond}, 30); !ok || got != defaultVideoLatencyNormal {
		t.Fatalf("fast pipeline recommendation = (%v, %t), want (%v, true)", got, ok, defaultVideoLatencyNormal)
	}
	ages := make([]time.Duration, 20)
	for i := range ages {
		ages[i] = time.Duration(80+i) * time.Millisecond
	}
	got, ok := recommendedAutomaticVideoLatency(ages, 30)
	// p95 is the nineteenth value (98 ms); reserve the 67 ms delivery-margin
	// heuristic derived from Apple's upstream source-queue ceiling.
	if !ok || got != 165*time.Millisecond {
		t.Fatalf("measured recommendation = (%v, %t), want (165ms, true)", got, ok)
	}
	if _, ok := recommendedAutomaticVideoLatency([]time.Duration{440 * time.Millisecond}, 30); ok {
		t.Fatal("pipeline exceeding the bounded automatic lead was accepted")
	}
	if got := automaticVideoDeliveryMargin(20); got != 100*time.Millisecond {
		t.Fatalf("20fps delivery margin = %v, want two frame periods", got)
	}
	if got := automaticVideoDeliveryMargin(60); got != ordinaryScreenFrameQueueDuration {
		t.Fatalf("60fps delivery margin = %v, want ordinary 67ms floor", got)
	}
}

func TestLiveVideoProbeTimeoutTracksConfiguredFrameRate(t *testing.T) {
	if got := liveVideoProbeTimeout(30); got != minimumLiveVideoProbeTimeout {
		t.Fatalf("30fps live probe timeout = %v, want %v", got, minimumLiveVideoProbeTimeout)
	}
	if got := liveVideoProbeTimeout(5); got != 7*time.Second {
		t.Fatalf("5fps live probe timeout = %v, want 7s", got)
	}
	if got := liveVideoProbeTimeout(0); got != minimumLiveVideoProbeTimeout {
		t.Fatalf("default-fps live probe timeout = %v, want %v", got, minimumLiveVideoProbeTimeout)
	}
}

type fixedAgeVideoReader struct {
	age time.Duration
	pts bool
}

func (r fixedAgeVideoReader) ReadVideoAccessUnit() (VideoAccessUnit, error) {
	frame := VideoAccessUnit{AnnexB: []byte{0, 0, 0, 1, 0x26}}
	if r.pts {
		frame.PTS = time.Now().Add(-r.age)
	}
	return frame, nil
}

func TestMeasureVideoCaptureLatencyUsesProductionSourceAge(t *testing.T) {
	capture := &ScreenCapture{
		frames: fixedAgeVideoReader{age: 100 * time.Millisecond, pts: true},
		waitCh: make(chan struct{}),
	}
	lead, err := MeasureVideoCaptureLatency(context.Background(), capture, 30)
	if err != nil {
		t.Fatalf("measure production capture: %v", err)
	}
	if lead < 167*time.Millisecond || lead > 200*time.Millisecond {
		t.Fatalf("production lead = %v, want approximately 167ms", lead)
	}

	untimestamped := &ScreenCapture{
		frames: fixedAgeVideoReader{},
		waitCh: make(chan struct{}),
	}
	if _, err := MeasureVideoCaptureLatency(context.Background(), untimestamped, 30); err == nil {
		t.Fatal("untimestamped production capture was accepted")
	}
}

type blockingVideoReader struct {
	closed chan struct{}
	waitCh chan struct{}
}

func (r *blockingVideoReader) Read([]byte) (int, error) {
	<-r.closed
	return 0, os.ErrClosed
}

func (r *blockingVideoReader) ReadVideoAccessUnit() (VideoAccessUnit, error) {
	<-r.closed
	return VideoAccessUnit{}, os.ErrClosed
}

func (r *blockingVideoReader) Close() error {
	close(r.closed)
	close(r.waitCh)
	return nil
}

func TestMeasureVideoCaptureLatencyCancellationInterruptsRead(t *testing.T) {
	waitCh := make(chan struct{})
	reader := &blockingVideoReader{closed: make(chan struct{}), waitCh: waitCh}
	capture := &ScreenCapture{stdout: reader, frames: reader, waitCh: waitCh}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := MeasureVideoCaptureLatency(ctx, capture, 30); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("canceled measurement = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("canceled measurement took %v", elapsed)
	}
	if !capture.stopped {
		t.Fatal("canceled measurement left its capture reader active")
	}
}

func TestStartGStreamerCommandSetsParentDeathSignal(t *testing.T) {
	cmd := exec.Command("true")
	waitResult, err := startGStreamerCommand(cmd)
	if err != nil {
		t.Fatalf("startGStreamerCommand: %v", err)
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("Pdeathsig = %v, want SIGKILL", cmd.SysProcAttr)
	}
	if err := <-waitResult; err != nil {
		t.Fatalf("wait for supervised command: %v", err)
	}
}

func TestValidateHWAccel(t *testing.T) {
	for _, method := range []string{"", "auto", "nvenc", "vaapi", "openh264", "none"} {
		if err := ValidateHWAccel(method); err != nil {
			t.Errorf("ValidateHWAccel(%q): %v", method, err)
		}
	}
	for _, method := range []string{"x264", "OPENH264", "bogus", " auto"} {
		err := ValidateHWAccel(method)
		if err == nil {
			t.Errorf("ValidateHWAccel(%q) succeeded", method)
		} else if !strings.Contains(err.Error(), method) {
			t.Errorf("ValidateHWAccel(%q) error %q does not name the invalid value", method, err)
		}
	}
}

func TestStartTestCaptureRejectsUnknownHWAccel(t *testing.T) {
	capture, err := StartTestCapture(context.Background(), CaptureConfig{HWAccel: "bogus"})
	if err == nil {
		if capture != nil {
			capture.Stop()
		}
		t.Fatal("StartTestCapture accepted an unknown hwaccel value")
	}
	if !strings.Contains(err.Error(), "unknown encoder") {
		t.Fatalf("StartTestCapture error = %q", err)
	}
}

func TestRecommendedBitrateKbps(t *testing.T) {
	tests := []struct {
		name   string
		width  int
		height int
		fps    int
		want   int
	}{
		{
			name:   "defaults when dimensions invalid",
			width:  0,
			height: 1080,
			fps:    30,
			want:   defaultVideoBitrateKbps,
		},
		{
			name:   "low resolution clamps to floor",
			width:  640,
			height: 360,
			fps:    30,
			want:   minVideoBitrateKbps,
		},
		{
			name:   "720p30 stays near wifi target",
			width:  1280,
			height: 720,
			fps:    30,
			want:   1843,
		},
		{
			name:   "1080p30 uses wifi friendly auto bitrate",
			width:  1920,
			height: 1080,
			fps:    30,
			want:   4147,
		},
		{
			name:   "high resolutions clamp to max",
			width:  3840,
			height: 2160,
			fps:    60,
			want:   maxVideoBitrateKbps,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := recommendedBitrateKbps(tt.width, tt.height, tt.fps); got != tt.want {
				t.Fatalf("recommendedBitrateKbps(%d, %d, %d) = %d, want %d", tt.width, tt.height, tt.fps, got, tt.want)
			}
		})
	}
}

func TestCaptureBitrateUsesReceiverSize(t *testing.T) {
	if got := captureBitrateKbps(CaptureConfig{FPS: 30, MaxWidth: 1280, MaxHeight: 720}); got != 1843 {
		t.Fatalf("720p receiver auto bitrate = %d, want 1843", got)
	}
	if got := captureBitrateKbps(CaptureConfig{FPS: 30, MaxWidth: 1280}); got != 4147 {
		t.Fatalf("partial receiver size auto bitrate = %d, want 1080p fallback 4147", got)
	}
	if got := captureBitrateKbps(CaptureConfig{FPS: 30, Bitrate: 3000, MaxWidth: 1280, MaxHeight: 720}); got != 3000 {
		t.Fatalf("explicit bitrate = %d, want 3000", got)
	}
	if got := captureBitrateKbps(CaptureConfig{FPS: 30, MaxWidth: 3840, MaxHeight: 2160}); got != 4147 {
		t.Fatalf("4K receiver ceiling auto bitrate = %d, want 1080p budget 4147", got)
	}
}

func TestKeyframeIntervalFrames(t *testing.T) {
	if got := keyframeIntervalFrames(30); got != 60 {
		t.Fatalf("keyframeIntervalFrames(30) = %d, want 60", got)
	}
	if got := keyframeIntervalFrames(0); got != 60 {
		t.Fatalf("keyframeIntervalFrames(0) = %d, want 60", got)
	}
}

func TestFrameIntervalMillis(t *testing.T) {
	for _, tt := range []struct {
		fps  int
		want int
	}{
		{fps: 30, want: 33},
		{fps: 60, want: 16},
		{fps: 0, want: 33},
		{fps: 2000, want: 1},
	} {
		if got := frameIntervalMillis(tt.fps); got != tt.want {
			t.Errorf("frameIntervalMillis(%d) = %d, want %d", tt.fps, got, tt.want)
		}
	}
}

func TestPipeWireVideoSourceBufferPoolPolicy(t *testing.T) {
	base := gstStage{
		"pipewiresrc",
		"fd=3",
		"path=42",
		"do-timestamp=true",
		"keepalive-time=33",
	}
	for _, test := range []struct {
		name       string
		alwaysCopy bool
		want       gstStage
	}{
		{name: "native import", want: base},
		{name: "retaining system path", alwaysCopy: true, want: append(append(gstStage(nil), base...), "always-copy=true")},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := pipeWireVideoSourceStage(3, 42, 30, test.alwaysCopy)
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("PipeWire source stage = %v, want %v", got, test.want)
			}
		})
	}
}

func TestPortalStreamDimensions(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value interface{}
		wantW int
		wantH int
		want  bool
	}{
		{name: "signed tuple", value: []int32{1920, 1080}, wantW: 1920, wantH: 1080, want: true},
		{name: "unsigned tuple", value: []uint32{2560, 1440}, wantW: 2560, wantH: 1440, want: true},
		{name: "variant struct", value: []interface{}{int32(3840), int32(2160)}, wantW: 3840, wantH: 2160, want: true},
		{name: "invalid", value: []int32{1920}, want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			width, height, ok := portalStreamDimensions(map[string]dbus.Variant{"size": dbus.MakeVariant(tt.value)})
			if width != tt.wantW || height != tt.wantH || ok != tt.want {
				t.Fatalf("portalStreamDimensions() = (%d, %d, %t), want (%d, %d, %t)", width, height, ok, tt.wantW, tt.wantH, tt.want)
			}
		})
	}
}

func TestVbvBufferKbit(t *testing.T) {
	tests := []struct {
		name    string
		bitrate int
		fps     int
		want    int
	}{
		{"invalid returns default", 0, 30, 300},
		{"low bitrate clamps to floor", 1800, 30, 200},
		{"1080p30 auto bitrate", 4147, 30, 276},
		{"high bitrate 60fps", 12000, 60, 400},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := vbvBufferKbit(tt.bitrate, tt.fps); got != tt.want {
				t.Fatalf("vbvBufferKbit(%d, %d) = %d, want %d", tt.bitrate, tt.fps, got, tt.want)
			}
		})
	}
}

func TestBuildGstVideoPipeline(t *testing.T) {
	encoder := encoderResult{
		parts:     gstStage{"testh264enc", "bitrate=2500"},
		rawFormat: "I420",
	}
	got := buildGstVideoPipeline(
		gstStage{"testsrc", "is-live=true"},
		[]gstStage{{"sourcefilter", "mode=test"}},
		[]gstStage{{"videorate", "drop-only=true"}, frameRateStage(30), lowLatencyVideoQueueStage()},
		encoder,
		0,
		0,
		false,
	)
	want := []string{
		"--quiet", "testsrc", "is-live=true",
		"!", "sourcefilter", "mode=test",
		"!", "videoconvert",
		"!", "video/x-raw,format=I420",
		"!", "videorate", "drop-only=true",
		"!", "video/x-raw,framerate=30/1",
		"!", "queue", "max-size-buffers=1", "max-size-bytes=0", "max-size-time=0", "leaky=downstream",
		"!", "testh264enc", "bitrate=2500",
		"!", "h264parse", "config-interval=-1",
		"!", "video/x-h264,stream-format=byte-stream,alignment=au",
		"!", "fdsink", "fd=1", "sync=false", "async=false",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("GStreamer pipeline = %v, want %v", got, want)
	}
}

func TestBuildGstVideoPipelineTimestampedOutput(t *testing.T) {
	encoder := encoderResult{parts: gstStage{"testh264enc"}, rawFormat: "I420"}
	pipeline := buildGstVideoPipeline(
		gstStage{"testsrc"}, nil, nil, encoder, 0, 0, true,
	)
	wantSuffix := []string{
		"!", "h264parse", "config-interval=-1",
		"!", "video/x-h264,stream-format=byte-stream,alignment=au",
		"!", "rtph264pay", "pt=96", "mtu=60000", "aggregate-mode=none", "timestamp-offset=0", "seqnum-offset=0",
		"!", "rtponviftimestamp", "ntp-offset=-1", "set-e-bit=false", "set-t-bit=false",
		"!", "rtpstreampay",
		"!", "fdsink", "fd=1", "sync=false", "async=false",
	}
	if got := pipeline[len(pipeline)-len(wantSuffix):]; !reflect.DeepEqual(got, wantSuffix) {
		t.Fatalf("timestamped encoding suffix = %v, want %v", got, wantSuffix)
	}
}

func TestBuildGstHEVCVideoPipelineTimestampedOutput(t *testing.T) {
	encoder := encoderResult{codec: VideoCodecHEVC, parts: gstStage{"testh265enc"}, rawFormat: "P010_10LE"}
	pipeline := buildGstVideoPipeline(gstStage{"testsrc"}, nil, nil, encoder, 3840, 2160, true)
	joined := strings.Join(pipeline, " ")
	for _, want := range []string{
		"video/x-raw,format=P010_10LE",
		"video/x-raw,width=3840,height=2160,pixel-aspect-ratio=1/1",
		"testh265enc ! h265parse config-interval=-1",
		"video/x-h265,stream-format=byte-stream,alignment=au",
		"rtph265pay pt=96",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("HEVC pipeline %q does not contain %q", joined, want)
		}
	}
}

func TestHEVCTestCaptureProducesUsableSampleDescription(t *testing.T) {
	if !hasGstElement("x265enc") || !supportsTimestampedVideoOutput(VideoCodecHEVC) {
		t.Skip("GStreamer HEVC timestamp pipeline is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	capture, err := StartTestCapture(ctx, CaptureConfig{
		FPS: 5, Bitrate: 1000, HWAccel: "none", VideoCodec: VideoCodecHEVC,
		MaxWidth: 320, MaxHeight: 180,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Stop()
	var vps, sps, pps []byte
	for len(vps) == 0 || len(sps) == 0 || len(pps) == 0 {
		unit, readErr := capture.ReadVideoAccessUnit()
		if readErr != nil {
			t.Fatal(readErr)
		}
		for _, nal := range splitAnnexBAccessUnit(unit.AnnexB) {
			raw := stripStartCode(nal)
			switch hevcNALType(raw) {
			case 32:
				vps = append([]byte(nil), raw...)
			case 33:
				sps = append([]byte(nil), raw...)
			case 34:
				pps = append([]byte(nil), raw...)
			}
		}
	}
	description, err := buildHEVCSampleDescription(vps, sps, pps)
	if err != nil {
		t.Fatal(err)
	}
	if string(description[4:8]) != "hvc1" || string(description[90:94]) != "hvcC" {
		t.Fatalf("HEVC sample description has invalid boxes: %x", description[:min(128, len(description))])
	}
	if description[117] != 0xa0 { // array_completeness + VPS NAL type 32
		t.Fatalf("first hvcC parameter-set array starts with 0x%02x, want 0xa0", description[117])
	}
	info, ok := parseHEVCSPS(sps)
	if !ok || info.width != 320 || info.height != 180 {
		t.Fatalf("HEVC SPS size = %dx%d ok=%v, want 320x180", info.width, info.height, ok)
	}
}

func TestBuildGstVideoPipelineSharesEncodingSuffix(t *testing.T) {
	encoder := encoderResult{
		parts:       gstStage{"vulkanh264enc", "bitrate=2500"},
		needsVulkan: true,
		rawFormat:   "NV12",
	}
	wayland := buildGstVideoPipeline(
		gstStage{"pipewiresrc", "path=42"},
		[]gstStage{{"vapostproc"}},
		[]gstStage{{"videorate"}, frameRateStage(30), lowLatencyVideoQueueStage()},
		encoder,
		0,
		0,
		false,
	)
	x11 := buildGstVideoPipeline(
		gstStage{"ximagesrc", "display-name=:0"},
		[]gstStage{frameRateStage(30), lowLatencyVideoQueueStage()},
		nil,
		encoder,
		0,
		0,
		false,
	)
	wantSuffix := []string{
		"!", "vulkanupload",
		"!", "vulkanh264enc", "bitrate=2500",
		"!", "h264parse", "config-interval=-1",
		"!", "video/x-h264,stream-format=byte-stream,alignment=au",
		"!", "fdsink", "fd=1", "sync=false", "async=false",
	}
	for name, pipeline := range map[string][]string{"Wayland": wayland, "X11": x11} {
		got := pipeline[len(pipeline)-len(wantSuffix):]
		if !reflect.DeepEqual(got, wantSuffix) {
			t.Errorf("%s encoding suffix = %v, want %v", name, got, wantSuffix)
		}
	}
}

func TestBuildGstVideoPipelineSharesReceiverScaling(t *testing.T) {
	encoder := encoderResult{
		parts:     gstStage{"testh264enc"},
		rawFormat: "NV12",
	}
	pipelines := map[string][]string{
		"Wayland": buildGstVideoPipeline(
			gstStage{"pipewiresrc", "path=42"},
			[]gstStage{{"vapostproc"}, {"compositor", "force-live=true"}},
			[]gstStage{lowLatencyVideoQueueStage()},
			encoder,
			1280,
			720,
			false,
		),
		"X11": buildGstVideoPipeline(
			gstStage{"ximagesrc", "display-name=:0"},
			[]gstStage{frameRateStage(30), lowLatencyVideoQueueStage()},
			nil,
			encoder,
			1280,
			720,
			false,
		),
		"test": buildGstVideoPipeline(
			gstStage{"videotestsrc", "is-live=true"},
			[]gstStage{{"video/x-raw,width=1920,height=1080"}},
			nil,
			encoder,
			1280,
			720,
			false,
		),
	}

	want := []string{
		"!", "video/x-raw,format=NV12",
		"!", "videoscale", "add-borders=true",
		"!", "video/x-raw,width=1280,height=720,pixel-aspect-ratio=1/1",
	}
	for name, pipeline := range pipelines {
		if !containsPipelineSequence(pipeline, want) {
			t.Errorf("%s pipeline lacks shared receiver scaling sequence:\n%v", name, pipeline)
		}
		scalers := 0
		for _, arg := range pipeline {
			if arg == "videoscale" {
				scalers++
			}
		}
		if scalers != 1 {
			t.Errorf("%s pipeline has %d videoscale elements, want exactly one:\n%v", name, scalers, pipeline)
		}
	}
}

func TestReceiverScaleStagesRequiresCompleteSize(t *testing.T) {
	if stages := receiverScaleStages(0, 720); stages != nil {
		t.Fatalf("partial receiver size produced stages: %v", stages)
	}
	if stages := receiverScaleStages(1280, 0); stages != nil {
		t.Fatalf("partial receiver size produced stages: %v", stages)
	}
	if stages := receiverScaleStages(1, 1); stages != nil {
		t.Fatalf("subsampled receiver size produced stages: %v", stages)
	}

	stages := receiverScaleStages(1279, 719)
	wantCaps := "video/x-raw,width=1278,height=718,pixel-aspect-ratio=1/1"
	if len(stages) != 2 || len(stages[1]) != 1 || stages[1][0] != wantCaps {
		t.Fatalf("odd receiver size stages = %v, want even caps %q", stages, wantCaps)
	}
}

func containsPipelineSequence(pipeline, sequence []string) bool {
	for start := 0; start+len(sequence) <= len(pipeline); start++ {
		if reflect.DeepEqual(pipeline[start:start+len(sequence)], sequence) {
			return true
		}
	}
	return false
}

func TestDetectGstEncoderSelectsExplicitOpenH264(t *testing.T) {
	var probes []string
	encoder, err := detectGstEncoderWithProbe(CaptureConfig{
		FPS:     25,
		Bitrate: 2500,
		HWAccel: "openh264",
	}, func(name string) bool {
		probes = append(probes, name)
		return name == "openh264enc"
	})
	if err != nil {
		t.Fatalf("detectGstEncoderWithProbe: %v", err)
	}

	if !reflect.DeepEqual(probes, []string{"openh264enc"}) {
		t.Fatalf("encoder probes = %v, want only openh264enc", probes)
	}
	if encoder.rawFormat != "I420" {
		t.Fatalf("OpenH264 raw format = %q, want I420", encoder.rawFormat)
	}
	if encoder.needsVulkan {
		t.Fatal("OpenH264 unexpectedly requires Vulkan upload")
	}
	wantParts := gstStage{
		"openh264enc",
		"bitrate=2500000",
		"gop-size=50",
		"rate-control=bitrate",
		"usage-type=screen",
	}
	if !reflect.DeepEqual(encoder.parts, wantParts) {
		t.Fatalf("OpenH264 pipeline = %v, want %v", encoder.parts, wantParts)
	}
}

func TestDetectGstEncoderRejectsMissingExplicitOpenH264(t *testing.T) {
	var probes []string
	_, err := detectGstEncoderWithProbe(CaptureConfig{
		FPS:     30,
		Bitrate: 2500,
		HWAccel: "openh264",
	}, func(name string) bool {
		probes = append(probes, name)
		return false
	})

	if !reflect.DeepEqual(probes, []string{"openh264enc"}) {
		t.Fatalf("encoder probes = %v, want only openh264enc", probes)
	}
	if err == nil {
		t.Fatal("missing explicit OpenH264 encoder did not return an error")
	}
	if !strings.Contains(err.Error(), "-hwaccel openh264") || !strings.Contains(err.Error(), "openh264enc") {
		t.Fatalf("missing OpenH264 error = %q", err)
	}
}

func TestDetectGstEncoderSelectionContract(t *testing.T) {
	allProbes := []string{"vulkanh264enc", "nvh264enc", "vah264enc", "openh264enc", "x264enc"}
	tests := []struct {
		name        string
		method      string
		available   map[string]bool
		wantEncoder string
		wantMemory  encoderInputMemory
		wantProbes  []string
		wantError   string
	}{
		{
			name:        "auto falls through to OpenH264",
			method:      "auto",
			available:   map[string]bool{"openh264enc": true, "x264enc": true},
			wantEncoder: "openh264enc",
			wantProbes:  allProbes[:4],
		},
		{
			name:        "empty aliases auto and reaches x264",
			available:   map[string]bool{"x264enc": true},
			wantEncoder: "x264enc",
			wantProbes:  allProbes,
		},
		{
			name:       "auto errors when no encoder exists",
			method:     "auto",
			wantProbes: allProbes,
			wantError:  "no supported GStreamer H.264 encoder",
		},
		{
			name:        "nvenc accepts legacy NVENC only",
			method:      "nvenc",
			available:   map[string]bool{"nvh264enc": true, "openh264enc": true},
			wantEncoder: "nvh264enc",
			wantProbes:  []string{"vulkanh264enc", "nvh264enc"},
		},
		{
			name:       "missing nvenc does not cross fallback",
			method:     "nvenc",
			available:  map[string]bool{"vah264enc": true, "openh264enc": true, "x264enc": true},
			wantProbes: []string{"vulkanh264enc", "nvh264enc"},
			wantError:  "-hwaccel nvenc",
		},
		{
			name:        "vaapi selects only VAAPI",
			method:      "vaapi",
			available:   map[string]bool{"vah264enc": true, "openh264enc": true},
			wantEncoder: "vah264enc",
			wantMemory:  encoderInputVAMemory,
			wantProbes:  []string{"vah264enc"},
		},
		{
			name:       "missing vaapi does not cross fallback",
			method:     "vaapi",
			available:  map[string]bool{"openh264enc": true, "x264enc": true},
			wantProbes: []string{"vah264enc"},
			wantError:  "vah264enc",
		},
		{
			name:        "none forces x264",
			method:      "none",
			available:   map[string]bool{"openh264enc": true, "x264enc": true},
			wantEncoder: "x264enc",
			wantProbes:  []string{"x264enc"},
		},
		{
			name:       "none errors without x264",
			method:     "none",
			available:  map[string]bool{"openh264enc": true},
			wantProbes: []string{"x264enc"},
			wantError:  "x264enc",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var probes []string
			encoder, err := detectGstEncoderWithProbe(CaptureConfig{Bitrate: 2500, HWAccel: test.method}, func(name string) bool {
				probes = append(probes, name)
				return test.available[name]
			})
			if !reflect.DeepEqual(probes, test.wantProbes) {
				t.Fatalf("encoder probes = %v, want %v", probes, test.wantProbes)
			}
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("encoder error = %v, want error containing %q", err, test.wantError)
				}
				return
			}
			if err != nil {
				t.Fatalf("detectGstEncoderWithProbe: %v", err)
			}
			if len(encoder.parts) == 0 || encoder.parts[0] != test.wantEncoder {
				t.Fatalf("encoder = %#v, want %s", encoder, test.wantEncoder)
			}
			if encoder.inputMemory != test.wantMemory {
				t.Fatalf("encoder input memory = %v, want %v", encoder.inputMemory, test.wantMemory)
			}
		})
	}
}

func TestVAWaylandPipelineKeepsFramesInVAMemory(t *testing.T) {
	encoder := encoderResult{parts: gstStage{"vah264enc"}, rawFormat: "NV12", codec: VideoCodecH264, inputMemory: encoderInputVAMemory}
	for _, size := range [][2]int{{0, 0}, {1920, 1080}, {1279, 719}, {1, 1}} {
		pipeline := buildVAWaylandVideoPipeline(3, 42, 30, encoder, size[0], size[1], true)
		joined := strings.Join(pipeline, " ")
		for _, forbidden := range []string{"always-copy", "videoconvert", "videoscale", "compositor"} {
			if strings.Contains(joined, forbidden) {
				t.Errorf("VA pipeline must not copy or process portal frames on the CPU: %s", joined)
			}
		}
		for _, required := range []string{"keepalive-time=33", "disable-passthrough=true", "add-borders=true", "video/x-raw(ANY),pixel-aspect-ratio=1/1", "video/x-raw(memory:VAMemory),format=NV12"} {
			if !strings.Contains(joined, required) {
				t.Errorf("VA pipeline is missing %q: %s", required, joined)
			}
		}
		if size[0] > 1 && size[1] > 1 {
			want := fmt.Sprintf("width=%d,height=%d,pixel-aspect-ratio=1/1", size[0]&^1, size[1]&^1)
			if !strings.Contains(joined, want) {
				t.Errorf("VA scaling must use an even receiver canvas: %s", joined)
			}
		} else if strings.Contains(joined, "width=") || strings.Contains(joined, "height=") {
			t.Errorf("invalid receiver size must not constrain the capture: %s", joined)
		}
		// The VA path must retain the same timestamp-preserving output as other
		// sources, since the sender schedules video from the encoded buffer PTS.
		suffix := appendGstVideoEncoding(nil, encoder, true)
		if !reflect.DeepEqual(pipeline[len(pipeline)-len(suffix):], suffix) {
			t.Errorf("VA pipeline changed the shared encoding/output suffix: %s", joined)
		}
	}
}

func TestVAWaylandPipelineSelection(t *testing.T) {
	hasVA := func(element string) bool { return element == "vapostproc" }
	noVA := func(string) bool { return false }
	for _, test := range []struct {
		name       string
		encoder    encoderResult
		hasElement func(string) bool
		want       bool
	}{
		{name: "VA H264", encoder: encoderResult{parts: gstStage{"vah264enc"}, inputMemory: encoderInputVAMemory}, hasElement: hasVA, want: true},
		{name: "missing postprocessor", encoder: encoderResult{parts: gstStage{"vah264enc"}, inputMemory: encoderInputVAMemory}, hasElement: noVA},
		{name: "VA encoder without VA input", encoder: encoderResult{parts: gstStage{"vah264enc"}}, hasElement: hasVA},
		{name: "software H264", encoder: encoderResult{parts: gstStage{"openh264enc"}}, hasElement: hasVA},
		{name: "NVENC H264", encoder: encoderResult{parts: gstStage{"nvh264enc"}}, hasElement: hasVA},
		{name: "empty encoder", hasElement: hasVA},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := canBuildVAWaylandVideoPipeline(test.encoder, test.hasElement); got != test.want {
				t.Fatalf("canBuildVAWaylandVideoPipeline() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestSystemWaylandPipelineDetachesBeforeRetention(t *testing.T) {
	encoder := encoderResult{parts: gstStage{"openh264enc"}, rawFormat: "I420", codec: VideoCodecH264}
	pipeline := buildSystemWaylandVideoPipeline(
		3, 42, 30, encoder, 1920, 1080, [2]int{1536, 960}, true,
		func(element string) bool { return element == "compositor" })
	joined := strings.Join(pipeline, " ")
	for _, forbidden := range []string{"always-copy", "vapostproc", "memory:VAMemory"} {
		if strings.Contains(joined, forbidden) {
			t.Errorf("system-memory Wayland pipeline contains %q: %s", forbidden, joined)
		}
	}
	wantOrder := []string{
		"pipewiresrc", "fd=3", "path=42", "do-timestamp=true", "keepalive-time=33",
		"!", "videoconvert", "!", "video/x-raw,format=NV12",
		"!", "videoconvert", "!", "video/x-raw,format=I420",
		"!", "compositor", "force-live=true", "ignore-inactive-pads=true", "background=black",
		"!", "video/x-raw,format=I420,width=1536,height=960,framerate=30/1",
		"!", "videoscale", "add-borders=true", "!", "video/x-raw,width=1920,height=1080,pixel-aspect-ratio=1/1",
		"!", "queue", "max-size-buffers=1", "max-size-bytes=0", "max-size-time=0", "leaky=downstream",
		"!", "openh264enc",
	}
	if !containsPipelineSequence(pipeline, wantOrder) {
		t.Fatalf("system conversion must own the frame before compositing, scaling, queuing, and encoding:\n%s", joined)
	}
}

func TestSystemWaylandStagingFormatsDifferFromEncoderInput(t *testing.T) {
	for _, test := range []struct {
		target string
		want   string
	}{
		{target: "I420", want: "NV12"},
		{target: "NV12", want: "I420"},
		{target: "I420_10LE", want: "P010_10LE"},
		{target: "P010_10LE", want: "I420_10LE"},
	} {
		t.Run(test.target, func(t *testing.T) {
			got := systemMemoryStagingFormat(test.target)
			if got != test.want {
				t.Fatalf("systemMemoryStagingFormat(%q) = %q, want %q", test.target, got, test.want)
			}
			if got == test.target {
				t.Fatalf("staging format %q permits a passthrough conversion", got)
			}
		})
	}
}

func TestWaylandEncoderPathMatrix(t *testing.T) {
	hasVA := func(element string) bool { return element == "vapostproc" }
	encoders := []struct {
		name    string
		encoder encoderResult
		wantVA  bool
	}{
		{name: "VA H264", encoder: encoderResult{parts: gstStage{"vah264enc"}, rawFormat: "NV12", inputMemory: encoderInputVAMemory}, wantVA: true},
		{name: "OpenH264", encoder: encoderResult{parts: gstStage{"openh264enc"}, rawFormat: "I420"}},
		{name: "x264", encoder: encoderResult{parts: gstStage{"x264enc"}, rawFormat: "I420"}},
		{name: "NVENC H264", encoder: encoderResult{parts: gstStage{"nvh264enc"}, rawFormat: "NV12"}},
		{name: "Vulkan H264", encoder: encoderResult{parts: gstStage{"vulkanh264enc"}, rawFormat: "NV12", needsVulkan: true}},
		{name: "NVENC HEVC", encoder: encoderResult{parts: gstStage{"nvh265enc"}, rawFormat: "P010_10LE", codec: VideoCodecHEVC}},
		{name: "x265", encoder: encoderResult{parts: gstStage{"x265enc"}, rawFormat: "I420_10LE", codec: VideoCodecHEVC}},
	}
	for _, test := range encoders {
		t.Run(test.name, func(t *testing.T) {
			pipeline := buildWaylandVideoPipeline(3, 42, 30, test.encoder, 1280, 720, [2]int{3072, 1920}, true, hasVA)
			joined := strings.Join(pipeline, " ")
			gotVA := strings.Contains(joined, "vapostproc")
			if gotVA != test.wantVA {
				t.Fatalf("VA path = %t, want %t: %s", gotVA, test.wantVA, joined)
			}
			if !test.wantVA {
				wantConversion := "videoconvert ! video/x-raw,format=" + systemMemoryStagingFormat(test.encoder.rawFormat) +
					" ! videoconvert ! video/x-raw,format=" + test.encoder.rawFormat
				if !strings.Contains(joined, wantConversion) {
					t.Fatalf("system path did not force a distinct allocation before %s encoding: %s", test.encoder.rawFormat, joined)
				}
			}
			if test.encoder.needsVulkan && !strings.Contains(joined, "queue max-size-buffers=1 max-size-bytes=0 max-size-time=0 leaky=downstream ! vulkanupload ! vulkanh264enc") {
				t.Fatalf("Vulkan upload is not immediately before its encoder: %s", joined)
			}
		})
	}
}

func captureTestAnnexB(nals ...[]byte) []byte {
	var out []byte
	for _, nal := range nals {
		out = append(out, 0, 0, 0, 1)
		out = append(out, nal...)
	}
	return out
}

type queuedVideoAccessUnitReader struct {
	units []VideoAccessUnit
}

func (r *queuedVideoAccessUnitReader) ReadVideoAccessUnit() (VideoAccessUnit, error) {
	if len(r.units) == 0 {
		return VideoAccessUnit{}, io.EOF
	}
	unit := r.units[0]
	r.units = r.units[1:]
	return unit, nil
}

type exitingVideoAccessUnitReader struct {
	queuedVideoAccessUnitReader
	waitCh chan struct{}
}

func (r *exitingVideoAccessUnitReader) ReadVideoAccessUnit() (VideoAccessUnit, error) {
	unit, err := r.queuedVideoAccessUnitReader.ReadVideoAccessUnit()
	if err == nil && len(r.units) == 0 {
		close(r.waitCh)
	}
	return unit, err
}

func TestWaylandStartupProbeReplaysTimestampedAccessUnitsExactly(t *testing.T) {
	base := time.Unix(1_700_000_000, 123_456_789)
	want := []VideoAccessUnit{
		{AnnexB: captureTestAnnexB([]byte{0x67, 1}, []byte{0x68, 2}, []byte{0x65, 0x80, 3}), PTS: base},
		{AnnexB: captureTestAnnexB([]byte{0x61, 0x80, 4}), PTS: base.Add(time.Second / 30)},
		{AnnexB: captureTestAnnexB([]byte{0x61, 0x80, 5}), PTS: base.Add(2 * time.Second / 30)},
	}
	capture := &ScreenCapture{
		frames: &queuedVideoAccessUnitReader{units: append([]VideoAccessUnit(nil), want...)},
		waitCh: make(chan struct{}),
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := probeWaylandCaptureStartup(ctx, capture, VideoCodecH264, true); err != nil {
		t.Fatal(err)
	}

	for index, expected := range want {
		got, err := capture.ReadVideoAccessUnit()
		if err != nil {
			t.Fatalf("read replayed access unit %d: %v", index, err)
		}
		if !bytes.Equal(got.AnnexB, expected.AnnexB) || got.PTS != expected.PTS {
			t.Fatalf("replayed access unit %d = {%x %v}, want {%x %v}", index, got.AnnexB, got.PTS, expected.AnnexB, expected.PTS)
		}
	}
}

func TestWaylandStartupProbeRejectsProcessThatExitedAfterValidPrefix(t *testing.T) {
	waitCh := make(chan struct{})
	reader := &exitingVideoAccessUnitReader{
		queuedVideoAccessUnitReader: queuedVideoAccessUnitReader{units: []VideoAccessUnit{
			{AnnexB: captureTestAnnexB([]byte{0x67}, []byte{0x68}, []byte{0x65, 0x80})},
			{AnnexB: captureTestAnnexB([]byte{0x61, 0x80})},
		}},
		waitCh: waitCh,
	}
	capture := &ScreenCapture{frames: reader, waitCh: waitCh, waitErr: errors.New("encoder stopped")}
	err := probeWaylandCaptureStartup(context.Background(), capture, VideoCodecH264, true)
	if err == nil || !strings.Contains(err.Error(), "exited after startup validation") || !strings.Contains(err.Error(), "encoder stopped") {
		t.Fatalf("startup probe error = %v, want completed-child rejection", err)
	}
}

func TestWaylandStartupProbeDrainsPrefetchedUnitsBeforeLaterExit(t *testing.T) {
	waitCh := make(chan struct{})
	want := []VideoAccessUnit{
		{AnnexB: captureTestAnnexB([]byte{0x67}, []byte{0x68}, []byte{0x65, 0x80})},
		{AnnexB: captureTestAnnexB([]byte{0x61, 0x80})},
	}
	capture := &ScreenCapture{
		frames: &queuedVideoAccessUnitReader{units: append([]VideoAccessUnit(nil), want...)},
		waitCh: waitCh,
	}
	if err := probeWaylandCaptureStartup(context.Background(), capture, VideoCodecH264, true); err != nil {
		t.Fatal(err)
	}
	wantExit := errors.New("later encoder failure")
	capture.waitErr = wantExit
	close(waitCh)
	for index, expected := range want {
		got, err := capture.ReadVideoAccessUnit()
		if err != nil || !bytes.Equal(got.AnnexB, expected.AnnexB) {
			t.Fatalf("replayed access unit %d = (%x, %v), want (%x, nil)", index, got.AnnexB, err, expected.AnnexB)
		}
	}
	if _, err := capture.ReadVideoAccessUnit(); !errors.Is(err, wantExit) {
		t.Fatalf("post-prefix read error = %v, want %v", err, wantExit)
	}
}

func TestWaylandStartupProbeRequiresCompleteRandomAccessSequence(t *testing.T) {
	tests := []struct {
		name  string
		codec VideoCodec
		units []VideoAccessUnit
		want  string
	}{
		{
			name:  "H264 missing following frame",
			codec: VideoCodecH264,
			units: []VideoAccessUnit{{AnnexB: captureTestAnnexB([]byte{0x67}, []byte{0x68}, []byte{0x65, 0x80})}},
			want:  "following-VCL=false",
		},
		{
			name:  "HEVC missing VPS",
			codec: VideoCodecHEVC,
			units: []VideoAccessUnit{
				{AnnexB: captureTestAnnexB([]byte{33 << 1, 1}, []byte{34 << 1, 1}, []byte{19 << 1, 1})},
				{AnnexB: captureTestAnnexB([]byte{1 << 1, 1})},
			},
			want: "VPS=false",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			capture := &ScreenCapture{frames: &queuedVideoAccessUnitReader{units: test.units}, waitCh: make(chan struct{})}
			err := probeWaylandCaptureStartup(context.Background(), capture, test.codec, true)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("startup probe error = %v, want evidence containing %q", err, test.want)
			}
		})
	}
}

func TestWaylandRawStartupProbeReplaysEveryByte(t *testing.T) {
	stream := captureTestAnnexB(
		[]byte{0x67, 1}, []byte{0x68, 2}, []byte{0x09, 0xf0},
		[]byte{0x65, 0x80, 3}, []byte{0x09, 0xf0},
		[]byte{0x61, 0x80, 4}, []byte{0x09, 0xf0},
		[]byte{0x61, 0x80, 5},
	)
	stdout := io.NopCloser(bytes.NewReader(stream))
	capture := &ScreenCapture{stdout: stdout, waitCh: make(chan struct{})}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := probeWaylandCaptureStartup(ctx, capture, VideoCodecH264, false); err != nil {
		t.Fatal(err)
	}
	close(capture.waitCh)
	got, err := io.ReadAll(capture)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, stream) {
		t.Fatalf("replayed raw prefix = %x, want %x", got, stream)
	}
	_ = capture.stdout.Close()
}

func TestWaylandStartupProbeTimeoutStopsBlockedReader(t *testing.T) {
	waitCh := make(chan struct{})
	reader := &blockingVideoReader{closed: make(chan struct{}), waitCh: waitCh}
	capture := &ScreenCapture{stdout: reader, frames: reader, waitCh: waitCh}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := probeWaylandCaptureStartup(ctx, capture, VideoCodecH264, true)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("startup timeout error = %v, want deadline exceeded", err)
	}
	if !capture.stopped {
		t.Fatal("startup timeout left the capture process active")
	}
	select {
	case <-reader.closed:
	default:
		t.Fatal("startup timeout returned before its blocked reader was released")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("startup timeout cleanup took %v", elapsed)
	}
}

type countingCloser struct {
	closes int
}

func (c *countingCloser) Close() error {
	c.closes++
	return nil
}

func closedCaptureForStartupTest(stderr string) *ScreenCapture {
	waitCh := make(chan struct{})
	close(waitCh)
	capture := &ScreenCapture{waitCh: waitCh}
	if stderr != "" {
		capture.stderr = newCaptureStderrTail()
		capture.stderr.append(stderr)
		capture.stderr.finish()
	}
	return capture
}

func TestWaylandCaptureFallbackReopensRemoteAndTransfersPortalOnce(t *testing.T) {
	va := encoderResult{parts: gstStage{"vah264enc"}, rawFormat: "NV12", inputMemory: encoderInputVAMemory}
	plans := []waylandCapturePlan{
		{encoder: va, mode: waylandPipelineVAMemory},
		{encoder: va, mode: waylandPipelineSystemMemory},
	}
	initial, initialPeer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer initialPeer.Close()
	var remotePeers []*os.File
	defer func() {
		for _, peer := range remotePeers {
			_ = peer.Close()
		}
	}()
	portal := &countingCloser{}
	var opened, attempted []*os.File
	openRemote := func(context.Context) (*os.File, error) {
		remote, peer, pipeErr := os.Pipe()
		if pipeErr == nil {
			opened = append(opened, remote)
			remotePeers = append(remotePeers, peer)
		}
		return remote, pipeErr
	}
	startAttempt := func(_ context.Context, _ CaptureConfig, _ waylandCapturePlan, _ uint32, remote *os.File, _ [2]int, _ bool) (*ScreenCapture, error) {
		attempted = append(attempted, remote)
		return closedCaptureForStartupTest(""), nil
	}
	probes := 0
	probeAttempt := func(context.Context, *ScreenCapture, VideoCodec, bool) error {
		probes++
		if probes == 1 {
			return fmt.Errorf("not-negotiated")
		}
		return nil
	}

	capture, err := startPreparedWaylandCapturePlans(context.Background(), context.Background(), CaptureConfig{}, plans,
		42, initial, portal, openRemote, [2]int{}, true, startAttempt, probeAttempt)
	if err != nil {
		t.Fatal(err)
	}
	if len(opened) != 1 || len(attempted) != 2 || attempted[0] != initial || attempted[1] != opened[0] {
		t.Fatalf("attempt remotes = %p, reopened = %p; want initial then one fresh remote", attempted, opened)
	}
	for _, remote := range attempted {
		if _, statErr := remote.Stat(); !errors.Is(statErr, os.ErrClosed) {
			t.Fatalf("attempt remote remained open: %v", statErr)
		}
	}
	if portal.closes != 0 {
		t.Fatalf("accepted capture portal closes = %d, want 0 before Stop", portal.closes)
	}
	capture.Stop()
	capture.Stop()
	if portal.closes != 1 {
		t.Fatalf("accepted capture portal closes = %d, want exactly 1", portal.closes)
	}
}

func TestWaylandCaptureFailureClosesPortalOnceAndReturnsStderrEvidence(t *testing.T) {
	va := encoderResult{parts: gstStage{"vah264enc"}, rawFormat: "NV12", inputMemory: encoderInputVAMemory}
	plans := []waylandCapturePlan{
		{encoder: va, mode: waylandPipelineVAMemory},
		{encoder: va, mode: waylandPipelineSystemMemory},
	}
	initial, initialPeer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer initialPeer.Close()
	var reopenedPeer *os.File
	defer func() {
		if reopenedPeer != nil {
			_ = reopenedPeer.Close()
		}
	}()
	portal := &countingCloser{}
	openRemote := func(context.Context) (*os.File, error) {
		remote, peer, pipeErr := os.Pipe()
		reopenedPeer = peer
		return remote, pipeErr
	}
	startAttempt := func(context.Context, CaptureConfig, waylandCapturePlan, uint32, *os.File, [2]int, bool) (*ScreenCapture, error) {
		return closedCaptureForStartupTest("streaming stopped, reason not-negotiated (-4)"), nil
	}
	probeAttempt := func(context.Context, *ScreenCapture, VideoCodec, bool) error {
		return io.EOF
	}

	_, err = startPreparedWaylandCapturePlans(context.Background(), context.Background(), CaptureConfig{}, plans,
		42, initial, portal, openRemote, [2]int{}, true, startAttempt, probeAttempt)
	if err == nil {
		t.Fatal("all failed Wayland plans returned no error")
	}
	for _, want := range []string{"native VA frame import", "system-memory frame staging", "not-negotiated (-4)"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("startup error %q is missing %q", err, want)
		}
	}
	if portal.closes != 1 {
		t.Fatalf("failed capture portal closes = %d, want exactly 1", portal.closes)
	}
}

func TestWaylandCapturePlansRetainSelectedEncoderBackend(t *testing.T) {
	available := map[string]bool{"vulkanh264enc": true, "nvh264enc": true, "vah264enc": true, "openh264enc": true, "x264enc": true}
	hasElement := func(name string) bool {
		return name == "vapostproc" || available[name]
	}
	for _, test := range []struct {
		method       string
		wantElements []string
		wantModes    []waylandPipelineMode
	}{
		{method: "auto", wantElements: []string{"vulkanh264enc"}, wantModes: []waylandPipelineMode{waylandPipelineSystemMemory}},
		{method: "vaapi", wantElements: []string{"vah264enc", "vah264enc"}, wantModes: []waylandPipelineMode{waylandPipelineVAMemory, waylandPipelineSystemMemory}},
		{method: "none", wantElements: []string{"x264enc"}, wantModes: []waylandPipelineMode{waylandPipelineSystemMemory}},
		{method: "openh264", wantElements: []string{"openh264enc"}, wantModes: []waylandPipelineMode{waylandPipelineSystemMemory}},
	} {
		t.Run(test.method, func(t *testing.T) {
			encoder, err := selectGstEncoderWithProbe(CaptureConfig{HWAccel: test.method}, hasElement, false)
			if err != nil {
				t.Fatal(err)
			}
			plans := waylandCapturePlans(encoder, hasElement)
			var elements []string
			var modes []waylandPipelineMode
			for _, plan := range plans {
				elements = append(elements, plan.encoder.parts[0])
				modes = append(modes, plan.mode)
			}
			if !reflect.DeepEqual(elements, test.wantElements) || !reflect.DeepEqual(modes, test.wantModes) {
				t.Fatalf("plans = elements %v modes %v, want %v %v", elements, modes, test.wantElements, test.wantModes)
			}
		})
	}
}

func TestH264TestCaptureStartupProbePreservesRealGStreamerOutput(t *testing.T) {
	if !hasGstElement("x264enc") || !supportsTimestampedVideoOutput(VideoCodecH264) {
		t.Skip("GStreamer H.264 timestamp pipeline is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	capture, err := StartTestCapture(ctx, CaptureConfig{
		FPS: 10, Bitrate: 500, HWAccel: "none", VideoCodec: VideoCodecH264,
		MaxWidth: 320, MaxHeight: 180,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Stop()
	probeCtx, cancelProbe := context.WithTimeout(ctx, waylandCaptureAttemptTimeout)
	defer cancelProbe()
	if err := probeWaylandCaptureStartup(probeCtx, capture, VideoCodecH264, true); err != nil {
		t.Fatal(err)
	}
	prefetched, ok := capture.frames.(*prefetchedVideoAccessUnitReader)
	if !ok || len(prefetched.units) < 2 {
		t.Fatalf("startup probe retained %#v, want at least two access units", capture.frames)
	}
	want := append([]VideoAccessUnit(nil), prefetched.units...)
	for index, expected := range want {
		got, readErr := capture.ReadVideoAccessUnit()
		if readErr != nil {
			t.Fatalf("read GStreamer startup access unit %d: %v", index, readErr)
		}
		if !bytes.Equal(got.AnnexB, expected.AnnexB) || got.PTS != expected.PTS {
			t.Fatalf("GStreamer startup access unit %d changed during replay", index)
		}
	}
}
