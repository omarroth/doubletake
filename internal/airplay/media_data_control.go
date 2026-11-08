package airplay

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"howett.net/plist"
)

const (
	mediaDataControlHeaderSize       = 32
	mediaDataControlMessageSizeLimit = 1024 * 1024

	dynamicLatencyMinimumReportDuration = 5
	dynamicLatencyPromotionWindow       = 60
	dynamicLatencyPromoteGlitches       = 0.0
	dynamicLatencyDemoteGlitches        = 0.2
	dynamicLatencyWorstGlitches         = 1.0
)

type mediaDataControlMessage struct {
	messageType [4]byte
	command     [4]byte
	replyToken  uint64
	status      uint32
	payload     []byte
	header      [mediaDataControlHeaderSize]byte
}

type audioPerformanceReport struct {
	durationSecs        uint64
	renderDeadlineMinMS int64
	weightedGlitches    float64
}

type serializedHistogram struct {
	minValue     float64
	maxValue     float64
	realMinValue float64
	realMaxValue float64
	bucketWidth  float64
	bucketRanges []float64
	samples      []uint64
}

// newMediaDataControlChannel constructs the sender side of AirPlay's
// MediaDataControl DataStream. The seed selects a distinct pair of keys from
// the pair-verify secret. "Input" and "Output" are named from the sender's
// perspective: receiver reports use Input and sender replies use Output.
func newMediaDataControlChannel(conn net.Conn, sharedSecret []byte, seed uint64) (*eventChannel, error) {
	if conn == nil {
		return nil, fmt.Errorf("media data control connection is nil")
	}
	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("media data control has no pair-verify shared secret")
	}

	salt := []byte("DataStream-Salt" + strconv.FormatUint(seed, 10))
	readKey := hkdfSHA512(sharedSecret, salt, []byte("DataStream-Input-Encryption-Key"), chacha20poly1305.KeySize)
	writeKey := hkdfSHA512(sharedSecret, salt, []byte("DataStream-Output-Encryption-Key"), chacha20poly1305.KeySize)
	readCipher, err := chacha20poly1305.New(readKey)
	if err != nil {
		return nil, fmt.Errorf("create media data control read cipher: %w", err)
	}
	writeCipher, err := chacha20poly1305.New(writeKey)
	if err != nil {
		return nil, fmt.Errorf("create media data control write cipher: %w", err)
	}
	return &eventChannel{conn: conn, readCipher: readCipher, writeCipher: writeCipher}, nil
}

func (c *AirPlayClient) dialMediaDataControl(port int, seed uint64) (*eventChannel, error) {
	if port <= 0 {
		return nil, fmt.Errorf("invalid media data control port %d", port)
	}
	if c == nil || c.PairKeys == nil || len(c.PairKeys.SharedSecret) == 0 {
		return nil, fmt.Errorf("media data control requires a pair-verify shared secret")
	}
	address := net.JoinHostPort(c.sessionPeerHost(), strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial media data control %s: %w", address, err)
	}
	channel, err := newMediaDataControlChannel(conn, c.PairKeys.SharedSecret, seed)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	dbg("[AUDIO-DLM] connected to MediaDataControl port %s", address)
	return channel, nil
}

func readMediaDataControlMessage(reader io.Reader) (mediaDataControlMessage, error) {
	var message mediaDataControlMessage
	if _, err := io.ReadFull(reader, message.header[:]); err != nil {
		return message, err
	}
	messageSize := int(binary.BigEndian.Uint32(message.header[0:4]))
	if messageSize < mediaDataControlHeaderSize || messageSize > mediaDataControlMessageSizeLimit {
		return message, fmt.Errorf("invalid media data control message size %d", messageSize)
	}
	copy(message.messageType[:], message.header[4:8])
	copy(message.command[:], message.header[16:20])
	message.replyToken = binary.BigEndian.Uint64(message.header[20:28])
	message.status = binary.BigEndian.Uint32(message.header[28:32])
	if payloadSize := messageSize - mediaDataControlHeaderSize; payloadSize > 0 {
		message.payload = make([]byte, payloadSize)
		if _, err := io.ReadFull(reader, message.payload); err != nil {
			return mediaDataControlMessage{}, fmt.Errorf("read media data control payload: %w", err)
		}
	}
	return message, nil
}

func mediaDataControlReply(request mediaDataControlMessage, status uint32) []byte {
	reply := make([]byte, mediaDataControlHeaderSize)
	binary.BigEndian.PutUint32(reply[0:4], mediaDataControlHeaderSize)
	copy(reply[4:8], "rply")
	copy(reply[8:16], request.header[8:16])
	copy(reply[16:20], request.command[:])
	binary.BigEndian.PutUint64(reply[20:28], request.replyToken)
	binary.BigEndian.PutUint32(reply[28:32], status)
	return reply
}

func serveMediaDataControl(ctx context.Context, channel *eventChannel, audio *AudioStream) error {
	defer channel.conn.Close()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = channel.conn.Close()
		case <-done:
		}
	}()
	defer close(done)

	for {
		message, err := readMediaDataControlMessage(channel)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}

		messageType := string(message.messageType[:])
		command := string(message.command[:])
		dbg("[AUDIO-DLM] <- type=%q command=%q reply-token=%d body=%d", messageType, command, message.replyToken, len(message.payload))
		var status uint32
		if command == "raup" {
			var reportMap map[string]interface{}
			if _, err := plist.Unmarshal(message.payload, &reportMap); err != nil {
				dbg("[AUDIO-DLM] invalid performance report: %v", err)
				status = 1
			} else if report, ok, err := parseAudioPerformanceReport(reportMap); err != nil {
				dbg("[AUDIO-DLM] invalid performance report: %v", err)
				status = 1
			} else if ok {
				audio.applyPerformanceReport(report)
			} else if duration, valid := plistNumericValue(reportMap["SessionDurationSec"]); valid && uint64(duration) < dynamicLatencyMinimumReportDuration {
				dbg("[AUDIO-DLM] ignoring short performance report: duration=%.0fs", duration)
			} else if _, nonStartup := reportMap["NonStartupGlitchHistogram"]; nonStartup {
				// Apple's screen sender only gives its dynamic-latency manager the
				// separately tagged live-adaptive histogram. Normal receiver reports
				// are useful telemetry, but must not lower the mirroring latency.
				dbg("[AUDIO-DLM] ignoring non-live performance report")
			}
		}

		// Receiver performance reports are normally asynchronous. Synchronous
		// requests carry an ID and require the matching DataStream reply.
		if messageType == "sync" {
			if _, err := channel.Write(mediaDataControlReply(message, status)); err != nil {
				return fmt.Errorf("write media data control reply: %w", err)
			}
		}
	}
}

func parseAudioPerformanceReport(values map[string]interface{}) (audioPerformanceReport, bool, error) {
	var report audioPerformanceReport
	if values == nil {
		return report, false, fmt.Errorf("report is not a dictionary")
	}
	protocolVersion, ok := plistNumericValue(values["ProtocolVersion"])
	if !ok || protocolVersion != 1 {
		return report, false, fmt.Errorf("unsupported ProtocolVersion %v", values["ProtocolVersion"])
	}
	duration, ok := plistNumericValue(values["SessionDurationSec"])
	if !ok || duration < 0 || duration > math.MaxUint32 || math.Trunc(duration) != duration {
		return report, false, fmt.Errorf("invalid SessionDurationSec %v", values["SessionDurationSec"])
	}
	if uint64(duration) < dynamicLatencyMinimumReportDuration {
		return report, false, nil
	}
	deadline, ok := plistNumericValue(values["RenderDeadlineMinMs"])
	if !ok || deadline < math.MinInt32 || deadline > math.MaxInt32 || math.Trunc(deadline) != deadline {
		return report, false, fmt.Errorf("invalid RenderDeadlineMinMs %v", values["RenderDeadlineMinMs"])
	}

	// Screen variants consume live-adaptive reports. A non-startup histogram is
	// valid receiver telemetry, but belongs to the non-live latency managers.
	histogramMap, ok := values["LiveAdaptiveGlitchHistogram"].(map[string]interface{})
	if !ok {
		if _, nonStartup := values["NonStartupGlitchHistogram"]; nonStartup {
			return report, false, nil
		}
		return report, false, fmt.Errorf("report omitted LiveAdaptiveGlitchHistogram")
	}
	histogram, err := parseSerializedHistogram(histogramMap)
	if err != nil {
		return report, false, err
	}
	report.durationSecs = uint64(duration)
	report.renderDeadlineMinMS = int64(deadline)
	report.weightedGlitches =
		0.05*float64(histogram.sampleCountInRange(-2147483648, 10)) +
			0.2*float64(histogram.sampleCountInRange(10, 25)) +
			float64(histogram.sampleCountInRange(25, 2147483647))
	return report, true, nil
}

func parseSerializedHistogram(values map[string]interface{}) (serializedHistogram, error) {
	var histogram serializedHistogram
	bucketCountValue, ok := plistNumericValue(values["BucketCount"])
	if !ok || bucketCountValue < 1 || bucketCountValue > 100 || math.Trunc(bucketCountValue) != bucketCountValue {
		return histogram, fmt.Errorf("invalid histogram BucketCount %v", values["BucketCount"])
	}
	bucketCount := int(bucketCountValue)
	var err error
	if histogram.minValue, err = requiredPlistNumber(values, "MinValue"); err != nil {
		return histogram, err
	}
	if histogram.maxValue, err = requiredPlistNumber(values, "MaxValue"); err != nil {
		return histogram, err
	}
	if histogram.realMinValue, err = requiredPlistNumber(values, "RealMinValue"); err != nil {
		return histogram, err
	}
	if histogram.realMaxValue, err = requiredPlistNumber(values, "RealMaxValue"); err != nil {
		return histogram, err
	}
	if histogram.bucketWidth, err = requiredPlistNumber(values, "BucketWidth"); err != nil {
		return histogram, err
	}

	samples, ok := plistArray(values["Samples"])
	if !ok || len(samples) != bucketCount {
		return histogram, fmt.Errorf("histogram Samples has %d entries, want %d", len(samples), bucketCount)
	}
	histogram.samples = make([]uint64, bucketCount)
	for index, value := range samples {
		number, ok := plistNumericValue(value)
		if !ok || number < 0 || number > math.MaxUint32 || math.Trunc(number) != number {
			return histogram, fmt.Errorf("invalid histogram sample %d: %v", index, value)
		}
		histogram.samples[index] = uint64(number)
	}

	if ranges, present := values["BucketRanges"]; present {
		array, ok := plistArray(ranges)
		if !ok || len(array) != bucketCount {
			return histogram, fmt.Errorf("histogram BucketRanges has %d entries, want %d", len(array), bucketCount)
		}
		histogram.bucketRanges = make([]float64, bucketCount)
		for index, value := range array {
			number, ok := plistNumericValue(value)
			if !ok {
				return histogram, fmt.Errorf("invalid histogram bucket range %d: %v", index, value)
			}
			histogram.bucketRanges[index] = number
		}
	}
	return histogram, nil
}

func (histogram serializedHistogram) sampleCountInRange(start, end float64) uint64 {
	if len(histogram.samples) == 0 {
		return 0
	}
	lower := math.Min(histogram.minValue, histogram.realMinValue)
	var count uint64
	for index, samples := range histogram.samples {
		upper := math.Max(histogram.maxValue, histogram.realMaxValue)
		if index+1 < len(histogram.samples) {
			if len(histogram.bucketRanges) == len(histogram.samples) {
				upper = histogram.bucketRanges[index+1]
			} else {
				upper = histogram.minValue + float64(index+1)*histogram.bucketWidth
			}
		}
		// APSStatsHistogram counts only buckets wholly contained in the range.
		if start <= lower && upper <= end {
			count += samples
		}
		lower = upper
	}
	return count
}

func (as *AudioStream) applyPerformanceReport(report audioPerformanceReport) bool {
	if as == nil {
		return false
	}
	as.mu.Lock()
	if !as.adaptiveLatency || len(as.latencyTiers) < 2 {
		as.mu.Unlock()
		return false
	}

	as.performanceReports = append(as.performanceReports, audioPerformanceReport{})
	copy(as.performanceReports[1:], as.performanceReports[:len(as.performanceReports)-1])
	as.performanceReports[0] = report

	var totalDuration uint64
	keep := 0
	for keep < len(as.performanceReports) && totalDuration < dynamicLatencyPromotionWindow {
		totalDuration += as.performanceReports[keep].durationSecs
		keep++
	}
	as.performanceReports = as.performanceReports[:keep]

	var weightedGlitches float64
	var deadlineTotal int64
	var deadlineCount int64
	for _, current := range as.performanceReports {
		weightedGlitches += current.weightedGlitches
		if current.renderDeadlineMinMS >= 0 {
			deadlineTotal += current.renderDeadlineMinMS
			deadlineCount++
		}
	}
	// The retained reports can cross the window boundary. Apple's manager scales
	// the glitch total back to the exact window duration before comparing it to
	// the tier thresholds; deadline headroom remains the average of the reports.
	if totalDuration > dynamicLatencyPromotionWindow {
		weightedGlitches *= float64(dynamicLatencyPromotionWindow) / float64(totalDuration)
	}
	averageDeadline := int64(0)
	if deadlineCount > 0 {
		averageDeadline = deadlineTotal / deadlineCount
	}

	oldTier := as.latencyTier
	newTier := oldTier
	if oldTier > 0 && weightedGlitches > dynamicLatencyWorstGlitches {
		newTier = 0
	} else if oldTier > 0 && weightedGlitches > dynamicLatencyDemoteGlitches {
		newTier = oldTier - 1
	} else if weightedGlitches <= dynamicLatencyPromoteGlitches &&
		totalDuration >= dynamicLatencyPromotionWindow && oldTier+1 < len(as.latencyTiers) {
		currentMS := audioLatencyDuration(as.latencyTiers[oldTier]).Milliseconds()
		nextMS := audioLatencyDuration(as.latencyTiers[oldTier+1]).Milliseconds()
		if currentMS-nextMS < averageDeadline {
			newTier = oldTier + 1
		}
	}

	if newTier == oldTier {
		as.mu.Unlock()
		dbg("[AUDIO-DLM] report duration=%ds weighted-glitches=%.2f render-deadline=%dms tier=%d unchanged",
			totalDuration, weightedGlitches, averageDeadline, oldTier)
		return false
	}
	oldSamples := as.latencySamples
	as.latencyTier = newTier
	as.latencySamples = as.latencyTiers[newTier]
	newSamples := as.latencySamples
	as.performanceReports = nil
	changedSignal := as.latencyChanged
	as.mu.Unlock()

	dbg("[AUDIO-DLM] latency changed from %v to %v: duration=%ds weighted-glitches=%.2f render-deadline=%dms",
		audioLatencyDuration(oldSamples), audioLatencyDuration(newSamples), totalDuration, weightedGlitches, averageDeadline)
	if changedSignal != nil {
		select {
		case changedSignal <- struct{}{}:
		default:
		}
	}
	return true
}

func plistNumericValue(value interface{}) (float64, bool) {
	switch number := value.(type) {
	case uint64:
		return float64(number), true
	case uint32:
		return float64(number), true
	case uint16:
		return float64(number), true
	case uint8:
		return float64(number), true
	case int64:
		return float64(number), true
	case int32:
		return float64(number), true
	case int16:
		return float64(number), true
	case int8:
		return float64(number), true
	case int:
		return float64(number), true
	case float64:
		return number, true
	case float32:
		return float64(number), true
	default:
		return 0, false
	}
}

func requiredPlistNumber(values map[string]interface{}, key string) (float64, error) {
	number, ok := plistNumericValue(values[key])
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) {
		return 0, fmt.Errorf("invalid histogram %s %v", key, values[key])
	}
	return number, nil
}

func plistArray(value interface{}) ([]interface{}, bool) {
	switch array := value.(type) {
	case []interface{}:
		return array, true
	case []uint64:
		values := make([]interface{}, len(array))
		for index := range array {
			values[index] = array[index]
		}
		return values, true
	case []float64:
		values := make([]interface{}, len(array))
		for index := range array {
			values[index] = array[index]
		}
		return values, true
	default:
		return nil, false
	}
}
