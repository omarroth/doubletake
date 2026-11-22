import AudioToolbox
import CoreGraphics
import CoreMedia
import Darwin
import Foundation
import ScreenCaptureKit

@available(macOS 13.0, *)
final class SystemAudioOutput: NSObject, SCStreamOutput, SCStreamDelegate {
    private var samples: [Float] = []

    func stream(_ stream: SCStream, didOutputSampleBuffer buffer: CMSampleBuffer, of type: SCStreamOutputType) {
        guard type == .audio, buffer.isValid else { return }
        do {
            guard let format = buffer.formatDescription?.audioStreamBasicDescription,
                  format.mFormatID == kAudioFormatLinearPCM,
                  format.mFormatFlags & kAudioFormatFlagIsFloat != 0,
                  format.mBitsPerChannel == 32, format.mSampleRate == 48_000,
                  format.mChannelsPerFrame == 2 else {
                throw CaptureError.unexpectedFormat
            }
            let frames = buffer.numSamples
            guard frames > 0 else { return }
            try buffer.withAudioBufferList { audio, _ in
                if audio.count == 1, let data = audio[0].mData, audio[0].mDataByteSize >= frames * 8 {
                    try FileHandle.standardOutput.write(contentsOf: Data(bytesNoCopy: data, count: frames * 8, deallocator: .none))
                } else if audio.count == 2,
                          audio[0].mDataByteSize >= frames * 4, audio[1].mDataByteSize >= frames * 4,
                          let left = audio[0].mData?.assumingMemoryBound(to: Float.self),
                          let right = audio[1].mData?.assumingMemoryBound(to: Float.self) {
                    if samples.count != frames * 2 { samples = Array(repeating: 0, count: frames * 2) }
                    for i in 0..<frames {
                        samples[2 * i] = left[i]
                        samples[2 * i + 1] = right[i]
                    }
                    try samples.withUnsafeMutableBytes { bytes in
                        if let data = bytes.baseAddress {
                            try FileHandle.standardOutput.write(contentsOf: Data(bytesNoCopy: data, count: bytes.count, deallocator: .none))
                        }
                    }
                } else {
                    throw CaptureError.unexpectedFormat
                }
            }
        } catch {
            fail(error)
        }
    }

    func stream(_ stream: SCStream, didStopWithError error: Error) {
        fail(error)
    }
}

private enum CaptureError: LocalizedError {
    case missingDisplay
    case unexpectedFormat

    var errorDescription: String? {
        switch self {
        case .missingDisplay: return "no shareable display is available in this desktop session"
        case .unexpectedFormat: return "ScreenCaptureKit returned an unexpected audio format"
        }
    }
}

private func fail(_ error: Error) -> Never {
    let message = "doubletake macOS audio: \(error.localizedDescription)\n"
    FileHandle.standardError.write(Data(message.utf8))
    exit(EXIT_FAILURE)
}

@main
struct DoubletakeSystemAudio {
    static func main() {
        if CommandLine.arguments.dropFirst().first == "--version" {
            print("doubletake ScreenCaptureKit audio helper")
            return
        }
        Task {
            do {
                try await capture()
            } catch {
                fail(error)
            }
        }
        dispatchMain()
    }

    static func capture() async throws {
        let content = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
        guard let display = content.displays.first(where: { $0.displayID == CGMainDisplayID() }) ?? content.displays.first else {
            throw CaptureError.missingDisplay
        }
        let filter = SCContentFilter(display: display, excludingWindows: [])
        let configuration = SCStreamConfiguration()
        configuration.capturesAudio = true
        configuration.sampleRate = 48_000
        configuration.channelCount = 2
        let output = SystemAudioOutput()
        let stream = SCStream(filter: filter, configuration: configuration, delegate: output)
        try stream.addStreamOutput(output, type: .audio, sampleHandlerQueue: DispatchQueue(label: "doubletake.audio"))
        try await stream.startCapture()

        // The Go process owns the helper. Exit even if it closes while the
        // stream is idle and no further write would notice its closed pipe.
        let parent = getppid()
        while parent > 1 && getppid() == parent {
            try await Task.sleep(nanoseconds: 1_000_000_000)
        }
        try await stream.stopCapture()
        withExtendedLifetime(output) {}
        exit(EXIT_SUCCESS)
    }
}
