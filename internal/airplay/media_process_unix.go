//go:build !windows

package airplay

import (
	"context"
	"io"
	"os"
)

func mediaFilePath(path string) string { return path }
func mediaURIPath(path string) string  { return path }

func launchMediaGraphProcess(ctx context.Context, uri string, videoArgs, audioArgs []string) (*runningGStreamerPipeline, io.ReadCloser, error) {
	pcm, audioWriter, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	defer audioWriter.Close()
	args := append([]string{"--quiet"}, mediaGraphArgs(uri, videoArgs, replaceMediaSinkFD(audioArgs, 3))...)
	pipeline, err := launchGStreamerProcess(ctx, args, []*os.File{audioWriter}, uri == "fd://0")
	if err != nil {
		_ = pcm.Close()
		return nil, nil, err
	}
	return pipeline, pcm, nil
}
