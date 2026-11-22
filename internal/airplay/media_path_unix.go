//go:build !windows

package airplay

func mediaFilePath(path string) string { return path }
func mediaURIPath(path string) string  { return path }
