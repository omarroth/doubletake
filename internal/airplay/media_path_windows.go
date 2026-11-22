package airplay

import "path/filepath"

func mediaFilePath(path string) string {
	if len(path) >= 4 && path[0] == '/' && path[2:4] == ":/" {
		path = path[1:]
	}
	return filepath.FromSlash(path)
}

func mediaURIPath(path string) string {
	path = filepath.ToSlash(path)
	if len(path) >= 3 && path[1:3] == ":/" {
		return "/" + path
	}
	return path
}
