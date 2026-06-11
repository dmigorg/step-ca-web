package server

import (
	"io/fs"
	"net/http"
	"os"
	"strings"

	"github.com/xix-support/step-ca-web/web"
)

func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/auth/") {
		http.NotFound(w, r)
		return
	}

	distFS, err := fs.Sub(web.FS, "dist")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	filePath := path
	if filePath == "/" {
		filePath = "/index.html"
	}

	f, err := distFS.Open(strings.TrimPrefix(filePath, "/"))
	if err != nil {
		if os.IsNotExist(err) {
			f, err = distFS.Open("index.html")
			if err != nil {
				http.Error(w, "index.html not found", http.StatusNotFound)
				return
			}
			defer f.Close()
			stat, _ := f.Stat()
			http.ServeContent(w, r, "index.html", stat.ModTime(), f.(readSeeker))
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if stat.IsDir() {
		f2, err := distFS.Open(strings.TrimPrefix(filePath, "/") + "/index.html")
		if err == nil {
			f2.Close()
			http.Redirect(w, r, path+"/", http.StatusMovedPermanently)
			return
		}
		f, err = distFS.Open("index.html")
		if err != nil {
			http.Error(w, "index.html not found", http.StatusNotFound)
			return
		}
		defer f.Close()
		stat, _ = f.Stat()
		http.ServeContent(w, r, "index.html", stat.ModTime(), f.(readSeeker))
		return
	}

	http.ServeContent(w, r, stat.Name(), stat.ModTime(), f.(readSeeker))
}

type readSeeker interface {
	Read(p []byte) (n int, err error)
	Seek(offset int64, whence int) (int64, error)
}
