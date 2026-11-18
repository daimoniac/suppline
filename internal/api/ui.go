package api

import (
	"bytes"
	"fmt"
	"html"
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	swaggerdocs "github.com/daimoniac/suppline/build/swagger"
)

// rootHandler serves the API and the embedded UI under the configured base
// path. Requests outside the base path get a 404; the bare base path
// redirects to itself with a trailing slash.
func (s *APIServer) rootHandler(uiFiles fs.FS) (http.Handler, error) {
	basePath := s.config.BasePath

	swaggerdocs.SwaggerInfo.Host = ""
	swaggerdocs.SwaggerInfo.BasePath = basePath + "/api/v1"

	ui, err := newUIHandler(uiFiles, basePath)
	if err != nil {
		return nil, err
	}
	s.ui = ui

	if basePath == "" {
		return s.router, nil
	}

	inner := http.StripPrefix(basePath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// StripPrefix only rewrites URL.Path; the swagger handler derives its
		// file paths from RequestURI, so strip it there too. r is already a
		// copy made by StripPrefix.
		r.RequestURI = strings.TrimPrefix(r.RequestURI, basePath)
		s.router.ServeHTTP(w, r)
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == basePath:
			target := basePath + "/"
			if r.URL.RawQuery != "" {
				target += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		case strings.HasPrefix(r.URL.Path, basePath+"/"):
			inner.ServeHTTP(&prefixRedirectWriter{ResponseWriter: w, prefix: basePath}, r)
		default:
			http.NotFound(w, r)
		}
	}), nil
}

// handleUI serves the UI; the "/" route is registered before the UI files
// are loaded, so it delegates to s.ui.
func (s *APIServer) handleUI(w http.ResponseWriter, r *http.Request) {
	if s.ui == nil {
		http.NotFound(w, r)
		return
	}
	s.ui.ServeHTTP(w, r)
}

func handleSwaggerRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/swagger/", http.StatusMovedPermanently)
}

// prefixRedirectWriter adds the base path to absolute redirect targets.
// Handlers behind StripPrefix (ServeMux path cleaning, the swagger handler)
// redirect to paths that no longer carry the prefix.
type prefixRedirectWriter struct {
	http.ResponseWriter
	prefix string
}

func (w *prefixRedirectWriter) WriteHeader(code int) {
	if code >= 300 && code < 400 {
		// Some handlers (the swagger one) build targets from the unstripped
		// RequestURI, so leave locations that already carry the prefix alone.
		if loc := w.Header().Get("Location"); strings.HasPrefix(loc, "/") && !strings.HasPrefix(loc, "//") &&
			loc != w.prefix && !strings.HasPrefix(loc, w.prefix+"/") {
			w.Header().Set("Location", w.prefix+loc)
		}
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *prefixRedirectWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// uiHandler serves the single-page UI. Known files are served as-is; any
// other path without a file extension gets index.html so client-side routes
// survive a reload or a shared link.
type uiHandler struct {
	files fs.FS
	index []byte
}

func newUIHandler(files fs.FS, basePath string) (*uiHandler, error) {
	index, err := fs.ReadFile(files, "index.html")
	if err != nil {
		return nil, fmt.Errorf("read UI index.html: %w", err)
	}
	return &uiHandler{files: files, index: injectBaseHref(index, basePath+"/")}, nil
}

// injectBaseHref adds <base href> right after <head> so relative asset and
// API URLs resolve against the base path on every client-side route.
func injectBaseHref(index []byte, href string) []byte {
	tag := []byte(`<base href="` + html.EscapeString(href) + `" />`)
	if i := bytes.Index(index, []byte("<head>")); i >= 0 {
		at := i + len("<head>")
		out := make([]byte, 0, len(index)+len(tag)+1)
		out = append(out, index[:at]...)
		out = append(out, '\n')
		out = append(out, tag...)
		return append(out, index[at:]...)
	}
	return append(tag, index...)
}

func (h *uiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")

	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if name != "" && name != "index.html" {
		if h.serveFile(w, r, name) {
			return
		}
		if path.Ext(name) != "" {
			http.NotFound(w, r)
			return
		}
	}

	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(h.index))
}

// serveFile serves name from the UI files and reports whether it existed.
func (h *uiHandler) serveFile(w http.ResponseWriter, r *http.Request, name string) bool {
	f, err := h.files.Open(name)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil || info.IsDir() {
		return false
	}

	if strings.HasPrefix(name, "assets/") {
		// Vite puts a content hash in every file name under assets/.
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}

	content, ok := f.(io.ReadSeeker)
	if !ok {
		data, err := io.ReadAll(f)
		if err != nil {
			http.Error(w, "read file", http.StatusInternalServerError)
			return true
		}
		content = bytes.NewReader(data)
	}
	http.ServeContent(w, r, name, info.ModTime(), content)
	return true
}
