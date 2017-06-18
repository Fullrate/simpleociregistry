package main

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"fmt"
	flag "github.com/ogier/pflag"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	ociImage "github.com/opencontainers/image-spec/specs-go/v1"
)

type OCIBlobEntry struct {
	Size   int64
	Source string
	File   *os.File
}

type OCISummary struct {
	Path    string
	ModTime time.Time
	Blobs   map[string]*OCIBlobEntry
	Refs    map[string]string
}

type OCIReferenceEntry struct {
	Name, Reference string
	Path, Blob      string
	ModTime         time.Time
}

type OCIRegistry struct {
	basedir string
	refs    map[string]*OCIReferenceEntry // name:ref -> ref entry
	blobs   map[string]*OCIBlobEntry      // blobs -> file
	mut     sync.Mutex
}

func NewOCIRegistry(basedir string) *OCIRegistry {
	reg := &OCIRegistry{
		basedir: basedir,
		refs:    make(map[string]*OCIReferenceEntry),
		blobs:   make(map[string]*OCIBlobEntry),
	}
	go reg.cleanup()
	return reg
}

func (reg *OCIRegistry) cleanup() {
	for {
		time.Sleep(10 * time.Minute)
		func() {
			log.Info("Cleaning up")
			reg.mut.Lock()
			defer reg.mut.Unlock()

			// Collect list of files that have to be checked for accessiblity
			files := make(map[string]struct{})

			for _, b := range reg.blobs {
				files[b.Source] = struct{}{}
			}
			for _, e := range reg.refs {
				files[e.Path] = struct{}{}
			}

			// Check the collected files, removing ones that are accessible
			for f, _ := range files {
				_, err := os.Stat(f)
				if err == nil {
					delete(files, f)
				}
			}

			// Files now contains a list of deleted/inaccessible files. We can use this
			// to filter blobs and refs.

			blobs := make(map[string]*OCIBlobEntry)
			for b, f := range reg.blobs {
				if _, ok := files[f.Source]; !ok {
					blobs[b] = f
				} else {
					f.File.Close()
				}
			}

			refs := make(map[string]*OCIReferenceEntry)
			for r, e := range reg.refs {
				if _, ok := files[e.Path]; !ok {
					refs[r] = e
				}
			}

			reg.blobs = blobs
			reg.refs = refs
		}()
	}
}

type ImageCandidate struct {
	Path    string
	ModTime time.Time
}

type ImageCandidateSlice []ImageCandidate

func (s ImageCandidateSlice) Len() int {
	return len(s)
}

func (s ImageCandidateSlice) Less(i, j int) bool {
	return s[i].ModTime.After(s[j].ModTime)
}

func (s ImageCandidateSlice) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (reg *OCIRegistry) FindCandidates(name, reference string) ([]ImageCandidate, error) {
	path, err := filepath.Abs(filepath.Join(reg.basedir, name))
	if err != nil {
		return nil, err
	}
	patterns := []string{
		filepath.Join(path, reference+".oci"),
		path + ":" + reference + ".oci",
		path + ".oci",
	}
	var candidates []string
	for _, p := range patterns {
		m, err := filepath.Glob(p)
		if err != nil {
			continue
		}
		candidates = append(candidates, m...)
	}
	var images []ImageCandidate
	for _, c := range candidates {
		fi, err := os.Stat(c)
		if err == nil {
			images = append(images, ImageCandidate{
				Path:    c,
				ModTime: fi.ModTime(),
			})
		}
	}
	return images, nil
}

type WalkCB func(header *tar.Header, rdr io.Reader) (bool, error)

func (reg *OCIRegistry) WalkTGZ(f *os.File, cb WalkCB) error {
	gzr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tarr := tar.NewReader(gzr)
	for {
		h, err := tarr.Next()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		cont, err := cb(h, tarr)
		if !cont {
			return nil
		} else if err != nil {
			return err
		}
	}
}

func (reg *OCIRegistry) SummarizeOCIFile(path string) (*OCISummary, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	entry := OCISummary{
		Path:    path,
		Blobs:   make(map[string]*OCIBlobEntry),
		Refs:    make(map[string]string),
		ModTime: fi.ModTime(),
	}

	var layout *ociImage.ImageLayout
	err = reg.WalkTGZ(f, func(header *tar.Header, rdr io.Reader) (bool, error) {
		if !header.FileInfo().Mode().IsRegular() {
			return true, nil
		}
		if strings.HasPrefix(header.Name, "blobs/") {
			blob := strings.Replace(header.Name[6:], "/", ":", 1)
			f, err := ioutil.TempFile("", "reg_blob_")
			if err != nil {
				return false, fmt.Errorf("Could not create temp file for blob %s: %v", blob, err)
			}
			if err := os.Remove(f.Name()); err != nil {
				f.Close()
				return false, fmt.Errorf("Could not unlink temp file for blob %s: %v", blob, err)
			}
			n, err := io.Copy(f, rdr)
			if err != nil {
				f.Close()
				return false, fmt.Errorf("Could not cache blob %s: %v", blob, err)
			}
			if n != header.Size {
				f.Close()
				return false, fmt.Errorf("Blob %s too short")
			}
			entry.Blobs[blob] = &OCIBlobEntry{
				Size:   header.Size,
				Source: path,
				File:   f,
			}
		} else if header.Name == "index.json" {
			var index ociImage.Index
			if err := json.NewDecoder(rdr).Decode(&index); err != nil {
				return false, fmt.Errorf("Index decoding failed: %v", err)
			}

			for _, manifest := range index.Manifests {
				if manifest.MediaType != ociImage.MediaTypeImageManifest {
					continue
				}
				if manifest.Annotations == nil {
					continue
				}
				refname := manifest.Annotations["org.opencontainers.image.ref.name"]
				if refname == "" {
					continue
				}
				entry.Refs[refname] = manifest.Digest.String()
			}

		} else if strings.HasPrefix(header.Name, "refs/") {
			refname := header.Name[5:]
			var refblob ociImage.Descriptor
			if err := json.NewDecoder(rdr).Decode(&refblob); err != nil {
				return false, fmt.Errorf("Ref descriptor decoding failed: %v", err)
			}
			if refblob.MediaType != "application/vnd.oci.image.manifest.v1+json" {
				// Ignore unknown manifest type
				return true, nil
			}
			entry.Refs[refname] = refblob.Digest.String()
		} else if header.Name == "oci-layout" {
			return true, json.NewDecoder(rdr).Decode(&layout)
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	if layout == nil {
		return nil, fmt.Errorf("No ImageLayout found!")
	}
	if layout.Version != "1.0.0" {
		return nil, fmt.Errorf("Unknown OCI version '%s'", layout.Version)
	}
	return &entry, nil
}

func (reg *OCIRegistry) GetManifestBlob(name, reference string) string {
	reg.mut.Lock()

	// Get the current reference. Might now exist
	curref := reg.refs[name+":"+reference]

	cands, err := reg.FindCandidates(name, reference)
	if err != nil {
		reg.mut.Unlock()
		log.WithFields(log.Fields{
			"name":      name,
			"reference": reference,
			"error":     err,
		}).Debug("Candidate search failed")
		return ""
	}

	// Does the original file still exist? If not, unset the current
	// reference.
	if curref != nil {
		if _, err := os.Stat(curref.Path); err != nil {
			curref = nil
		}
	}

	// Scan through the candidates until we find a viable OCI
	var viable []ImageCandidate
	for _, c := range cands {
		if curref == nil || c.ModTime.After(curref.ModTime) {
			viable = append(viable, c)
		}
	}
	if len(viable) == 0 {
		var blob string
		if curref != nil {
			blob = curref.Blob
		}
		reg.mut.Unlock()
		return blob
	}
	reg.mut.Unlock() // Release the lock while we scan
	sort.Sort(ImageCandidateSlice(viable))

	// We now have a list of viable candidates to scan
	var choice *OCISummary
	for _, v := range viable {
		log.WithFields(log.Fields{
			"name":      name,
			"reference": reference,
			"file":      v.Path,
		}).Debug("Summarizing OCI file")
		entry, err := reg.SummarizeOCIFile(v.Path)
		if err != nil {
			log.WithFields(log.Fields{
				"name":      name,
				"reference": reference,
				"file":      v.Path,
				"error":     err,
			}).Error("OCI summary failed")
			continue // This OCI failed, but another one might succeed
		}
		log.WithFields(log.Fields{
			"name":      name,
			"reference": reference,
			"file":      v.Path,
			"refs":      entry.Refs,
			"blobs":     len(entry.Blobs),
		}).Debug("OCI file summary")

		if _, ok := entry.Refs[reference]; ok {
			choice = entry
			break
		}
	}

	if choice == nil {
		return "" // Couldn't find the blob anywhere :(
	}

	reg.mut.Lock()
	defer reg.mut.Unlock()

	for b, f := range choice.Blobs {
		if _, ok := reg.blobs[b]; !ok {
			reg.blobs[b] = f
		} else {
			f.File.Close() // Blob already exists, so we can close the new file
		}
	}

	// Reload curref, it might have changed!
	curref = reg.refs[name+":"+reference]
	if curref != nil && curref.ModTime.After(choice.ModTime) {
		// A better choice was selected concurrently, return that
		return curref.Blob
	}

	curref = &OCIReferenceEntry{
		Name:      name,
		Reference: reference,
		Path:      choice.Path,
		Blob:      choice.Refs[reference],
		ModTime:   choice.ModTime,
	}
	reg.refs[name+":"+reference] = curref

	return curref.Blob
}

func (reg *OCIRegistry) GetBlob(blob string, cb func(size int64, rdr io.Reader) error) (bool, error) {
	reg.mut.Lock()
	// No defer, need explicit control so we don't have to hold the lock during the
	// file scan.

	b, ok := reg.blobs[blob]
	if !ok {
		reg.mut.Unlock()
		return false, fmt.Errorf("Blob reference not found")
	}

	size := b.Size
	rdr := io.NewSectionReader(b.File, 0, size)

	// Now that we have the file handle, we can drop the lock safely
	reg.mut.Unlock()

	return true, cb(size, rdr)
}

func (reg *OCIRegistry) HandleManifests(name, reference string, w http.ResponseWriter, r *http.Request) {
	blob := reg.GetManifestBlob(name, reference)
	if blob == "" {
		w.WriteHeader(404)
		return
	}
	found, _ := reg.GetBlob(blob, func(size int64, rdr io.Reader) error {
		w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
		w.WriteHeader(200)
		_, err := io.Copy(w, rdr)
		return err
	})
	if !found {
		w.WriteHeader(404)
	}
}

func (reg *OCIRegistry) HandleBlobs(name, blob string, w http.ResponseWriter, r *http.Request) {
	found, _ := reg.GetBlob(blob, func(size int64, rdr io.Reader) error {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
		w.WriteHeader(200)
		_, err := io.Copy(w, rdr)
		return err
	})
	if !found {
		w.WriteHeader(404)
	}
}

func (reg *OCIRegistry) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.String(), "/v2/"))

	if path == "" {
		w.WriteHeader(200)
		return
	}

	parts := strings.Split(path, "/")
	if len(parts) < 3 {
		w.WriteHeader(404)
		return
	}

	nameseg := parts[0 : len(parts)-2]
	for i := len(nameseg) - 1; i >= 0; i-- {
		nameseg[i] = strings.TrimSpace(nameseg[i])
		if nameseg[i] == ".." || nameseg[i] == "." {
			nameseg = append(nameseg[0:i], nameseg[i+1:]...)
		}
	}
	name := strings.Join(nameseg, "/")
	action := parts[len(parts)-2]
	reference := parts[len(parts)-1]

	switch action {
	case "blobs":
		log.WithFields(log.Fields{
			"name":   name,
			"method": r.Method,
			"blob":   reference,
		}).Debug("Blob request")
		reg.HandleBlobs(name, reference, w, r)
	case "manifests":
		log.WithFields(log.Fields{
			"name":      name,
			"method":    r.Method,
			"reference": reference,
		}).Debug("Manifest request")
		reg.HandleManifests(name, reference, w, r)
	default:
		w.WriteHeader(404)
		w.Write([]byte("{}"))
	}
}

func main() {

	loglevel := flag.String("loglevel", "info", "Debug level")
	basedir := flag.String("dir", "./images/", "Directory to load images from")
	certfile := flag.String("cert", "cert.pem", "File to load TLS certificate from")
	keyfile := flag.String("keyfile", "key.pem", "File to load TLS secret key from")
	listen := flag.String("listen", ":443", "Listen address")

	flag.Parse()
	level, err := log.ParseLevel(*loglevel)
	if err != nil {
		log.Fatalf("Invalid log level '%s'", *loglevel)
	}
	log.SetLevel(level)

	*basedir, err = filepath.Abs(*basedir)
	if err != nil {
		log.Fatalf("Could not open base dir: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/v2/", NewOCIRegistry(*basedir))

	log.Fatal(http.ListenAndServeTLS(*listen, *certfile, *keyfile, mux))
}
