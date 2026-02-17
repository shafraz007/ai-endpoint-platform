package logging

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type dailyFileWriter struct {
	mu          sync.Mutex
	dir         string
	baseName    string
	currentDate string
	file        *os.File
	maxDays     int
}

func newDailyFileWriter(dir, baseName string, maxDays int) (*dailyFileWriter, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	w := &dailyFileWriter{
		dir:      dir,
		baseName: baseName,
		maxDays:  maxDays,
	}
	if err := w.rotateIfNeeded(time.Now()); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *dailyFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.rotateIfNeeded(time.Now()); err != nil {
		return 0, err
	}

	return w.file.Write(p)
}

func (w *dailyFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	return w.file.Close()
}

func (w *dailyFileWriter) rotateIfNeeded(now time.Time) error {
	date := now.Format("2006-01-02")
	if w.file != nil && date == w.currentDate {
		return nil
	}

	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}

	filename := fmt.Sprintf("%s-%s.log", w.baseName, date)
	path := filepath.Join(w.dir, filename)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}

	w.file = file
	w.currentDate = date
	w.cleanupOldFiles()
	return nil
}

func (w *dailyFileWriter) cleanupOldFiles() {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return
	}

	prefix := w.baseName + "-"
	type logFile struct {
		path string
		date time.Time
	}
	var logs []logFile

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, ".log") {
			continue
		}
		datePart := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ".log")
		parsed, err := time.Parse("2006-01-02", datePart)
		if err != nil {
			continue
		}
		logs = append(logs, logFile{
			path: filepath.Join(w.dir, name),
			date: parsed,
		})
	}

	if len(logs) <= w.maxDays {
		return
	}

	sort.Slice(logs, func(i, j int) bool {
		return logs[i].date.Before(logs[j].date)
	})

	excess := len(logs) - w.maxDays
	for i := 0; i < excess; i++ {
		_ = os.Remove(logs[i].path)
	}
}

func Setup(appName, dir string, alsoConsole bool) (io.Closer, error) {
	writer, err := newDailyFileWriter(dir, appName, 7)
	if err != nil {
		return nil, err
	}

	if alsoConsole {
		log.SetOutput(io.MultiWriter(os.Stdout, writer))
	} else {
		log.SetOutput(writer)
	}

	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	return writer, nil
}
