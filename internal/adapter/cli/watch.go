package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/fsnotify/fsnotify"
)

// runWatcher uses fsnotify (inotify on Linux) to watch a local directory
// recursively and print every changed file path to stdout. The local sync
// coordinator reads this stream and pushes each file to the remote dest.
func runWatcher(dir string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("fsnotify: %w", err)
	}
	defer watcher.Close()
	if err := watchRecursive(watcher, dir); err != nil {
		return fmt.Errorf("watch %s: %w", dir, err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename) != 0 {
				fmt.Println(event.Name)
				if info, statErr := os.Stat(event.Name); statErr == nil && info.IsDir() {
					_ = watchRecursive(watcher, event.Name)
				}
			}
		}
	}
}

func watchRecursive(watcher *fsnotify.Watcher, root string) error {
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return watcher.Add(path)
		}
		return nil
	})
}
