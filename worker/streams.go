package worker

import (
	"errors"
	"io"
	"os/exec"
	"sync"
)

type processReader struct {
	*io.PipeReader
	cmd  *exec.Cmd
	done chan struct{}
	once sync.Once
}

func (p *processReader) Close() error {
	p.once.Do(func() {
		p.PipeReader.Close()
		p.cmd.Process.Kill()
		<-p.done
	})
	return nil
}

func ProcessStream(command []string, dir string, stderr io.Writer, environment []string) (io.ReadCloser, error) {
	if len(command) == 0 {
		return nil, errors.New("empty subprocess command")
	}

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Dir = dir
	cmd.Stderr = stderr
	cmd.Env = environment

	reader, writer := io.Pipe()
	cmd.Stdout = writer
	if err := cmd.Start(); err != nil {
		reader.Close()
		writer.Close()
		return nil, err
	}

	result := &processReader{
		PipeReader: reader,
		cmd:        cmd,
		done:       make(chan struct{}),
	}
	go func() {
		err := cmd.Wait()
		writer.CloseWithError(err)
		close(result.done)
	}()
	return result, nil
}

// transformStream closes its source on completion or cancellation, including a
// subprocess whose output would otherwise remain blocked after an upload fails.
func transformStream(source io.Reader, transform func(io.Writer) error) io.ReadCloser {
	reader, writer := io.Pipe()
	stream := &transformReader{PipeReader: reader, done: make(chan struct{})}
	if closer, ok := source.(io.Closer); ok {
		stream.source = closer
	}
	go func() {
		err := transform(writer)
		stream.closeSource()
		writer.CloseWithError(err)
		close(stream.done)
	}()
	return stream
}

type transformReader struct {
	*io.PipeReader
	source io.Closer
	done   chan struct{}
	once   sync.Once
}

func (s *transformReader) closeSource() {
	s.once.Do(func() {
		if s.source != nil {
			s.source.Close()
		}
	})
}

func (s *transformReader) Close() error {
	s.PipeReader.Close()
	s.closeSource()
	<-s.done
	return nil
}
