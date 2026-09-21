package worker

import (
	"errors"
	"regexp"
)

var requestIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

type BuildRequest struct {
	ID        string
	Source    string
	Selection map[string]string
}

func NewBuildRequest(id, source, host, pkg string) (BuildRequest, error) {
	request := BuildRequest{ID: id, Source: source}
	if !requestIDPattern.MatchString(id) {
		return request, errors.New("invalid build request ID")
	}
	if source == "" {
		return request, errors.New("build request must select a source ref")
	}
	if host == "" && pkg == "" {
		return request, nil
	}
	request.Selection = map[string]string{"host": host}
	if pkg != "" {
		request.Selection["package"] = pkg
	}
	return request, ValidateSelection(request.Selection)
}
