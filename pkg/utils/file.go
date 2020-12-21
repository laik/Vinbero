package utils

import (
	"io/ioutil"
	"os"

	"github.com/pkg/errors"
)

func FileOpen(filepath *string) ([]byte, error) {
	buf, err := ioutil.ReadFile(*filepath)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return buf, nil
}

func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}
