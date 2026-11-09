// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/otfabric/go-mms-trace/trace"
)

// inputError marks an error in reading a capture: a file that cannot be
// opened, is not a capture or is damaged.
type inputError struct{ err error }

func (e *inputError) Error() string { return e.err.Error() }
func (e *inputError) Unwrap() error { return e.err }

// inputErr marks err, from opening or reading the captures, as an input
// error.
func inputErr(err error) error {
	if err == nil {
		return nil
	}
	return &inputError{err}
}

// outputError marks an output that cannot be written: a closed pipe or a
// full disk.
type outputError struct{ err error }

func (e *outputError) Error() string { return e.err.Error() }
func (e *outputError) Unwrap() error { return e.err }

// outWriter marks the write errors of an output, so that they are told from
// input errors.
type outWriter struct{ w io.Writer }

func (o outWriter) Write(b []byte) (int, error) {
	n, err := o.w.Write(b)
	if err != nil {
		return n, &outputError{err}
	}
	return n, nil
}

// exitCode classifies a command's error (docs/exitcodes.md).
func exitCode(ctx context.Context, err error) int {
	var out *outputError
	var in *inputError
	switch {
	case err == nil:
		return exitOK
	case ctx.Err() != nil, errors.Is(err, context.Canceled):
		return exitInterrupted
	case errors.Is(err, errUsage), strings.HasPrefix(err.Error(), "unknown command "): // cobra's
		return exitUsage
	case errors.As(err, &out):
		return exitInternal
	case errors.As(err, &in), errors.Is(err, trace.ErrCorrupt), errors.Is(err, trace.ErrFormat):
		return exitInvalidInput
	default:
		return exitInternal
	}
}
