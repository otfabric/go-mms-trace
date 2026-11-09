// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/otfabric/go-mms-trace/trace"
)

// analysis is one capture and what Analyze found in it.
type analysis struct {
	name string
	res  *trace.Result
	// err is the damage that ended reading early (wraps trace.ErrCorrupt);
	// res holds what was read before it.
	err error
}

// analysisFlags are the flags of every command that reads captures.
type analysisFlags struct {
	ports     []uint
	maxPacket int
}

func (f *analysisFlags) add(c *cobra.Command) {
	c.Flags().UintSliceVar(&f.ports, "port", []uint{102}, "TCP ports of MMS servers")
	c.Flags().IntVar(&f.maxPacket, "max-packet", 0, "largest packet record read, bytes (0: the reader's default, 256 KiB)")
}

func (f *analysisFlags) options() (trace.Options, error) {
	var o trace.Options
	if len(f.ports) == 0 {
		return o, usageErr("--port: at least one port")
	}
	for _, p := range f.ports {
		if p == 0 || p > 65535 {
			return o, usageErr("--port %d: not a TCP port", p)
		}
		o.Ports = append(o.Ports, uint16(p))
	}
	if f.maxPacket < 0 {
		return o, usageErr("--max-packet %d: negative", f.maxPacket)
	}
	o.MaxPacket = f.maxPacket
	return o, nil
}

// load analyses every capture. A capture that cannot be opened or is not a
// capture fails the command before anything is written; a damaged one is
// kept with what was read and its error.
func load(ctx context.Context, e *env, names []string, f *analysisFlags) ([]analysis, error) {
	o, err := f.options()
	if err != nil {
		return nil, err
	}
	stdin := 0
	for _, n := range names {
		if n == "-" {
			stdin++
		}
	}
	if stdin > 0 && len(names) > 1 {
		return nil, usageErr("standard input (-) cannot be combined with other captures")
	}
	out := make([]analysis, 0, len(names))
	for _, n := range names {
		a, err := analyse(ctx, e, n, o)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func analyse(ctx context.Context, e *env, name string, o trace.Options) (analysis, error) {
	r := e.stdin
	if name != "-" {
		f, err := os.Open(name)
		if err != nil {
			return analysis{}, inputErr(err)
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	res, err := trace.Analyze(ctx, r, o)
	switch {
	case err == nil:
		return analysis{name: name, res: res}, nil
	case errors.Is(err, trace.ErrCorrupt) && res != nil:
		return analysis{name: name, res: res, err: err}, nil
	case ctx.Err() != nil:
		return analysis{}, err
	default:
		return analysis{}, inputErr(fmt.Errorf("%s: %w", name, err))
	}
}

// damaged returns the error of the first damaged capture, as an input
// error naming the file, after the output was written.
func damaged(as []analysis) error {
	for _, a := range as {
		if a.err != nil {
			return inputErr(fmt.Errorf("%s: %w", a.name, a.err))
		}
	}
	return nil
}
