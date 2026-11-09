// SPDX-License-Identifier: MIT

// Command mmstracectl reads packet captures (pcap or pcapng, plain or gzip)
// and reports the IEC 61850 traffic in them: the MMS associations with
// their transactions and reports, and the GOOSE and Sampled Values
// streams. It never captures live and never sends anything: the capture is
// its only input.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/otfabric/go-mms-trace/cmd/mmstracectl/internal/buildinfo"
)

// Set by the linker (see Makefile and .github/workflows/release.yml); empty
// when not injected, and then resolved by buildinfo.
var (
	version   = ""
	tag       = ""
	commit    = ""
	buildDate = ""
)

// build is the resolved build information of this binary.
func build() buildinfo.Info {
	return buildinfo.Resolve("mmstracectl", version, tag, commit, buildDate, "github.com/otfabric/go-mms-trace")
}

// Exit codes (docs/exitcodes.md): the organisation table. No command
// completes with a result that reports problems, so 1 (findings) is not
// used; a damaged capture is invalid input even when what was read before
// the damage is printed.
const (
	exitOK           = 0
	exitUsage        = 2
	exitInvalidInput = 3
	exitInternal     = 10 // output that cannot be written, or an internal error
	exitInterrupted  = 130
)

// errUsage marks an error in the command line.
var errUsage = errors.New("usage")

func usageErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errUsage, fmt.Sprintf(format, args...))
}

// env is what a command reads and writes besides files.
type env struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	e := &env{stdin: stdin, stdout: outWriter{stdout}, stderr: stderr}
	root := rootCommand(e)
	root.SetArgs(args)
	root.SetIn(stdin)
	root.SetOut(e.stdout)
	root.SetErr(stderr)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return exitOK
	}
	code := exitCode(ctx, err)
	switch code {
	case exitUsage:
		_, _ = fmt.Fprintf(stderr, "mmstracectl: %s\n", strings.TrimPrefix(err.Error(), errUsage.Error()+": "))
		_, _ = fmt.Fprintln(stderr, "Run 'mmstracectl --help' for usage.")
	case exitInterrupted:
		_, _ = fmt.Fprintln(stderr, "mmstracectl: interrupted")
	default:
		_, _ = fmt.Fprintf(stderr, "mmstracectl: %v\n", err)
	}
	return code
}

func rootCommand(e *env) *cobra.Command {
	root := &cobra.Command{
		Use:   "mmstracectl",
		Short: "Analyse MMS, GOOSE and Sampled Values traffic in pcap and pcapng captures",
		Long: `mmstracectl reads packet captures (pcap or pcapng, plain or gzip) and reports
the IEC 61850 traffic in them: the MMS associations over ISO-on-TCP with their
confirmed services paired by invoke ID and their reports, and the GOOSE and
Sampled Values streams. It never captures live and never sends anything: the
capture is its only input.

A capture argument is a path, or - for standard input. Several captures are
analysed one by one.

Every flag can also be set by an environment variable: MMSTRACECTL_ and the flag
name in capitals with dashes as underscores (MMSTRACECTL_FORMAT=json,
MMSTRACECTL_PORT=102,3782). A flag on the command line wins.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return applyEnv(cmd)
		},
	}
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageErr("%v", err) })
	root.AddCommand(infoCommand(e), associationsCommand(e), transactionsCommand(e), reportsCommand(e),
		gooseCommand(e), svCommand(e), versionCommand(e))
	registerCompletions(root)
	return root
}

// applyEnv sets every flag not given on the command line from its
// MMSTRACECTL_ environment variable.
func applyEnv(cmd *cobra.Command) error {
	var err error
	set := func(f *pflag.Flag) {
		if err != nil || f.Changed {
			return
		}
		name := "MMSTRACECTL_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if v, ok := os.LookupEnv(name); ok {
			if e := cmd.Flags().Set(f.Name, v); e != nil {
				err = usageErr("%s: %v", name, e)
			}
		}
	}
	cmd.Flags().VisitAll(set)
	return err
}

// args checks the number of positional arguments as a usage error.
func args(lo, hi int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, a []string) error {
		if len(a) < lo || (hi >= 0 && len(a) > hi) {
			return usageErr("%s: %s", cmd.Name(), cmd.Use)
		}
		return nil
	}
}

// Output formats.
const (
	formatText = "text"
	formatJSON = "json"
	formatCSV  = "csv"
)

// formatFlag adds --format with the formats a command writes; the first is
// the default.
func formatFlag(c *cobra.Command, dst *string, formats ...string) {
	c.Flags().StringVar(dst, "format", formats[0], "output format: "+strings.Join(formats, ", "))
	_ = c.Flags().SetAnnotation("format", valuesAnnotation, formats) // the flag exists
	prev := c.PreRunE
	c.PreRunE = func(cmd *cobra.Command, a []string) error {
		if !slices.Contains(formats, *dst) {
			return usageErr("--format %q: want %s", *dst, strings.Join(formats, ", "))
		}
		if prev != nil {
			return prev(cmd, a)
		}
		return nil
	}
}

func versionCommand(e *env) *cobra.Command {
	var format string
	c := &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Long: `Print the version, tag, commit, build date, OT Fabric libraries, Go version and
platform on one line, or with --format json as one line of JSON.`,
		Args: args(0, 0),
		RunE: func(*cobra.Command, []string) error {
			b := build()
			line := b.String()
			if format == formatJSON {
				line = b.JSON()
			}
			_, err := fmt.Fprintln(e.stdout, line)
			return err
		},
	}
	formatFlag(c, &format, formatText, formatJSON)
	return c
}
