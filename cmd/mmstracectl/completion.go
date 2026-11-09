// SPDX-License-Identifier: MIT

package main

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// captureExts are the file extensions offered for a capture argument.
var captureExts = []string{"pcap", "pcapng", "cap", "gz"}

// valuesAnnotation is the flag annotation that holds a flag's value set.
const valuesAnnotation = "mmstracectl_values"

// registerCompletions gives every flag of every command a completion: its
// value set, or no file names for a free value; and the capture arguments
// complete capture files.
func registerCompletions(root *cobra.Command) {
	walk(root, func(c *cobra.Command) {
		if c.ValidArgsFunction == nil && len(c.ValidArgs) == 0 && strings.Contains(c.Use, "CAPTURE") {
			c.ValidArgsFunction = func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
				return captureExts, cobra.ShellCompDirectiveFilterFileExt
			}
		}
		each := func(f *pflag.Flag) {
			if _, ok := c.GetFlagCompletionFunc(f.Name); ok || f.Value.Type() == "bool" {
				return
			}
			fn := cobra.NoFileCompletions
			if v := f.Annotations[valuesAnnotation]; len(v) > 0 {
				fn = cobra.FixedCompletions(v, cobra.ShellCompDirectiveNoFileComp)
			}
			_ = c.RegisterFlagCompletionFunc(f.Name, fn)
		}
		c.LocalFlags().VisitAll(each)
	})
}

func walk(c *cobra.Command, fn func(*cobra.Command)) {
	fn(c)
	for _, s := range c.Commands() {
		walk(s, fn)
	}
}
