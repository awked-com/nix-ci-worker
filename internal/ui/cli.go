// Package ui formats human-facing help and diagnostics without touching data streams.
package ui

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

func style(w io.Writer, code, text string) string {
	f, ok := w.(interface{ Fd() uintptr })
	if !ok || !term.IsTerminal(int(f.Fd())) || os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" || os.Getenv("CLICOLOR") == "0" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

type Command struct {
	Name, Summary, Usage, Example string
	Flags                         *flag.FlagSet
}

func New(name, summary, usage, example string) *Command {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}
	return &Command{name, summary, usage, example, flags}
}

func IsHelp(args []string) bool {
	return len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h")
}

func (c *Command) Help(out io.Writer) error {
	var b bytes.Buffer
	fmt.Fprintln(&b, style(out, "1;36", c.Name))
	fmt.Fprintln(&b, c.Summary)
	fmt.Fprintln(&b, "\n"+style(out, "1", "Usage:"))
	fmt.Fprintln(&b, "  "+style(out, "36", c.Usage))
	fmt.Fprintln(&b, "\n"+style(out, "1", "Flags:"))
	c.Flags.VisitAll(func(f *flag.Flag) {
		name, usage := flag.UnquoteUsage(f)
		label := "--" + f.Name
		if name != "" {
			label += " " + name
		}
		fmt.Fprint(&b, "  "+style(out, "36", label)+"  "+usage)
		if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "0" {
			fmt.Fprintf(&b, " (default %s)", f.DefValue)
		}
		fmt.Fprintln(&b)
	})
	fmt.Fprintln(&b, "  "+style(out, "36", "-h, --help")+"  Show command help")
	if c.Example != "" {
		fmt.Fprintln(&b, "\n"+style(out, "1", "Examples:"))
		fmt.Fprintln(&b, style(out, "36", c.Example))
	}
	_, err := io.Copy(out, &b)
	return err
}

func (c *Command) Parse(args []string) error {
	err := c.Flags.Parse(args)
	if IsHelp(args) || errors.Is(err, flag.ErrHelp) {
		if err := c.Help(os.Stdout); err != nil {
			return err
		}
		return flag.ErrHelp
	}
	if err != nil {
		return c.Invalid(err.Error())
	}
	return nil
}

type usageError struct{ error }

func IsUsage(err error) bool { var usage *usageError; return errors.As(err, &usage) }

func (c *Command) Invalid(message string) error {
	return &usageError{fmt.Errorf("%s\nRun `%s --help` for usage", strings.TrimSpace(message), c.Name)}
}

// Report preserves protocol and child failure codes supplied by the caller.
func Report(err error, code int) int {
	if err == nil || errors.Is(err, flag.ErrHelp) {
		return 0
	}
	var usage *usageError
	if errors.As(err, &usage) {
		code = 2
	}
	fmt.Fprintln(os.Stderr, style(os.Stderr, "1;31", "error:"), err)
	return code
}
