package commands

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// ReadLine prints prompt and reads one line from stdin, trimming CR/LF.
func ReadLine(prompt string) (string, error) {
	fmt.Print(prompt)
	r := bufio.NewReader(os.Stdin)
	line, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read input: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// ReadPassword prints prompt, reads a password without terminal echo, and
// prints a trailing newline. The returned slice must be zeroed by the caller
// after use.
func ReadPassword(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	defer fmt.Println()
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	return pw, nil
}

// ReadLineWithDefault prompts and returns input, falling back to def when empty.
func ReadLineWithDefault(prompt, def string) (string, error) {
	display := prompt
	if def != "" {
		display = fmt.Sprintf("%s [%s]: ", strings.TrimSuffix(strings.TrimSuffix(prompt, ": "), " "), def)
	}
	val, err := ReadLine(display)
	if err != nil {
		return "", err
	}
	if val == "" {
		return def, nil
	}
	return val, nil
}

// ReadPasswordOptional reads a password without echo. Returns nil if the user
// presses Enter without typing anything (meaning "keep current value").
func ReadPasswordOptional(prompt string) ([]byte, error) {
	fmt.Print(prompt)
	defer fmt.Println()
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	if len(pw) == 0 {
		return nil, nil
	}
	return pw, nil
}

// ZeroBytes overwrites b with zeros to remove sensitive data from memory.
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
