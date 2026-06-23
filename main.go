package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/yetanotherchris/rclone-encrypt-test-chatgpt/internal/crypt"
	"golang.org/x/term"
)

const (
	defaultEncoding = "base32"
	envPasswordVar  = "RCLONE_ENCRYPT_PASSWORD"
	envSaltVar      = "RCLONE_ENCRYPT_SALT"
)

var (
	version        = "dev"
	passwordReader = termReader
)

func main() {
	if err := run(os.Args, os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		printUsage(stderr)
		return errors.New("encrypt or decrypt command required")
	}

	switch args[1] {
	case "encrypt", "decrypt":
		return operate(args[1], args[2:], stdin, stdout, stderr)
	case "--version", "-version", "-v":
		fmt.Fprintf(stdout, "version %s\n", version)
		return nil
	case "--help", "-h":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown subcommand %q", args[1])
	}
}

func operate(mode string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet(mode, flag.ContinueOnError)
	flags.SetOutput(stderr)

	var (
		inputFile   string
		outputFile  string
		password    string
		salt        string
		encoding    string
		showVersion bool
	)
	flags.StringVar(&inputFile, "input-file", "", "path to the input file")
	flags.StringVar(&inputFile, "i", "", "alias for --input-file")
	flags.StringVar(&outputFile, "output-file", "", "optional output path")
	flags.StringVar(&outputFile, "o", "", "alias for --output-file")
	flags.StringVar(&password, "password", "", "(insecure) password, prefer env variable")
	flags.StringVar(&salt, "salt", "", "optional salt (also called password2)")
	flags.StringVar(&encoding, "filename-encoding", defaultEncoding, "filename encoding: base32, base64, base32768")
	flags.BoolVar(&showVersion, "version", false, "print version")

	if err := flags.Parse(args); err != nil {
		return err
	}

	if showVersion {
		fmt.Fprintf(stdout, "version %s\n", version)
		return nil
	}

	if inputFile == "" {
		return errors.New("-i/--input-file is required")
	}

	resolvedPassword, err := obtainSecret("password", password, envPasswordVar, false, stdin, stdout)
	if err != nil {
		return err
	}
	if password != "" {
		fmt.Fprintln(stderr, "WARNING: passing --password might leak secrets. Prefer", envPasswordVar, "or prompt and clear your shell history afterwards.")
	}
	resolvedSalt, err := obtainSecret("salt", salt, envSaltVar, true, stdin, stdout)
	if err != nil {
		return err
	}

	c, err := crypt.NewCipher(resolvedPassword, resolvedSalt, encoding)
	if err != nil {
		return fmt.Errorf("invalid cipher configuration: %w", err)
	}

	output := outputFile
	if output == "" {
		dir := filepath.Dir(inputFile)
		base := filepath.Base(inputFile)
		var fileName string
		if mode == "encrypt" {
			fileName = c.EncryptFileName(base)
		} else {
			decrypted, err := c.DecryptFileName(base)
			if err != nil {
				return fmt.Errorf("decrypting embedded filename: %w", err)
			}
			fileName = decrypted
		}
		if fileName == "" {
			return errors.New("resulting file name is empty")
		}
		output = filepath.Join(dir, fileName)
	}

	absInput, err := filepath.Abs(inputFile)
	if err != nil {
		return fmt.Errorf("failed to resolve %q: %w", inputFile, err)
	}
	absOutput, err := filepath.Abs(output)
	if err != nil {
		return fmt.Errorf("failed to resolve %q: %w", output, err)
	}
	if absInput == absOutput {
		return errors.New("input and output files must differ")
	}

	inFile, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("opening input file: %w", err)
	}
	defer inFile.Close()

	outFile, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("creating output file: %w", err)
	}
	defer outFile.Close()

	if mode == "encrypt" {
		if err := c.Encrypt(inFile, outFile); err != nil {
			return fmt.Errorf("encrypting data: %w", err)
		}
		fmt.Fprintf(stdout, "wrote encrypted file to %s\n", output)
		return nil
	}

	if err := c.Decrypt(inFile, outFile); err != nil {
		return fmt.Errorf("decrypting data: %w", err)
	}
	fmt.Fprintf(stdout, "wrote decrypted file to %s\n", output)
	return nil
}

func obtainSecret(label, provided, envVar string, allowEmpty bool, stdin io.Reader, stdout io.Writer) (string, error) {
	if provided != "" {
		return provided, nil
	}
	if env := os.Getenv(envVar); env != "" {
		return env, nil
	}
	prompt := fmt.Sprintf("Enter %s: ", label)
	secret, err := passwordReader(prompt, stdin, stdout)
	if err != nil {
		return "", err
	}
	secret = strings.TrimSpace(secret)
	if secret == "" && !allowEmpty {
		return "", fmt.Errorf("%s cannot be empty", label)
	}
	return secret, nil
}

func termReader(prompt string, stdin io.Reader, stdout io.Writer) (string, error) {
	if _, err := fmt.Fprint(stdout, prompt); err != nil {
		return "", err
	}
	if file, ok := stdin.(interface{ Fd() uintptr }); ok {
		fd := int(file.Fd())
		if term.IsTerminal(fd) {
			pass, err := term.ReadPassword(fd)
			fmt.Fprintln(stdout)
			if err != nil {
				return "", err
			}
			return string(pass), nil
		}
	}
	reader := bufio.NewReader(stdin)
	line, err := reader.ReadString('\n')
	fmt.Fprintln(stdout)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `Usage: %s <encrypt|decrypt> -i INPUT [-o OUTPUT] [flags]

Commands:
  encrypt   encrypt a local file using rclone secrets
  decrypt   decrypt a file produced by this program

Flags:
  -i, --input-file string        path to the file to read from (required)
  -o, --output-file string       destination path (defaults to the transformed name)
  --password string             (insecure) password; prefer %s
  --salt string                 optional salt (rclone calls this password2)
  --filename-encoding string    base32, base64, or base32768 (default: %s)
  --version                     print embedded version and exit

Environment:
  %s  supply the password without exposing it on the command line
  %s     supply the optional salt

`, filepath.Base(os.Args[0]), envPasswordVar, defaultEncoding, envPasswordVar, envSaltVar)
}
