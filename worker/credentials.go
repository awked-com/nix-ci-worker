package worker

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
)

const credentialLimit = 1024 * 1024

// Secret keeps credentials in memory and redacts them when formatted.
type Secret struct{ Data []byte }

func (Secret) String() string { return "[secret]" }

func (Secret) GoString() string { return "[secret]" }

func ReadCredentialFile(path string) (Secret, error) {
	file, err := os.Open(path)
	if err != nil {
		return Secret{}, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, credentialLimit+1))
	if err == nil && len(data) > credentialLimit {
		err = errors.New("credential exceeds size limit")
	}
	if err != nil {
		return Secret{}, err
	}
	return Secret{Data: data}, nil
}

func withCredential(secret Secret, callback func(string, []*os.File) error) error {
	reader, writer, err := os.Pipe()
	if err != nil {
		return err
	}

	done := make(chan error, 1)
	go func() {
		_, err := writer.Write(secret.Data)
		writer.Close()
		done <- err
	}()
	err = callback("/dev/fd/3", []*os.File{reader})
	reader.Close()
	feedErr := <-done
	if err != nil {
		return err
	}

	return feedErr
}

func IdentityRecipients(identity Secret) (Secret, error) {
	identities, err := age.ParseIdentities(bytes.NewReader(identity.Data))
	if err != nil {
		return Secret{}, errors.New("invalid age identity")
	}
	var recipients strings.Builder
	for _, identity := range identities {
		switch identity := identity.(type) {
		case *age.X25519Identity:
			fmt.Fprintln(&recipients, identity.Recipient())
		case *age.HybridIdentity:
			fmt.Fprintln(&recipients, identity.Recipient())
		default:
			return Secret{}, errors.New("unsupported age identity")
		}
	}
	if recipients.Len() == 0 {
		return Secret{}, errors.New("empty age identity")
	}
	return Secret{Data: []byte(recipients.String())}, nil
}

func EncryptedStream(source io.Reader, credential Secret) (io.ReadCloser, error) {
	recipients, err := age.ParseRecipients(bytes.NewReader(credential.Data))
	if err != nil || len(recipients) == 0 {
		return nil, errors.New("invalid age recipients")
	}
	return transformStream(source, func(output io.Writer) error {
		writer, err := age.Encrypt(output, recipients...)
		if err != nil {
			return err
		}
		if _, err = io.Copy(writer, source); err != nil {
			return err
		}
		return writer.Close()
	}), nil
}

func decryptedStream(source io.Reader, identity Secret) (io.ReadCloser, error) {
	identities, err := age.ParseIdentities(bytes.NewReader(identity.Data))
	if err != nil || len(identities) == 0 {
		return nil, errors.New("invalid age identity")
	}
	return transformStream(source, func(output io.Writer) error {
		reader, err := age.Decrypt(source, identities...)
		if err != nil {
			return err
		}
		_, err = io.Copy(output, reader)
		return err
	}), nil
}
