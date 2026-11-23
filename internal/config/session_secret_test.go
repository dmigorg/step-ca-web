package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadSessionSecret(t *testing.T) {
	t.Parallel()

	content := strings.Repeat("a", 32)
	for _, test := range []struct {
		name    string
		content string
		want    string
		wantErr bool
	}{
		{name: "generated file with newline", content: content + "\n", want: content},
		{name: "short key", content: "weak\n", wantErr: true},
		{name: "empty file", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			file := filepath.Join(t.TempDir(), "secret")
			if err := os.WriteFile(file, []byte(test.content), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := readSessionSecret(file)
			if got != test.want || (err != nil) != test.wantErr {
				t.Errorf("readSessionSecret(%s) returned length %d and error %v, want length %d and error present %t", test.name, len(got), err, len(test.want), test.wantErr)
			}
		})
	}
}
