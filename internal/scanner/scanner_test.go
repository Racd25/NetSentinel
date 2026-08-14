package scanner

import (
	"reflect"
	"testing"
)

func TestParsePorts(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []int
		wantErr  bool
	}{
		{
			name:     "single port",
			input:    "80",
			expected: []int{80},
			wantErr:  false,
		},
		{
			name:     "multiple ports",
			input:    "22,80,443",
			expected: []int{22, 80, 443},
			wantErr:  false,
		},
		{
			name:     "range",
			input:    "1-5",
			expected: []int{1, 2, 3, 4, 5},
			wantErr:  false,
		},
		{
			name:     "mixed",
			input:    "22,80,443,8000-8002",
			expected: []int{22, 80, 443, 8000, 8001, 8002},
			wantErr:  false,
		},
		{
			name:    "invalid port",
			input:   "99999",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePorts(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParsePorts() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("ParsePorts() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestServiceName(t *testing.T) {
	tests := []struct {
		port     int
		expected string
	}{
		{22, "SSH"},
		{80, "HTTP"},
		{443, "HTTPS"},
		{9999, "unknown"},
	}

	for _, tt := range tests {
		got := ServiceName(tt.port)
		if got != tt.expected {
			t.Errorf("ServiceName(%d) = %s, want %s", tt.port, got, tt.expected)
		}
	}
}
