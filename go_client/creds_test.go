package main

import "testing"

func TestClassifyTerminalVKJoinError(t *testing.T) {
	tests := []struct {
		name string
		err  map[string]interface{}
		want string
	}{
		{
			name: "invalid link code",
			err: map[string]interface{}{
				"error_code": float64(9008),
				"error_msg":  "Join link is not valid",
			},
			want: "INVALID_JOIN_LINK",
		},
		{
			name: "anonymous blocked text",
			err: map[string]interface{}{
				"error_code": float64(1),
				"error_msg":  "anonymous join is disabled",
			},
			want: "ANON_BLOCKED",
		},
		{
			name: "call full text",
			err: map[string]interface{}{
				"error_code": float64(1),
				"error_msg":  "call is full",
			},
			want: "CALL_FULL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyTerminalVKJoinError(tt.err)
			if got == nil || got.Error() != tt.want {
				t.Fatalf("got %v, want %s", got, tt.want)
			}
		})
	}
}

func TestClassifyTerminalVKJoinErrorIgnoresTransient(t *testing.T) {
	got := classifyTerminalVKJoinError(map[string]interface{}{
		"error_code": float64(14),
		"error_msg":  "Captcha needed",
	})
	if got != nil {
		t.Fatalf("unexpected terminal error: %v", got)
	}
}
