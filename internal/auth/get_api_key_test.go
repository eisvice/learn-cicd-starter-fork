package auth

import (
	"net/http"
	"reflect"
	"testing"
)

func TestGetAPIKey_Success(t *testing.T) {
	headers := http.Header{};
	headers.Add("Authorization", "ApiKey Mee");

	auth, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v\n", err)
	}
	if !reflect.DeepEqual(auth, "Me") {
		t.Fatalf("expected bearer to be Me, got %s\n", auth)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	headers := http.Header{};
	headers.Add("Authorization", "Bearer");

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatalf("expected error, but did not get\n")
	}
	if !reflect.DeepEqual(
		err.Error(),
		"malformed authorization header",
	) {
		t.Fatalf("got the unexpected error text: %v", err)
	}
}

func TestGetAPIKey_EmptyHeader(t *testing.T) {
	headers := http.Header{};

	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatalf("expected error, but did not get\n")
	}
	if !reflect.DeepEqual(
		err.Error(),
		ErrNoAuthHeaderIncluded.Error(),
	) {
		t.Fatalf("got the unexpected error text: %v", err)
	}
}