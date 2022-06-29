package gsandbox_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestGsandbox(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Gsandbox Suite")
}
