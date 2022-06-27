package gsandbox_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/souk4711/gsandbox"
)

var _ = Describe("Version", func() {
	var subject = ""

	BeforeEach(func() {
		subject = gsandbox.Version()
	})

	It("satisfies semantic versioning", func() {
		Expect(subject).To(MatchRegexp(`\A\d+\.\d+\.\d+\z`))
	})
})
