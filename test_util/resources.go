package test_util

import (
	"io/ioutil"
	"os"

	"code.cloudfoundry.org/localip"
	. "github.com/onsi/gomega"
)

// NextAvailPort returns an available TCP port number. It may return a port
// number that was previously returned from this function if that port has not
// been used by the time this function is invocated again. Port collisions
// may occur during this race condition.
func NextAvailPort() uint16 {
	port, err := localip.LocalPort()
	Expect(err).ToNot(HaveOccurred())

	return port
}

// TempUnixSocket returns a temp file name that can be used as a unix socket.
// Collisions may occur in the unlikely scenario that this function returns
// the same temp file name as a previous invocation.
func TempUnixSocket() string {
	tmpfile, err := ioutil.TempFile("", "gorouter.sock")
	Expect(err).ToNot(HaveOccurred())
	defer os.Remove(tmpfile.Name())

	err = tmpfile.Close()
	Expect(err).ToNot(HaveOccurred())
	return tmpfile.Name()
}
