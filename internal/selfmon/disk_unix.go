//go:build linux || darwin || freebsd || netbsd || openbsd

package selfmon

import "golang.org/x/sys/unix"

// diskSpace returns the free (available to this process) and total bytes of the file system
// holding dir.
func diskSpace(dir string) (free, total int64, ok bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, 0, false
	}
	bs := int64(st.Bsize) //nolint:unconvert // the field type differs between platforms
	return int64(st.Bavail) * bs, int64(st.Blocks) * bs, true
}
