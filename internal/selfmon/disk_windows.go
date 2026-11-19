//go:build windows

package selfmon

import "golang.org/x/sys/windows"

func diskSpace(dir string) (free, total int64, ok bool) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, 0, false
	}
	var avail, tot, totFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &avail, &tot, &totFree); err != nil {
		return 0, 0, false
	}
	return int64(avail), int64(tot), true
}
