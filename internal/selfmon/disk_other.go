//go:build !(linux || darwin || freebsd || netbsd || openbsd || windows)

package selfmon

func diskSpace(string) (int64, int64, bool) { return 0, 0, false }
