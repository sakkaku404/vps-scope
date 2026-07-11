//go:build !linux

package audit

func diskFreePercent(string) int { return -1 }
