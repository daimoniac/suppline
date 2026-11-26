package types

import "strings"

// IsKernelHeaderPackage reports whether a package ships only Linux kernel
// headers. Scanners map kernel CVEs onto these packages, but a container runs
// the node's kernel, so the image holds none of the vulnerable kernel code.
func IsKernelHeaderPackage(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "linux-libc-dev", "linux-headers", "kernel-headers", "linux-api-headers", "linux-uapi-headers":
		return true
	}
	return strings.HasPrefix(n, "linux-headers-")
}
