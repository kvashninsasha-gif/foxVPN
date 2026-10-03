//go:build darwin

package main

/*
#include <unistd.h>
#include <grp.h>
#include <errno.h>
int fox_drop_privileges(int uid) {
  if (setgroups(0, NULL) || setgid(65534) || setuid(uid)) return errno;
  return getuid() == uid && geteuid() == uid ? 0 : EPERM;
}
*/
import "C"
import (
 "fmt"
 "os"
 "strconv"
)

// Only the root-owned foxVPN daemon sets this after constructing the TUN.
// The core cannot regain root. PF can then allow its dedicated uid, rather
// than allowing every root process to bypass the kill switch.
func foxDropPrivileges() error {
 raw := os.Getenv("FOXVPN_CORE_UID")
 if raw == "" { return nil }
 uid, err := strconv.Atoi(raw)
 if err != nil || uid != 62077 || os.Geteuid() != 0 { return fmt.Errorf("invalid foxVPN service identity") }
 if code := C.fox_drop_privileges(C.int(uid)); code != 0 { return fmt.Errorf("drop network-core privileges: errno %d", int(code)) }
 return nil
}
