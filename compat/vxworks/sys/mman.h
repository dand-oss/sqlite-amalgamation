#ifndef SQLITE3_VXWORKS_SYS_MMAN_H
#define SQLITE3_VXWORKS_SYS_MMAN_H

#if !defined(SCADAPACK_VXWORKS_SQLITE)
#error "compat/vxworks/sys/mman.h is only valid for the SCADAPack VxWorks SQLite target"
#endif

#include <stddef.h>

#ifndef PROT_READ
#define PROT_READ 0x1
#endif

#ifndef PROT_WRITE
#define PROT_WRITE 0x2
#endif

#ifndef MAP_SHARED
#define MAP_SHARED 0x01
#endif

#ifndef MAP_FAILED
#define MAP_FAILED ((void *)-1)
#endif

void *mmap(void *addr, size_t len, int prot, int flags, int fd, long off);
int munmap(void *addr, size_t len);

#endif
