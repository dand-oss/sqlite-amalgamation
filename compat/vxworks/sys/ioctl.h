#ifndef SQLITE3_VXWORKS_SYS_IOCTL_H
#define SQLITE3_VXWORKS_SYS_IOCTL_H

#if !defined(SCADAPACK_VXWORKS_SQLITE)
#error "compat/vxworks/sys/ioctl.h is only valid for the SCADAPack VxWorks SQLite target"
#endif

int ioctl(int fd, int request, ...);

#endif
