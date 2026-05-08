#ifndef SQLITE3_VXWORKS_COMPAT_H
#define SQLITE3_VXWORKS_COMPAT_H

#if !defined(SCADAPACK_VXWORKS_SQLITE)
#error "sqlite3_vxworks_compat.h is only valid for the SCADAPack VxWorks SQLite target"
#endif

/*
** SCADAPack's VxWorks headers define isascii()/toascii() as macros.  Include
** newlib ctype.h first so its declarations are parsed before those macros
** become visible through VxWorks system headers.
*/
#include <ctype.h>

/*
** Let the SCADAPack VxWorks headers provide their own macro bodies without
** warning after newlib ctype.h has been parsed.
*/
#undef isascii
#undef toascii

#ifndef F_OK
#define F_OK 0
#endif

#ifndef R_OK
#define R_OK 4
#endif

#ifndef W_OK
#define W_OK 2
#endif

#ifndef INFINITY
#define INFINITY (1.0/0.0)
#endif

struct stat;

int access(const char *path, int mode);
int fchmod(int fd, unsigned int mode);
int fchown(int fd, int owner, int group);
int fcntl(int fd, int command, ...);
int lstat(const char *path, struct stat *buf);
long pread(int fd, void *buf, unsigned long nbyte, long offset);
long pwrite(int fd, const void *buf, unsigned long nbyte, long offset);
int readlink(const char *path, char *buf, unsigned long bufsiz);
unsigned int geteuid(void);

#endif
