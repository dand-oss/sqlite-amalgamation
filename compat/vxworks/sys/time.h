#ifndef SQLITE3_VXWORKS_SYS_TIME_H
#define SQLITE3_VXWORKS_SYS_TIME_H

#if !defined(SCADAPACK_VXWORKS_SQLITE)
#error "compat/vxworks/sys/time.h is only valid for the SCADAPack VxWorks SQLite target"
#endif

#include <sys/times.h>

int gettimeofday(struct timeval *tp, struct timezone *tzp);

#endif
