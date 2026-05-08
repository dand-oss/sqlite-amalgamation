#ifndef SQLITE3_VXWORKS_SEMAPHORE_H
#define SQLITE3_VXWORKS_SEMAPHORE_H

#if !defined(SCADAPACK_VXWORKS_SQLITE)
#error "compat/vxworks/semaphore.h is only valid for the SCADAPack VxWorks SQLite target"
#endif

#include <fcntl.h>

typedef struct sqlite3_vxworks_posix_sem sem_t;

#ifndef SEM_FAILED
#define SEM_FAILED ((sem_t *)0)
#endif

sem_t *sem_open(const char *name, int oflag, ...);
int sem_close(sem_t *sem);
int sem_unlink(const char *name);
int sem_trywait(sem_t *sem);
int sem_post(sem_t *sem);

#endif
