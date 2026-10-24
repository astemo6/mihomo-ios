#ifndef NC_LWIP_SYS_ARCH_H
#define NC_LWIP_SYS_ARCH_H

/* NO_SYS=1: no threads, no semaphores/mutexes/mailboxes are ever used.
   lwIP still wants these typedefs to exist. */
typedef unsigned int sys_prot_t;
typedef void *sys_sem_t;
typedef void *sys_mutex_t;
typedef void *sys_mbox_t;
typedef void *sys_thread_t;

#endif
