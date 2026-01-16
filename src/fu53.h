#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <semaphore.h>
#include <stdarg.h>
#include <sys/sem.h>
#include <stdint.h>
#include <limits.h>
#include <assert.h>
#include <sched.h>
#include <sys/mount.h>

typedef int (*open_type)(const char *pathname, int flags, ...);
typedef int (*open64_type)(const char *pathname, int flags, ...);
typedef int (*openat_type)(int dirfd, const char *pathname, int flags, ...);
typedef int (*creat_type)(const char *pathname, mode_t mode);
typedef void *(*dlopen_type)(const char *, int);
typedef FILE *(*fopen_type)(const char *pathname, const char *mode);
typedef FILE *(*fopen64_type)(const char *pathname, const char *mode);
typedef FILE *(*fdopen_type)(int fildes, const char *mode);
typedef FILE *(*freopen_type)(const char *pathname, const char *mode, FILE *stream);
typedef int (*remove_type)(const char *pathname);
typedef int (*rmdir_type)(const char *pathname);
typedef int (*unlink_type)(const char *pathname);
typedef int (*unlinkat_type)(int dirfd, const char *pathname, int flags);
typedef int (*execv_type)(const char *path, char *const argv[]);
typedef int (*execve_type)(const char *path, char *const argv[], char *const envp[]);
typedef int (*execvp_type)(const char *file, char *const argv[]);
typedef int (*execvpe_type)(const char *file, char *const argv[], char *const envp[]);
typedef int (*execveat_type)(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags);
typedef int (*fexecve_type)(int fd, char *const argv[], char *const envp[]);
typedef int (*rename_type)(const char *oldpath, const char *newpath);
typedef int (*renameat_type)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);
typedef int (*renameat2_type)(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);
typedef int (*chown_type)(const char *path, uid_t owner, gid_t group);
typedef int (*fchownat_type)(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);
typedef int (*chmod_type)(const char *pathname, mode_t mode);
typedef int (*fchmodat_type)(int dirfd, const char *pathname, mode_t mode, int flags);
typedef int (*system_type)(const char *command);
typedef long (*syscall_type)(long number, ...);
typedef int (*chroot_type)(const char *path);
typedef pid_t (*fork_type)(void);
typedef FILE *(*popen_type)(const char *command, const char *type);
typedef int (*mkfifo_type)(const char *pathname, mode_t mode);
typedef int (*mkfifoat_type)(int dirfd, const char *pathname, mode_t mode);
typedef int (*mknod_type)(const char *pathname, mode_t mode, dev_t dev);
typedef int (*mknodat_type)(int dirfd, const char *pathname, mode_t mode, dev_t dev);
typedef sem_t *(*sem_open_type)(const char *name, int oflag, ...);
typedef int (*semctl_type)(int semid, int semnum, int cmd, ...);
typedef int (*semget_type)(key_t key, int nsems, int semflg);
typedef int (*pipe_type)(int pipefd[2]);
typedef int (*dup_type)(int oldfd);
typedef int (*dup2_type)(int oldfd, int newfd);
typedef int (*dup3_type)(int oldfd, int newfd, int flags);
typedef int (*setenv_type)(const char *name, const char *value, int overwrite);
typedef int (*unsetenv_type)(const char *name);
typedef int (*unshare_type)(int flags);
typedef int (*mount_type)(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data);

/* Safe call of original open().
 * To prevent system file modification
 * we use /dev/null, when w/a/+ mods specified,
 * read access works normally.
 */
int open(const char *pathname, int flags, ...);

/* Safe call of original open64().
 * To prevent system file modification
 * we use /dev/null, when w/a/+ mods specified,
 * read access works normally.
 */
int open64(const char *pathname, int flags, ...);

/* Safe call of original openat().
 * To prevent system file modification
 * we use /dev/null, when w/a/+ mods specified,
 * read access works normally.
 */
int openat(int dirfd, const char *pathname, int flags, ...);

/* Stub for creat() function.
 * Need to prevent creating files.
 */
int creat(const char *pathname, mode_t mode);

/* Stub for dlopen() function.
 * Need to prevent preloading files.
 */
void *dlopen(const char *filename, int flag);

/* Safe call of original fopen().
 * To prevent system file modification
 * we use /dev/null, when w/a/+ mods specified,
 * read access works normally.
 */
FILE *fopen(const char *pathname, const char *mode);

/* Safe call of fopen64().
 * We use safe fopen() instead of original fopen64().
 */
FILE *fopen64(const char *pathname, const char *mode);

/* Safe call of original fdopen().
 * To prevent system file modification
 * we use /dev/null, when w/a/+ mods specified,
 * read access works normally.
 */
FILE *fdopen(int fildes, const char *mode);

/* Safe call of original freopen().
 * To prevent system file modification
 * we use /dev/null, when w/a/+ mods specified,
 * read access works normally.
 */
FILE *freopen(const char *path, const char *mode, FILE *stream);

/* Stub for remove() function.
 * Necessary to prevent removing files and dirs.
 */
int remove(const char *pathname);

/* Stub for rmdir() function.
 * Need to prevent removing directories.
 */
int rmdir(const char *pathname);

/* Stub for unlink() function.
 * Need to prevent removing files.
 */
int unlink(const char *fname);

/* Stub for unlinkat() function.
 * Need to prevent removing files.
 */
int unlinkat(int dirfd, const char *pathname, int flags);

/* Stub for execv() function.
 * Need to prevent executing files.
 */
int execv(const char *path, char *const argv[]);

/* Stub for execv() function.
 * Need to prevent executing files.
 */
int execve(const char *path, char *const argv[], char *const envp[]);

/* Stub for execvp() function.
 * Need to prevent executing files.
 */
int execvp(const char *file, char *const argv[]);

/* Stub for execvpe() function.
 * Need to prevent executing files.
 */
int execvpe(const char *file, char *const argv[], char *const envp[]);

/* Stub for execveat() function.
 * Need to prevent executing files.
 */
int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags);

/* Stub for fexecve() function.
 * Need to prevent executing files.
 */
int fexecve(int fd, char *const argv[], char *const envp[]);

/* Stub for execl() function.
 * Need to prevent executing files.
 */
int execl(const char *path, const char *arg, ...);

/* Stub for execlp() function.
 * Need to prevent executing files.
 */
int execlp(const char *file, const char *arg, ...);

/* Stub for execle() function.
 * Need to prevent executing files.
 */
int execle(const char *path, const char *arg, ...);

/* Stub for rename() function.
 * Necessary to prevent renaming files.
 */
int rename(const char *oldpath, const char *newpath);

/* Stub for renameat() function.
 * Necessary to prevent renaming and moving files.
 */
int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath);

/* Stub for renameat2() function.
 * Necessary to prevent renaming and moving files.
 */
int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags);

/* Stub for chown() function.
 * Necessary to prevent owner of files.
 */
int chown(const char *path, uid_t owner, gid_t group);

/* Stub for chownat() function.
 * Necessary to prevent owner of files.
 */
int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags);

/* Stub for chown() function.
 * Necessary to prevent rights of files.
 */
int chmod(const char *pathname, mode_t mode);

/* Stub for fchmodat() function.
 * Necessary to prevent rights of files.
 */
int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags);

/* Stub for system() function.
 * Necessary to prevent dangerous command execution.
 */
int system(const char *command);

/* Stub for syscall() function.
 * Necessary to prevent dangerous command execution.
 * Original implementation of syscall() function came from glibc.
 * It can occurs some ASAN/LSAN errors, but it's ok.
 */
long syscall(long number, ...);

/* Stub for chroot() function.
 */
int chroot(const char *path);

/* Stub for fork() function.
 * Necessary to prevent spawning of processes.
 */
pid_t fork(void);

/* Stub for popen() function.
 * Necessary to prevent spawning of processes.
 */
FILE *popen(const char *command, const char *type);

/* Stub for mkfifo() function.
 * Necessary to prevent spawning of processes.
 */
int mkfifo(const char *pathname, mode_t mode);

/* Stub for mkfifoat() function.
 * Necessary to prevent spawning of processes.
 */
int mkfifoat(int dirfd, const char *pathname, mode_t mode);

/* Stub for mknod() function.
 * Necessary to prevent spawning of processes.
 */
int mknod(const char *pathname, mode_t mode, dev_t dev);

/* Stub for mknodat() function.
 * Necessary to prevent spawning of processes.
 */
int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev);

/* Stub for sem_open() function.
 * Necessary to prevent spawning of processes.
 */
sem_t *sem_open(const char *name, int oflag, ...);

/* Stub for semctl() function.
 * Necessary to prevent spawning of processes.
 */
int semctl(int semid, int semnum, int cmd, ...);

/* Stub for semget() function.
 * Necessary to prevent spawning of processes.
 */
int semget(key_t key, int nsems, int semflg);

/* Stub for pipe() function.
 * Necessary to prevent spawning of processes.
 */
int pipe(int pipefd[2]);

/* Stub for dup() function.
 */
int dup(int oldfd);

/* Stub for dup2() function.
 */
int dup2(int oldfd, int newfd);

/* Stub for dup3() function.
 */
int dup3(int oldfd, int newfd, int flags);

/* Stub for setenv() function.
 */
int setenv(const char *name, const char *value, int overwrite);

/* Stub for unsetenv() function.
 */
int unsetenv(const char *name);

/* Stub for unshare() function.
 */
int unshare(int flags);

/* Stub for mount() function.
 */
int mount(const char *source, const char *target, const char *filesystemtype, unsigned long mountflags, const void *data);
