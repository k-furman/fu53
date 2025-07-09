/*
 * Library, that makes fuzzing safer.
 * This library makes standard C and POSIX functions much safer,
 * turning off deleting/moving/writing/executing files without patching
 * target binary.
 * To use this lib, you should compile it and link to target
 * binary when compiling, or use it via LD_PRELOAD/AFL_PRELOAD.
 *
 * Supported enviromental variables are:
 * - WITH_OPEN, which turnes on original open(), openat(), creat(),
 *   fopen(), fopen64(), fdopen(), freopen() funcs;
 * - WITH_REMOVE, which turnes on original remove(), rmdir(),
 *   unlink(), unlinkat() funcs;
 * - WITH_EXEC, which turnes on original execv(), execve(), execvp(),
 *   execvpe(), execveat(), fexecve(), execl(), execlp(),
 *   execle() funcs;
 * - WITH_RENAME, which turnes on original rename(), renameat(),
 *   renameat2() funcs;
 * - WITH_CHANGE, which turnes on original chown(), fchownat(),
 *   chmod(), fchmodat() funcs;
 * - WITH_SYSTEM, which turnes on original system(), syscall(),
 *   chroot() funcs;
 * - WITH_PARALLEL, which turnes on original fork(), popen(),
 *   mkfifo(), mkfifoat(), mknod(), mknodat(), sem_open(),
 *   semclt(), semget(), pipe() funcs;
 * - WITH_DUP, which turnes on original dup(), dup2(), dup3(), funcs.
 * - WITH_COVERAGE, which turnes on coverage collection support.
 */

#include "fu53.h"

int open(const char *pathname, int flags, ...)
{
	static open_type original_open = NULL;
	static int promoted = (sizeof(mode_t) < sizeof(uint32_t) - 1 ? 1 : 0);
	if (!original_open)
		original_open = (open_type)dlsym(RTLD_NEXT, "open");

	if (getenv("WITH_OPEN"))
	{
		if (flags & O_CREAT)
		{
			va_list arg;
			mode_t mode;
			va_start(arg, flags);
			if (promoted)
				mode = va_arg(arg, uint32_t);
			else
				mode = va_arg(arg, mode_t);
			va_end(arg);
			return (original_open(pathname, flags, mode));
		}
		return (original_open(pathname, flags));
	}

	if (getenv("WITH_COVERAGE"))
		if (strstr(pathname, ".gcda") || strstr(pathname, ".gcno"))
			return (original_open(pathname, flags));

	if (flags & (O_CREAT | O_APPEND | O_WRONLY | O_RDWR | O_SYNC))
		return (original_open("/dev/null", flags));

	return (original_open(pathname, flags));
}

int openat(int dirfd, const char *pathname, int flags, ...)
{
	static openat_type original_openat = NULL;
	static int promoted = (sizeof(mode_t) < sizeof(uint32_t) - 1 ? 1 : 0);
	if (!original_openat)
		original_openat = (openat_type)dlsym(RTLD_NEXT, "openat");

	if (getenv("WITH_OPEN"))
	{
		if (flags & O_CREAT)
		{
			va_list arg;
			mode_t mode;
			va_start(arg, flags);
			if (promoted)
				mode = va_arg(arg, uint32_t);
			else
				mode = va_arg(arg, mode_t);
			va_end(arg);
			return (original_openat(dirfd, pathname, flags, mode));
		}
		return (original_openat(dirfd, pathname, flags));
	}

	if (getenv("WITH_COVERAGE"))
		if (strstr(pathname, ".gcda") || strstr(pathname, ".gcno"))
			return (original_openat(dirfd, pathname, flags));

	if (flags & (O_CREAT | O_APPEND | O_WRONLY | O_RDWR | O_SYNC))
		return (original_openat(dirfd, "/dev/null", flags));

	return (original_openat(dirfd, pathname, flags));
}

int creat(const char *pathname, mode_t mode)
{
	if (!getenv("WITH_OPEN"))
		return -1;

	static creat_type original_creat = NULL;
	if (!original_creat)
		original_creat = (creat_type)dlsym(RTLD_NEXT, "creat");

	return (original_creat(pathname, mode));
}

void *dlopen(const char *filename, int flag)
{
	if (!getenv("WITH_OPEN"))
		return NULL;

	static dlopen_type original_dlopen = NULL;
	if (!original_dlopen)
		original_dlopen = (dlopen_type)dlsym(RTLD_NEXT, "dlopen");

	return (original_dlopen(filename, flag));
}

FILE *fopen(const char *pathname, const char *mode)
{
	static fopen_type original_fopen = NULL;
	if (!original_fopen)
		original_fopen = (fopen_type)dlsym(RTLD_NEXT, "fopen");

	if (getenv("WITH_OPEN"))
		return (original_fopen(pathname, mode));

	if (getenv("WITH_COVERAGE"))
		if (strstr(pathname, ".gcda") || strstr(pathname, ".gcno"))
			return (original_fopen(pathname, mode));

	if (strchr(mode, 'w') || strchr(mode, 'a' || strchr(mode, '+')))
		return (original_fopen("/dev/null", mode));

	return (original_fopen(pathname, mode));
}

FILE *fopen64(const char *pathname, const char *mode)
{
	static fopen_type original_fopen64 = NULL;
	if (!original_fopen64)
		original_fopen64 = (fopen_type)dlsym(RTLD_NEXT, "fopen64");

	if (getenv("WITH_OPEN"))
		return (original_fopen64(pathname, mode));

	if (getenv("WITH_COVERAGE"))
		if (strstr(pathname, ".gcda") || strstr(pathname, ".gcno"))
			return (fopen(pathname, mode));

	return (fopen(pathname, mode));
}

FILE *fdopen(int fildes, const char *mode)
{
	static fdopen_type original_fdopen = NULL;
	if (!original_fdopen)
		original_fdopen = (fdopen_type)dlsym(RTLD_NEXT, "fdopen");

	if (getenv("WITH_OPEN"))
		return (original_fdopen(fildes, mode));

	if (strchr(mode, 'w') || strchr(mode, 'a' || strchr(mode, '+')))
		return (fopen("/dev/null", mode));

	return (original_fdopen(fildes, mode));
}

FILE *freopen(const char *path, const char *mode, FILE *stream)
{
	static freopen_type original_freopen = NULL;
	if (!original_freopen)
		original_freopen = (freopen_type)dlsym(RTLD_NEXT, "freopen");

	if (getenv("WITH_OPEN"))
		return (original_freopen(path, mode, stream));

	if (strchr(mode, 'w') || strchr(mode, 'a' || strchr(mode, '+')))
		return (original_freopen("/dev/null", mode, stream));

	return (original_freopen(path, mode, stream));
}

int remove(const char *pathname)
{
	if (!getenv("WITH_REMOVE"))
		return -1;

	static remove_type original_remove = NULL;
	if (!original_remove)
		original_remove = (remove_type)dlsym(RTLD_NEXT, "remove");

	return (original_remove(pathname));
}

int rmdir(const char *pathname)
{
	if (!getenv("WITH_REMOVE"))
		return -1;

	static rmdir_type original_rmdir = NULL;
	if (!original_rmdir)
		original_rmdir = (rmdir_type)dlsym(RTLD_NEXT, "rmdir");

	return (original_rmdir(pathname));
}

int unlink(const char *fname)
{
	if (!getenv("WITH_REMOVE"))
		return -1;

	static unlink_type original_unlink = NULL;
	if (!original_unlink)
		original_unlink = (unlink_type)dlsym(RTLD_NEXT, "unlink");

	return (original_unlink(fname));
}

int unlinkat(int dirfd, const char *pathname, int flags)
{
	if (!getenv("WITH_REMOVE"))
		return -1;

	static unlinkat_type original_unlinkat = NULL;
	if (!original_unlinkat)
		original_unlinkat = (unlinkat_type)dlsym(RTLD_NEXT, "unlinkat");

	return (original_unlinkat(dirfd, pathname, flags));
}

int execv(const char *path, char *const argv[])
{
	if (!getenv("WITH_EXEC"))
		return -1;

	static execv_type original_execv = NULL;
	if (!original_execv)
		original_execv = (execv_type)dlsym(RTLD_NEXT, "execv");

	return (original_execv(path, argv));
}

int execve(const char *path, char *const argv[], char *const envp[])
{
	if (!getenv("WITH_EXEC"))
		return -1;

	static execve_type original_execve = NULL;
	if (!original_execve)
		original_execve = (execve_type)dlsym(RTLD_NEXT, "execve");

	return (original_execve(path, argv, envp));
}

int execvp(const char *file, char *const argv[])
{
	if (!getenv("WITH_EXEC"))
		return -1;

	static execvp_type original_execvp = NULL;
	if (!original_execvp)
		original_execvp = (execvp_type)dlsym(RTLD_NEXT, "execvp");

	return (original_execvp(file, argv));
}

int execvpe(const char *file, char *const argv[], char *const envp[])
{
	if (!getenv("WITH_EXEC"))
		return -1;

	static execvpe_type original_execvpe = NULL;
	if (!original_execvpe)
		original_execvpe = (execvpe_type)dlsym(RTLD_NEXT, "execvpe");

	return (original_execvpe(file, argv, envp));
}

int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags)
{
	if (!getenv("WITH_EXEC"))
		return -1;

	static execveat_type original_execveat = NULL;
	if (!original_execveat)
		original_execveat = (execveat_type)dlsym(RTLD_NEXT, "execveat");

	return (original_execveat(dirfd, pathname, argv, envp, flags));
}

int fexecve(int fd, char *const argv[], char *const envp[])
{
	if (!getenv("WITH_EXEC"))
		return -1;

	static fexecve_type original_fexecve = NULL;
	if (!original_fexecve)
		original_fexecve = (fexecve_type)dlsym(RTLD_NEXT, "fexecve");

	return (original_fexecve(fd, argv, envp));
}

int execl(const char *path, const char *arg, ...)
{
	if (!getenv("WITH_EXEC"))
		return -1;

	va_list ap;
	va_start(ap, arg);
	unsigned int argc = 1;
	for (; va_arg(ap, const char *); argc++)
		if (argc == INT_MAX)
		{
			va_end(ap);
			return -1;
		}
	va_end(ap);

	va_start(ap, arg);
	char *argv[argc + 1];
	argv[0] = (char *)arg;

	for (int i = 1; i <= argc; i++)
		argv[i] = va_arg(ap, char *);

	va_end(ap);

	return (execv(path, argv));
}

int execlp(const char *file, const char *arg, ...)
{
	if (!getenv("WITH_EXEC"))
		return -1;

	va_list ap;
	va_start(ap, arg);
	unsigned int argc = 1;
	for (; va_arg(ap, const char *); argc++)
		if (argc == INT_MAX)
		{
			va_end(ap);
			return -1;
		}
	va_end(ap);

	va_start(ap, arg);
	char **envp;
	char *argv[argc + 1];
	argv[0] = (char *)arg;

	for (int i = 1; i <= argc; i++)
		argv[i] = va_arg(ap, char *);

	envp = va_arg(ap, char **);
	va_end(ap);

	return (execvpe(file, argv, envp));
}

int execle(const char *path, const char *arg, ...)
{
	if (!getenv("WITH_EXEC"))
		return -1;

	va_list ap;
	va_start(ap, arg);
	unsigned int argc = 1;
	for (; va_arg(ap, const char *); argc++)
		if (argc == INT_MAX)
		{
			va_end(ap);
			return -1;
		}
	va_end(ap);

	va_start(ap, arg);
	char **envp;
	char *argv[argc + 1];
	argv[0] = (char *)arg;

	for (int i = 1; i <= argc; i++)
		argv[i] = va_arg(ap, char *);

	envp = va_arg(ap, char **);
	va_end(ap);

	return (execve(path, argv, envp));
}

int rename(const char *oldpath, const char *newpath)
{
	if (!getenv("WITH_RENAME"))
		return -1;

	static rename_type original_rename = NULL;
	if (!original_rename)
		original_rename = (rename_type)dlsym(RTLD_NEXT, "rename");

	return (original_rename(oldpath, newpath));
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
	if (!getenv("WITH_RENAME"))
		return -1;

	static renameat_type original_renameat = NULL;
	if (!original_renameat)
		original_renameat = (renameat_type)dlsym(RTLD_NEXT, "renameat");

	return (original_renameat(olddirfd, oldpath, newdirfd, newpath));
}

int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags)
{
	if (!getenv("WITH_RENAME"))
		return -1;

	static renameat2_type original_renameat2 = NULL;
	if (!original_renameat2)
		original_renameat2 = (renameat2_type)dlsym(RTLD_NEXT, "renameat2");

	return (original_renameat2(olddirfd, oldpath, newdirfd, newpath, flags));
}

int chown(const char *path, uid_t owner, gid_t group)
{
	if (!getenv("WITH_CHANGE"))
		return -1;

	static chown_type original_chown = NULL;
	if (!original_chown)
		original_chown = (chown_type)dlsym(RTLD_NEXT, "chown");

	return (original_chown(path, owner, group));
}

int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags)
{
	if (!getenv("WITH_CHANGE"))
		return -1;

	static fchownat_type original_fchownat = NULL;
	if (!original_fchownat)
		original_fchownat = (fchownat_type)dlsym(RTLD_NEXT, "fchownat");

	return (original_fchownat(dirfd, pathname, owner, group, flags));
}

int chmod(const char *pathname, mode_t mode)
{
	if (!getenv("WITH_CHANGE"))
		return -1;

	static chmod_type original_chmod = NULL;
	if (!original_chmod)
		original_chmod = (chmod_type)dlsym(RTLD_NEXT, "chmod");

	return (original_chmod(pathname, mode));
}

int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags)
{
	if (!getenv("WITH_CHANGE"))
		return -1;

	static fchmodat_type original_fchmodat = NULL;
	if (!original_fchmodat)
		original_fchmodat = (fchmodat_type)dlsym(RTLD_NEXT, "fchmodat");

	return (original_fchmodat(dirfd, pathname, mode, flags));
}

int system(const char *command)
{
	if (!getenv("WITH_SYSTEM"))
		return -1;

	static system_type original_system = NULL;
	if (!original_system)
		original_system = (system_type)dlsym(RTLD_NEXT, "system");

	return (original_system(command));
}

long syscall(long number, ...)
{
	if (!getenv("WITH_SYSTEM"))
		return -1;

	static syscall_type original_syscall = NULL;
	if (!original_syscall)
		original_syscall = (syscall_type)dlsym(RTLD_NEXT, "syscall");

	va_list args;

	va_start(args, number);
	long int a0 = va_arg(args, long int);
	long int a1 = va_arg(args, long int);
	long int a2 = va_arg(args, long int);
	long int a3 = va_arg(args, long int);
	long int a4 = va_arg(args, long int);
	long int a5 = va_arg(args, long int);
	va_end(args);

	return (original_syscall(number, a0, a1, a2, a3, a4, a5));
}

int chroot(const char *path)
{
	if (!getenv("WITH_SYSTEM"))
		return -1;

	static chroot_type original_chroot = NULL;
	if (!original_chroot)
		original_chroot = (chroot_type)dlsym(RTLD_NEXT, "chroot");

	return (original_chroot(path));
}

pid_t fork(void)
{
	if (!getenv("WITH_PARALLEL"))
		return -1;

	static fork_type original_fork = NULL;
	if (!original_fork)
		original_fork = (fork_type)dlsym(RTLD_NEXT, "fork");

	return (original_fork());
}

FILE *popen(const char *command, const char *type)
{
	if (!getenv("WITH_PARALLEL"))
		return NULL;

	static popen_type original_popen = NULL;
	if (!original_popen)
		original_popen = (popen_type)dlsym(RTLD_NEXT, "popen");

	return (original_popen(command, type));
}

int mkfifo(const char *pathname, mode_t mode)
{
	if (!getenv("WITH_PARALLEL"))
		return -1;

	static mkfifo_type original_mkfifo = NULL;
	if (!original_mkfifo)
		original_mkfifo = (mkfifo_type)dlsym(RTLD_NEXT, "mkfifo");

	return (original_mkfifo(pathname, mode));
}

int mkfifoat(int dirfd, const char *pathname, mode_t mode)
{
	if (!getenv("WITH_PARALLEL"))
		return -1;

	static mkfifoat_type original_mkfifoat = NULL;
	if (!original_mkfifoat)
		original_mkfifoat = (mkfifoat_type)dlsym(RTLD_NEXT, "mkfifoat");

	return (original_mkfifoat(dirfd, pathname, mode));
}

int mknod(const char *pathname, mode_t mode, dev_t dev)
{
	if (!getenv("WITH_PARALLEL"))
		return -1;

	static mknod_type original_mknod = NULL;
	if (!original_mknod)
		original_mknod = (mknod_type)dlsym(RTLD_NEXT, "mknod");

	return (original_mknod(pathname, mode, dev));
}

int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev)
{
	if (!getenv("WITH_PARALLEL"))
		return -1;

	static mknodat_type original_mknodat = NULL;
	if (!original_mknodat)
		original_mknodat = (mknodat_type)dlsym(RTLD_NEXT, "mknodat");

	return (original_mknodat(dirfd, pathname, mode, dev));
}

sem_t *sem_open(const char *name, int oflag, ...)
{
	if (!getenv("WITH_PARALLEL"))
		return SEM_FAILED;

	static sem_open_type original_sem_open = NULL;
	if (!original_sem_open)
		original_sem_open = (sem_open_type)dlsym(RTLD_NEXT, "sem_open");

	if (oflag & O_CREAT)
	{
		va_list args;
		mode_t mode;
		unsigned int value;

		va_start(args, oflag);
		mode = va_arg(args, mode_t);
		value = va_arg(args, unsigned int);
		va_end(args);
		return (original_sem_open(name, oflag, mode, value));
	}

	return (original_sem_open(name, oflag));
}

int semctl(int semid, int semnum, int cmd, ...)
{
	if (!getenv("WITH_PARALLEL"))
		return -1;

	static semctl_type original_semctl = NULL;
	if (!original_semctl)
		original_semctl = (semctl_type)dlsym(RTLD_NEXT, "semctl");

	union semun
	{
		int val;			   /* Value for SETVAL */
		struct semid_ds *buf;  /* Buffer for IPC_STAT, IPC_SET */
		unsigned short *array; /* Array for GETALL, SETALL */
		struct seminfo *__buf; /* Buffer for IPC_INFO */
	};
	va_list args;
	union semun arg = {0};
	switch (cmd)
	{
	case SETVAL: /* arg.val */
	case GETALL: /* arg.array */
	case SETALL:
	case IPC_STAT: /* arg.buf */
	case IPC_SET:
	case SEM_STAT:
	case SEM_STAT_ANY:
	case IPC_INFO: /* arg.__buf */
	case SEM_INFO:
		va_start(args, cmd);
		arg = va_arg(args, union semun);
		va_end(args);
		return (original_semctl(semid, semnum, cmd, arg));
	}

	return (original_semctl(semid, semnum, cmd));
}

int semget(key_t key, int nsems, int semflg)
{
	if (!getenv("WITH_PARALLEL"))
		return -1;

	static semget_type original_semget = NULL;
	if (!original_semget)
		original_semget = (semget_type)dlsym(RTLD_NEXT, "semget");

	return (original_semget(key, nsems, semflg));
}

int pipe(int pipefd[2])
{
	if (!getenv("WITH_PARALLEL"))
		return -1;

	static pipe_type original_pipe = NULL;
	if (!original_pipe)
		original_pipe = (pipe_type)dlsym(RTLD_NEXT, "pipe");

	return (original_pipe(pipefd));
}

int dup(int oldfd)
{
	if (!getenv("WITH_DUP"))
		return -1;

	static dup_type original_dup = NULL;
	if (!original_dup)
		original_dup = (dup_type)dlsym(RTLD_NEXT, "dup");

	return (original_dup(oldfd));
}

int dup2(int oldfd, int newfd)
{
	if (!getenv("WITH_DUP"))
		return -1;

	static dup2_type original_dup2 = NULL;
	if (!original_dup2)
		original_dup2 = (dup2_type)dlsym(RTLD_NEXT, "dup2");

	return (original_dup2(oldfd, newfd));
}

int dup3(int oldfd, int newfd, int flags)
{
	if (!getenv("WITH_DUP"))
		return -1;

	static dup3_type original_dup3 = NULL;
	if (!original_dup3)
		original_dup3 = (dup3_type)dlsym(RTLD_NEXT, "dup3");

	return (original_dup3(oldfd, newfd, flags));
}
