/*
 * Library, that makes fuzzing safer.
 * This library makes standard C and POSIX functions much safer,
 * turning off deleting/moving/writing/executing files without patching
 * target binary.
 * To use this lib, you should compile it and link to target
 * binary when compiling, or use it via LD_PRELOAD/AFL_PRELOAD.
 *
 * Supported enviromental variables are:
 * - WITH_OPEN=N, which enables original open(), open64(), openat(),
 *   creat(), fopen(), fopen64(), fdopen(), freopen() funcs. N value
 *   determines how many times original functions can call during one
 *   execution. If any character/string as N value is specified,
 *   or 0 pass as N value, original functions will use;
 * - WITH_REMOVE, which enables original remove(), rmdir(),
 *   unlink(), unlinkat() funcs;
 * - WITH_EXEC, which enables original execv(), execve(), execvp(),
 *   execvpe(), execveat(), fexecve(), execl(), execlp(),
 *   execle() funcs;
 * - WITH_RENAME, which enables original rename(), renameat(),
 *   renameat2() funcs;
 * - WITH_CHANGE, which enables original chown(), fchownat(),
 *   chmod(), fchmodat() funcs;
 * - WITH_SYSTEM, which enables original system(), syscall(),
 *   chroot() funcs;
 * - WITH_FORK=N, which enables original fork(). N value determines
 *   how many times original fork() can call during one execution.
 *   If any character/string as N value is specified,
 *   or 0 pass as N value, original function will use;
 * - WITH_PARALLEL=N, which enables original popen(), mkfifo(),
 *   mkfifoat(), mknod(), mknodat(), sem_open(), semclt(), semget(),
 *   pipe() funcs. If any character/string as N value is specified,
 *   or 0 pass as N value, original functions will use;
 * - WITH_DUP, which enables original dup(), dup2(), dup3(), funcs.
 * - WITH_ENV, which enables original setenv(), unsetenv() funcs;
 * - WITH_COVERAGE, which enables coverage collection support.
 * 
 * - NO_OPEN, which throw assert(0), on original open(), open64(),
 *   openat(), creat(), fopen(), fopen64(), fdopen(), freopen() funcs;
 * - NO_EXEC, which throw assert(0) on original execv(), execve(), 
 *   execvp(), execvpe(), execveat(), fexecve(), execl(), execlp(),
 *   execle() funcs;
 */

#include "fu53.h"

int open(const char *pathname, int flags, ...)
{
	static open_type original_open = NULL;
	static int promoted = (sizeof(mode_t) < sizeof(uint32_t) - 1 ? 1 : 0);
	static long unsigned num = 0;
	static char init = 0;
	static int calls = 0;
	char *value = NULL;
	if (!init)
	{
		value = getenv("WITH_OPEN");
		if (value)
		{
			num = strtoul(value, NULL, 10);
			init = 1;
		}

		value = getenv("NO_OPEN");
		if (value)
			init = 2;
		else 
			init = 3;
	}

	if (init == 2)
		assert(0);

	if (!original_open)
		original_open = (open_type)dlsym(RTLD_NEXT, "open");

	if (init == 1)
	{
		if (calls < num || num == 0)
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
				calls++;
				return (original_open(pathname, flags, mode));
			}
			calls++;
			return (original_open(pathname, flags));
		}
	}

	if (getenv("WITH_COVERAGE"))
		if (strstr(pathname, ".gcda") || strstr(pathname, ".gcno") ||
			strstr(pathname, ".profraw") || strstr(pathname, ".profdata"))
			return (original_open(pathname, flags));

	if (flags & (O_CREAT | O_APPEND | O_WRONLY | O_RDWR | O_SYNC))
		return (original_open("/dev/null", flags));

	return (original_open(pathname, flags));
}

int open64(const char *pathname, int flags, ...)
{
	static open64_type original_open64 = NULL;
	static int promoted = (sizeof(mode_t) < sizeof(uint32_t) - 1 ? 1 : 0);
	static long unsigned num = 0;
	static char init = 0;
	static int calls = 0;
	char *value = NULL;
	if (!init)
	{
		value = getenv("WITH_OPEN");
		if (value)
		{
			num = strtoul(value, NULL, 10);
			init = 1;
		}

		value = getenv("NO_OPEN");
		if (value)
			init = 2;
		else 
			init = 3;
	}

	if (init == 2)
		assert(0);

	if (!original_open64)
		original_open64 = (open64_type)dlsym(RTLD_NEXT, "open64");

	if (init == 1)
	{
		if (calls < num || num == 0)
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
				calls++;
				return (original_open64(pathname, flags, mode));
			}
			calls++;
			return (original_open64(pathname, flags));
		}
	}

	if (getenv("WITH_COVERAGE"))
		if (strstr(pathname, ".gcda") || strstr(pathname, ".gcno") ||
			strstr(pathname, ".profraw") || strstr(pathname, ".profdata"))
			return (original_open64(pathname, flags));

	if (flags & (O_CREAT | O_APPEND | O_WRONLY | O_RDWR | O_SYNC))
		return (original_open64("/dev/null", flags));

	return (original_open64(pathname, flags));
}

int openat(int dirfd, const char *pathname, int flags, ...)
{
	static openat_type original_openat = NULL;
	static int promoted = (sizeof(mode_t) < sizeof(uint32_t) - 1 ? 1 : 0);
	static long unsigned num = 0;
	static char init = 0;
	static int calls = 0;
	char *value = NULL;
	if (!init)
	{
		value = getenv("WITH_OPEN");
		if (value)
		{
			num = strtoul(value, NULL, 10);
			init = 1;
		}

		value = getenv("NO_OPEN");
		if (value)
			init = 2;
		else 
			init = 3;
	}

	if (init == 2)
		assert(0);

	if (!original_openat)
		original_openat = (openat_type)dlsym(RTLD_NEXT, "openat");

	if (init == 1)
	{
		if (calls < num || num == 0)
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
				calls++;
				return (original_openat(dirfd, pathname, flags, mode));
			}
			calls++;
			return (original_openat(dirfd, pathname, flags));
		}
	}

	if (getenv("WITH_COVERAGE"))
		if (strstr(pathname, ".gcda") || strstr(pathname, ".gcno") ||
			strstr(pathname, ".profraw") || strstr(pathname, ".profdata"))
			return (original_openat(dirfd, pathname, flags));

	if (flags & (O_CREAT | O_APPEND | O_WRONLY | O_RDWR | O_SYNC))
		return (original_openat(dirfd, "/dev/null", flags));

	return (original_openat(dirfd, pathname, flags));
}

int creat(const char *pathname, mode_t mode)
{
	static creat_type original_creat = NULL;
	static char init = 0;
	static long unsigned num = 0;
	static int calls = 0;
	char *value = NULL;
	if (!init)
	{
		value = getenv("WITH_OPEN");
		if (value)
		{
			num = strtoul(value, NULL, 10);
			init = 1;
		}

		value = getenv("NO_OPEN");
		if (value)
			init = 2;
		else 
			init = 3;
	}

	if (init == 1)
		return -1;
	else if (init == 2)
		assert(0);

	if (!original_creat)
		original_creat = (creat_type)dlsym(RTLD_NEXT, "creat");

	if (calls < num || num == 0)
	{
		calls++;
		return (original_creat(pathname, mode));
	}

	return -1;
}

void *dlopen(const char *filename, int flag)
{
	static dlopen_type original_dlopen = NULL;
	static char init = 0;
	static long unsigned num = 0;
	static int calls = 0;
	char *value = NULL;
	if (!init)
	{
		value = getenv("WITH_OPEN");
		if (value)
		{
			num = strtoul(value, NULL, 10);
			init = 1;
		}

		value = getenv("NO_OPEN");
		if (value)
			init = 2;
		else 
			init = 3;
	}

	if (init == 1)
		return NULL;
	else if (init == 2)
		assert(0);

	if (!original_dlopen)
		original_dlopen = (dlopen_type)dlsym(RTLD_NEXT, "dlopen");

	if (calls < num || num == 0)
	{
		calls++;
		return (original_dlopen(filename, flag));
	}

	return NULL;
}

FILE *fopen(const char *pathname, const char *mode)
{
	static fopen_type original_fopen = NULL;
	static long unsigned num = 0;
	static char init = 0;
	static int calls = 0;
	char *value = NULL;
	if (!init)
	{
		value = getenv("WITH_OPEN");
		if (value)
		{
			num = strtoul(value, NULL, 10);
			init = 1;
		}

		value = getenv("NO_OPEN");
		if (value)
			init = 2;
		else 
			init = 3;
	}

	if (init == 2)
		assert(0);

	if (!original_fopen)
		original_fopen = (fopen_type)dlsym(RTLD_NEXT, "fopen");

	if (init == 1)
	{
		if (calls < num || num == 0)
		{
			calls++;
			return (original_fopen(pathname, mode));
		}
	}

	if (getenv("WITH_COVERAGE"))
		if (strstr(pathname, ".gcda") || strstr(pathname, ".gcno") ||
			strstr(pathname, ".profraw") || strstr(pathname, ".profdata"))
			return (original_fopen(pathname, mode));

	if (strchr(mode, 'w') || strchr(mode, 'a' || strchr(mode, '+')))
		return (original_fopen("/dev/null", mode));

	return (original_fopen(pathname, mode));
}

FILE *fopen64(const char *pathname, const char *mode)
{
	static fopen64_type original_fopen64 = NULL;
	static long unsigned num = 0;
	static char init = 0;
	static int calls = 0;
	char *value = NULL;
	if (!init)
	{
		value = getenv("WITH_OPEN");
		if (value)
		{
			num = strtoul(value, NULL, 10);
			init = 1;
		}

		value = getenv("NO_OPEN");
		if (value)
			init = 2;
		else 
			init = 3;
	}

	if (init == 2)
		assert(0);

	if (!original_fopen64)
		original_fopen64 = (fopen_type)dlsym(RTLD_NEXT, "fopen64");

	if (init == 1)
	{
		if (calls < num || num == 0)
		{
			calls++;
			return (original_fopen64(pathname, mode));
		}
	}

	if (getenv("WITH_COVERAGE"))
		if (strstr(pathname, ".gcda") || strstr(pathname, ".gcno") ||
			strstr(pathname, ".profraw") || strstr(pathname, ".profdata"))
			return (original_fopen64(pathname, mode));

	if (strchr(mode, 'w') || strchr(mode, 'a' || strchr(mode, '+')))
		return (original_fopen64("/dev/null", mode));

	return (original_fopen64(pathname, mode));
}

FILE *fdopen(int fildes, const char *mode)
{
	static fdopen_type original_fdopen = NULL;
	static long unsigned num = 0;
	static char init = 0;
	static int calls = 0;
	char *value = NULL;
	if (!init)
	{
		value = getenv("WITH_OPEN");
		if (value)
		{
			num = strtoul(value, NULL, 10);
			init = 1;
		}

		value = getenv("NO_OPEN");
		if (value)
			init = 2;
		else 
			init = 3;
	}

	if (init == 2)
		assert(0);

	if (!original_fdopen)
		original_fdopen = (fdopen_type)dlsym(RTLD_NEXT, "fdopen");

	if (init == 1)
	{
		if (calls < num || num == 0)
		{
			calls++;
			return (original_fdopen(fildes, mode));
		}
	}

	if (strchr(mode, 'w') || strchr(mode, 'a' || strchr(mode, '+')))
		return (fopen("/dev/null", mode));

	return (original_fdopen(fildes, mode));
}

FILE *freopen(const char *path, const char *mode, FILE *stream)
{
	static freopen_type original_freopen = NULL;
	static long unsigned num = 0;
	static char init = 0;
	static int calls = 0;
	char *value = NULL;
	if (!init)
	{
		value = getenv("WITH_OPEN");
		if (value)
		{
			num = strtoul(value, NULL, 10);
			init = 1;
		}

		value = getenv("NO_OPEN");
		if (value)
			init = 2;
		else 
			init = 3;
	}

	if (init == 2)
		assert(0);

	if (!original_freopen)
		original_freopen = (freopen_type)dlsym(RTLD_NEXT, "freopen");

	if (init == 1)
	{
		if (calls < num || num == 0)
		{
			calls++;
			return (original_freopen(path, mode, stream));
		}
	}

	if (strchr(mode, 'w') || strchr(mode, 'a' || strchr(mode, '+')))
		return (original_freopen("/dev/null", mode, stream));

	return (original_freopen(path, mode, stream));
}

int remove(const char *pathname)
{
	static char *value;
	static char init = 0;
	if (!init)
	{
		value = getenv("WITH_REMOVE");
		init = 1;
	}

	if (!value)
		return -1;

	static remove_type original_remove = NULL;
	if (!original_remove)
		original_remove = (remove_type)dlsym(RTLD_NEXT, "remove");

	return (original_remove(pathname));
}

int rmdir(const char *pathname)
{
	static char *value;
	static char init = 0;
	if (!init)
	{
		value = getenv("WITH_REMOVE");
		init = 1;
	}

	if (!value)
		return -1;

	static rmdir_type original_rmdir = NULL;
	if (!original_rmdir)
		original_rmdir = (rmdir_type)dlsym(RTLD_NEXT, "rmdir");

	return (original_rmdir(pathname));
}

int unlink(const char *fname)
{
	static char *value;
	static char init = 0;
	if (!init)
	{
		value = getenv("WITH_REMOVE");
		init = 1;
	}

	if (!value)
		return -1;

	static unlink_type original_unlink = NULL;
	if (!original_unlink)
		original_unlink = (unlink_type)dlsym(RTLD_NEXT, "unlink");

	return (original_unlink(fname));
}

int unlinkat(int dirfd, const char *pathname, int flags)
{
	static char *value;
	static char init = 0;
	if (!init)
	{
		value = getenv("WITH_REMOVE");
		init = 1;
	}

	if (!value)
		return -1;

	static unlinkat_type original_unlinkat = NULL;
	if (!original_unlinkat)
		original_unlinkat = (unlinkat_type)dlsym(RTLD_NEXT, "unlinkat");

	return (original_unlinkat(dirfd, pathname, flags));
}

int execv(const char *path, char *const argv[])
{
	static char *value;
	static char init = 0;
	if (!init)
	{
		value = getenv("WITH_EXEC");
		init = 1;
	}

	if (!value)
		return -1;

	static execv_type original_execv = NULL;
	if (!original_execv)
		original_execv = (execv_type)dlsym(RTLD_NEXT, "execv");

	return (original_execv(path, argv));
}

int execve(const char *path, char *const argv[], char *const envp[])
{
	static char init = 0;
	char *value = NULL;
	if (!init)
	{
		value = getenv("WITH_EXEC");
		if (value)
			init = 1;
		value = getenv("NO_EXEC");
		if (value)	
			init = 2;
		else
			init = 3;
	}

	if (init == 2)
		assert(0);
	else if (init == 3)
		return -1;

	static execve_type original_execve = NULL;
	if (!original_execve)
		original_execve = (execve_type)dlsym(RTLD_NEXT, "execve");

	return (original_execve(path, argv, envp));
}

int execvp(const char *file, char *const argv[])
{
	static char init = 0;
	char *value = NULL;
	if (!init)
	{
		value = getenv("WITH_EXEC");
		if (value)
			init = 1;
		value = getenv("NO_EXEC");
		if (value)	
			init = 2;
		else
			init = 3;
	}

	if (init == 2)
		assert(0);
	else if (init == 3)
		return -1;

	static execvp_type original_execvp = NULL;
	if (!original_execvp)
		original_execvp = (execvp_type)dlsym(RTLD_NEXT, "execvp");

	return (original_execvp(file, argv));
}

int execvpe(const char *file, char *const argv[], char *const envp[])
{
	static char init = 0;
	char *value = NULL;
	if (!init)
	{
		value = getenv("WITH_EXEC");
		if (value)
			init = 1;
		value = getenv("NO_EXEC");
		if (value)	
			init = 2;
		else
			init = 3;
	}

	if (init == 2)
		assert(0);
	else if (init == 3)
		return -1;

	static execvpe_type original_execvpe = NULL;
	if (!original_execvpe)
		original_execvpe = (execvpe_type)dlsym(RTLD_NEXT, "execvpe");

	return (original_execvpe(file, argv, envp));
}

int execveat(int dirfd, const char *pathname, char *const argv[], char *const envp[], int flags)
{
	static char init = 0;
	char *value = NULL;
	if (!init)
	{
		value = getenv("WITH_EXEC");
		if (value)
			init = 1;
		value = getenv("NO_EXEC");
		if (value)	
			init = 2;
		else
			init = 3;
	}

	if (init == 2)
		assert(0);
	else if (init == 3)
		return -1;

	static execveat_type original_execveat = NULL;
	if (!original_execveat)
		original_execveat = (execveat_type)dlsym(RTLD_NEXT, "execveat");

	return (original_execveat(dirfd, pathname, argv, envp, flags));
}

int fexecve(int fd, char *const argv[], char *const envp[])
{
	static char init = 0;
	char *value = NULL;
	if (!init)
	{
		value = getenv("WITH_EXEC");
		if (value)
			init = 1;
		value = getenv("NO_EXEC");
		if (value)	
			init = 2;
		else
			init = 3;
	}

	if (init == 2)
		assert(0);
	else if (init == 3)
		return -1;

	static fexecve_type original_fexecve = NULL;
	if (!original_fexecve)
		original_fexecve = (fexecve_type)dlsym(RTLD_NEXT, "fexecve");

	return (original_fexecve(fd, argv, envp));
}

int execl(const char *path, const char *arg, ...)
{
	static char init = 0;
	char *value = NULL;
	if (!init)
	{
		value = getenv("WITH_EXEC");
		if (value)
			init = 1;
		value = getenv("NO_EXEC");
		if (value)	
			init = 2;
		else
			init = 3;
	}

	if (init == 2)
		assert(0);
	else if (init == 3)
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
	static char init = 0;
	char *value = NULL;
	if (!init)
	{
		value = getenv("WITH_EXEC");
		if (value)
			init = 1;
		value = getenv("NO_EXEC");
		if (value)	
			init = 2;
		else
			init = 3;
	}

	if (init == 2)
		assert(0);
	else if (init == 3)
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
	static char init = 0;
	char *value = NULL;
	if (!init)
	{
		value = getenv("WITH_EXEC");
		if (value)
			init = 1;
		value = getenv("NO_EXEC");
		if (value)	
			init = 2;
		else
			init = 3;
	}

	if (init == 2)
		assert(0);
	else if (init == 3)
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
	static char *value;
	static char init = 0;
	if (!init)
	{
		value = getenv("WITH_RENAME");
		init = 1;
	}

	if (!value)
		return -1;

	static rename_type original_rename = NULL;
	if (!original_rename)
		original_rename = (rename_type)dlsym(RTLD_NEXT, "rename");

	return (original_rename(oldpath, newpath));
}

int renameat(int olddirfd, const char *oldpath, int newdirfd, const char *newpath)
{
	static char *value;
	static char init = 0;
	if (!init)
	{
		value = getenv("WITH_RENAME");
		init = 1;
	}

	if (!value)
		return -1;

	static renameat_type original_renameat = NULL;
	if (!original_renameat)
		original_renameat = (renameat_type)dlsym(RTLD_NEXT, "renameat");

	return (original_renameat(olddirfd, oldpath, newdirfd, newpath));
}

int renameat2(int olddirfd, const char *oldpath, int newdirfd, const char *newpath, unsigned int flags)
{
	static char *value;
	static char init = 0;
	if (!init)
	{
		value = getenv("WITH_RENAME");
		init = 1;
	}

	if (!value)
		return -1;

	static renameat2_type original_renameat2 = NULL;
	if (!original_renameat2)
		original_renameat2 = (renameat2_type)dlsym(RTLD_NEXT, "renameat2");

	return (original_renameat2(olddirfd, oldpath, newdirfd, newpath, flags));
}

int chown(const char *path, uid_t owner, gid_t group)
{
	static char *value;
	static char init = 0;
	if (!init)
	{
		value = getenv("WITH_CHANGE");
		init = 1;
	}

	if (!value)
		return -1;

	static chown_type original_chown = NULL;
	if (!original_chown)
		original_chown = (chown_type)dlsym(RTLD_NEXT, "chown");

	return (original_chown(path, owner, group));
}

int fchownat(int dirfd, const char *pathname, uid_t owner, gid_t group, int flags)
{
	static char *value;
	static char init = 0;
	if (!init)
	{
		value = getenv("WITH_CHANGE");
		init = 1;
	}

	if (!value)
		return -1;

	static fchownat_type original_fchownat = NULL;
	if (!original_fchownat)
		original_fchownat = (fchownat_type)dlsym(RTLD_NEXT, "fchownat");

	return (original_fchownat(dirfd, pathname, owner, group, flags));
}

int chmod(const char *pathname, mode_t mode)
{
	static char *value;
	static char init = 0;
	if (!init)
	{
		value = getenv("WITH_CHANGE");
		init = 1;
	}

	if (!value)
		return -1;

	static chmod_type original_chmod = NULL;
	if (!original_chmod)
		original_chmod = (chmod_type)dlsym(RTLD_NEXT, "chmod");

	return (original_chmod(pathname, mode));
}

int fchmodat(int dirfd, const char *pathname, mode_t mode, int flags)
{
	static char *value;
	static char init = 0;
	if (!init)
	{
		value = getenv("WITH_CHANGE");
		init = 1;
	}

	if (!value)
		return -1;

	static fchmodat_type original_fchmodat = NULL;
	if (!original_fchmodat)
		original_fchmodat = (fchmodat_type)dlsym(RTLD_NEXT, "fchmodat");

	return (original_fchmodat(dirfd, pathname, mode, flags));
}

int system(const char *command)
{
	static char *value;
	static char init = 0;
	if (!init)
	{
		value = getenv("WITH_SYSTEM");
		init = 1;
	}

	if (!value)
		return -1;

	static system_type original_system = NULL;
	if (!original_system)
		original_system = (system_type)dlsym(RTLD_NEXT, "system");

	return (original_system(command));
}

long syscall(long number, ...)
{
	static char *value;
	static char init = 0;
	if (!init)
	{
		value = getenv("WITH_SYSTEM");
		init = 1;
	}

	if (!value)
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
	static char *value;
	static char init = 0;
	if (!init)
	{
		value = getenv("WITH_SYSTEM");
		init = 1;
	}

	if (!value)
		return -1;

	static chroot_type original_chroot = NULL;
	if (!original_chroot)
		original_chroot = (chroot_type)dlsym(RTLD_NEXT, "chroot");

	return (original_chroot(path));
}

pid_t fork(void)
{
	static fork_type original_fork = NULL;
	static char *value;
	static char init = 0;
	static long unsigned num = 0;
	static int calls = 0;
	if (!init)
	{
		value = getenv("WITH_FORK");
		if (value)
			num = strtoul(value, NULL, 10);
		init = 1;
	}

	if (value)
	{
		if (!original_fork)
			original_fork = (fork_type)dlsym(RTLD_NEXT, "fork");

		if (calls < num || num == 0)
		{
			calls++;
			return (original_fork());
		}
	}

	return -1;
}

FILE *popen(const char *command, const char *type)
{
	static popen_type original_popen = NULL;
	static char *value;
	static char init = 0;
	static long unsigned num = 0;
	static int calls = 0;
	if (!init)
	{
		value = getenv("WITH_PARALLEL");
		if (value)
			num = strtoul(value, NULL, 10);
		init = 1;
	}

	if (value)
	{
		if (!original_popen)
			original_popen = (popen_type)dlsym(RTLD_NEXT, "popen");

		if (calls < num || num == 0)
		{
			calls++;
			return (original_popen(command, type));
		}
	}

	return NULL;
}

int mkfifo(const char *pathname, mode_t mode)
{
	static mkfifo_type original_mkfifo = NULL;
	static char *value;
	static char init = 0;
	static long unsigned num = 0;
	static int calls = 0;
	if (!init)
	{
		value = getenv("WITH_PARALLEL");
		if (value)
			num = strtoul(value, NULL, 10);
		init = 1;
	}

	if (value)
	{
		if (!original_mkfifo)
			original_mkfifo = (mkfifo_type)dlsym(RTLD_NEXT, "mkfifo");

		if (calls < num || num == 0)
		{
			calls++;
			return (original_mkfifo(pathname, mode));
		}
	}

	return -1;
}

int mkfifoat(int dirfd, const char *pathname, mode_t mode)
{
	static mkfifoat_type original_mkfifoat = NULL;
	static char *value;
	static char init = 0;
	static long unsigned num = 0;
	static int calls = 0;
	if (!init)
	{
		value = getenv("WITH_PARALLEL");
		if (value)
			num = strtoul(value, NULL, 10);
		init = 1;
	}

	if (value)
	{
		if (!original_mkfifoat)
			original_mkfifoat = (mkfifoat_type)dlsym(RTLD_NEXT, "mkfifoat");

		if (calls < num || num == 0)
		{
			calls++;
			return (original_mkfifoat(dirfd, pathname, mode));
		}
	}

	return -1;
}

int mknod(const char *pathname, mode_t mode, dev_t dev)
{
	static mknod_type original_mknod = NULL;
	static char *value;
	static char init = 0;
	static long unsigned num = 0;
	static int calls = 0;
	if (!init)
	{
		value = getenv("WITH_PARALLEL");
		if (value)
			num = strtoul(value, NULL, 10);
		init = 1;
	}

	if (value)
	{
		if (!original_mknod)
			original_mknod = (mknod_type)dlsym(RTLD_NEXT, "mknod");
		
		if (calls < num || num == 0)
		{
			calls++;
			return (original_mknod(pathname, mode, dev));
		}
	}

	return -1;
}

int mknodat(int dirfd, const char *pathname, mode_t mode, dev_t dev)
{
	static mknodat_type original_mknodat = NULL;
	static char *value;
	static char init = 0;
	static long unsigned num = 0;
	static int calls = 0;
	if (!init)
	{
		value = getenv("WITH_PARALLEL");
		if (value)
			num = strtoul(value, NULL, 10);
		init = 1;
	}

	if (value)
	{
		if (!original_mknodat)
			original_mknodat = (mknodat_type)dlsym(RTLD_NEXT, "mknodat");

		if (calls < num || num == 0)
		{
			calls++;
			return (original_mknodat(dirfd, pathname, mode, dev));
		}
	}

	return -1;
}

sem_t *sem_open(const char *name, int oflag, ...)
{
	static sem_open_type original_sem_open = NULL;
	static char *value;
	static char init = 0;
	static long unsigned num = 0;
	static int calls = 0;
	if (!init)
	{
		value = getenv("WITH_PARALLEL");
		if (value)
			num = strtoul(value, NULL, 10);
		init = 1;
	}

	if (value)
	{
		if (calls < num || num == 0)
		{
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
				calls++;
				return (original_sem_open(name, oflag, mode, value));
			}

			calls++;
			return (original_sem_open(name, oflag));
		}
	}

	return SEM_FAILED;
}

int semctl(int semid, int semnum, int cmd, ...)
{
	static semctl_type original_semctl = NULL;
	static char *value;
	static char init = 0;
	static long unsigned num = 0;
	static int calls = 0;
	if (!init)
	{
		value = getenv("WITH_PARALLEL");
		if (value)
			num = strtoul(value, NULL, 10);
		init = 1;
	}

	if (value)
	{
		if (!original_semctl)
			original_semctl = (semctl_type)dlsym(RTLD_NEXT, "semctl");

		if (calls < num || num == 0)
		{
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
				calls++;
				return (original_semctl(semid, semnum, cmd, arg));
			}

			calls++;
			return (original_semctl(semid, semnum, cmd));
		}
	}

	return -1;
}

int semget(key_t key, int nsems, int semflg)
{
	static semget_type original_semget = NULL;
	static char *value;
	static char init = 0;
	static long unsigned num = 0;
	static int calls = 0;
	if (!init)
	{
		value = getenv("WITH_PARALLEL");
		if (value)
			num = strtoul(value, NULL, 10);
		init = 1;
	}

	if (value)
	{
		if (!original_semget)
			original_semget = (semget_type)dlsym(RTLD_NEXT, "semget");

		if (calls < num || num == 0)
		{
			calls++;
			return (original_semget(key, nsems, semflg));
		}
	}

	return -1;
}

int pipe(int pipefd[2])
{
	static pipe_type original_pipe = NULL;
	static char *value;
	static char init = 0;
	static long unsigned num = 0;
	static int calls = 0;
	if (!init)
	{
		value = getenv("WITH_PARALLEL");
		if (value)
			num = strtoul(value, NULL, 10);
		init = 1;
	}

	if (value)
	{
		if (!original_pipe)
			original_pipe = (pipe_type)dlsym(RTLD_NEXT, "pipe");
		
		if (calls < num || num == 0)
		{
			calls++;
			return (original_pipe(pipefd));
		}
	}

	return -1;
}

int dup(int oldfd)
{
	static char *value;
	static char init = 0;
	if (!init)
	{
		value = getenv("WITH_DUP");
		init = 1;
	}

	if (!value)
		return -1;

	static dup_type original_dup = NULL;
	if (!original_dup)
		original_dup = (dup_type)dlsym(RTLD_NEXT, "dup");

	return (original_dup(oldfd));
}

int dup2(int oldfd, int newfd)
{
	static char *value;
	static char init = 0;
	if (!init)
	{
		value = getenv("WITH_DUP");
		init = 1;
	}

	if (!value)
		return -1;

	static dup2_type original_dup2 = NULL;
	if (!original_dup2)
		original_dup2 = (dup2_type)dlsym(RTLD_NEXT, "dup2");

	return (original_dup2(oldfd, newfd));
}

int dup3(int oldfd, int newfd, int flags)
{
	static char *value;
	static char init = 0;
	if (!init)
	{
		value = getenv("WITH_DUP");
		init = 1;
	}

	if (!value)
		return -1;

	static dup3_type original_dup3 = NULL;
	if (!original_dup3)
		original_dup3 = (dup3_type)dlsym(RTLD_NEXT, "dup3");

	return (original_dup3(oldfd, newfd, flags));
}

int setenv(const char *name, const char *value, int overwrite)
{
	static char *env_value;
	static char init = 0;
	if (!init)
	{
		env_value = getenv("WITH_ENV");
		init = 1;
	}

	if (!env_value)
		return -1;

	static setenv_type original_setenv = NULL;
	if (!original_setenv)
		original_setenv = (setenv_type)dlsym(RTLD_NEXT, "setenv");

	return (original_setenv(name, env_value, overwrite));
}

int unsetenv(const char *name)
{
	static char *value;
	static char init = 0;
	if (!init)
	{
		value = getenv("WITH_ENV");
		init = 1;
	}

	if (!value)
		return -1;

	static unsetenv_type original_unsetenv = NULL;
	if (!original_unsetenv)
		original_unsetenv = (unsetenv_type)dlsym(RTLD_NEXT, "unsetenv");

	return (original_unsetenv(name));
}
