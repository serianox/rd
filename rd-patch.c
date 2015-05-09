#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <linux/user.h>

#define log(...) fprintf(stdout, __VA_ARGS__)
#define err(...) fprintf(stderr, __VA_ARGS__)

const unsigned long CPSR_T = 0x00000020u;

int shim_access(const char * path, int mode)
{
	if (strcmp(path, "/system/app/Superuser.apk") == 0)
		goto err_noent;

	if (strcmp(path, "/system/xbin/su") == 0)
		goto err_noent;

	return syscall(__NR_access, path, mode);

	err_noent:
		errno = ENOENT;
		return -1;
}

#if defined(SHARED)
static void __attribute__((constructor)) init()
{
	log("patching access@%#010x with shim@%#010x...\n", (unsigned) &access, (unsigned) &shim_access);

	uint32_t * src = (uint32_t *) &access;
	uint32_t * dst = (uint32_t *) &shim_access;

	size_t range = sysconf(_SC_PAGE_SIZE);
	void * page_base = (void *) ((uint32_t) src & ~(range - 1));
	void * page_end = page_base + range;

	log("reset memory protection for [%#010x, %#010x[...\n", (unsigned) page_base, (unsigned) page_end);

	if (mprotect(page_base, range, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
		exit(EXIT_FAILURE);

	0x0[src] = (    0xe59f3000); // ldr     r3, [pc]
	0x1[src] = (    0xea000000); // b       +4
	0x2[src] = ((uint32_t) dst); // .word   dst
	0x3[src] = (    0xe12fff13); // bx      r3

	if (mprotect(page_base, range, PROT_READ | PROT_EXEC) != 0)
		exit(EXIT_FAILURE);

	log("syscall patched!\n");
}
#endif // defined(SHARED)

static char * get_image_path()
{
	char buffer[1024]; int length = readlink("/proc/self/exe", buffer, sizeof buffer); buffer[length] = '\0';

	char * image_path; asprintf(&image_path, "%s", buffer);

	memcpy(&(strlen(image_path) - strlen("rd-patch"))[image_path], "librd.so", strlen("librd.so") + 1);

	return image_path;
}

static void dump_registers(struct user_regs * regs)
{
	log(" r0=%#010lx  r1=%#010lx  r2=%#010lx  r3=%#010lx\n", 0x0[regs->uregs], 0x1[regs->uregs], 0x2[regs->uregs], 0x3[regs->uregs]);
	log(" r4=%#010lx  r5=%#010lx  r6=%#010lx  r7=%#010lx\n", 0x4[regs->uregs], 0x5[regs->uregs], 0x6[regs->uregs], 0x7[regs->uregs]);
	log(" r8=%#010lx  r9=%#010lx r10=%#010lx r11=%#010lx\n", 0x8[regs->uregs], 0x9[regs->uregs], 0xa[regs->uregs], 0xb[regs->uregs]);
	log("r12=%#010lx  sp=%#010lx  lr=%#010lx  pc=%#010lx\n", 0xc[regs->uregs], 0xd[regs->uregs], 0xe[regs->uregs], 0xf[regs->uregs]);
	log("                                            cpsr=%#010lx\n", 0x10[regs->uregs]);
}

static unsigned long find_mapping(pid_t pid, char * image)
{
	char * map_file; if (asprintf(&map_file, "/proc/%u/maps", pid) == -1)
		exit(EXIT_FAILURE);

	FILE * map_fd; if ((map_fd = fopen(map_file, "r")) == NULL)
		exit(EXIT_FAILURE);

	char buffer[1024]; while (fgets(buffer, sizeof buffer, map_fd) != NULL)
	{
		// split line into null terminated srings (offsets are constants, except the remaining \n
		// 2aaaf000-2aaf1000 r-xp 00000000 1f:00 1474       /system/lib/libc.so
		char * begin = buffer;
		char * end = buffer + strlen("2aaaf000-");
		char * perms = buffer + strlen("2aaaf000-2aaf1000 ");
		char * offset = buffer + strlen("2aaaf000-2aaf1000 r-xp ");
		char * path = buffer + strlen("2aaaf000-2aaf1000 r-xp 00000000 1f:00 1474       ");
		buffer[strlen(buffer) - 1] = '\0';
		buffer[strlen("2aaaf000-2aaf1000 r-xp 00000000")] = '\0';
		buffer[strlen("2aaaf000-2aaf1000 r-xp")] = '\0';
		buffer[strlen("2aaaf000-2aaf1000")] = '\0';
		buffer[strlen("2aaaf000")] = '\0';

		if (strcmp(path, image) == 0)
		{
			if (strcmp(perms, "r-xp") == 0)
			{
				return atol(begin);
			}
		}
	}

	return 0;
}

int main(int argc, char * argv[])
{
	int euid; if ((euid = geteuid()) != 0)
	{
		err("not run as root (%i)\n", euid);
		exit(EXIT_FAILURE);
	}

	if (argc != 2)
	{
		err("invalid number of arguments (%i, expected 1)\n", argc - 1);
		exit(EXIT_FAILURE);
	}

	pid_t tracee_pid; if (sscanf (1[argv], "%u", &tracee_pid) != 1)
	{
		err("invalid argument (%s)\n", 1[argv]);
		exit(EXIT_FAILURE);
	}

	log("starting patching process %u...\n", tracee_pid);

	if (ptrace(PTRACE_ATTACH, tracee_pid, NULL, NULL) != 0)
		exit(EXIT_FAILURE);
	waitpid(tracee_pid, NULL, __WALL);

	log("injecting frame...\n");

	struct user_regs patch_regs, backup_regs;

	ptrace(PTRACE_GETREGS, tracee_pid, NULL, &patch_regs);
	memcpy(&backup_regs, &patch_regs, sizeof (struct user_regs));

	char * image_path;
	unsigned long * target;
	size_t image_path_size;

	image_path = get_image_path();
	image_path_size = strlen(image_path);
	target = (unsigned long *) patch_regs.ARM_sp;
	for (int count = (image_path_size + 3) >> 2; count >= 0; --count)
		ptrace(PTRACE_POKEDATA, tracee_pid, (void *) --target, (void *) count[(unsigned long *) image_path]);

	patch_regs.ARM_r0 = (unsigned long) target;
	patch_regs.ARM_r1 = RTLD_LAZY;
	patch_regs.ARM_sp = (unsigned long) target;
	patch_regs.ARM_lr = 0;
	patch_regs.ARM_pc = (unsigned long) &dlopen;
	patch_regs.ARM_cpsr |= CPSR_T;

	ptrace(PTRACE_SETREGS, tracee_pid, NULL, &patch_regs);

	ptrace(PTRACE_CONT, tracee_pid, NULL, NULL);
	log("resume process %u...\n", tracee_pid);
	waitpid(tracee_pid, NULL, __WALL);

	ptrace(PTRACE_GETREGS, tracee_pid, NULL, &patch_regs);
	ptrace(PTRACE_SETREGS, tracee_pid, NULL, &backup_regs);

	if (patch_regs.ARM_r0 != 0 && patch_regs.ARM_pc == 0 && find_mapping(tracee_pid, get_image_path()) != 0)
		log("successfully patched %u!!!\n", tracee_pid);

	ptrace(PTRACE_DETACH, tracee_pid, NULL, NULL);

	exit(EXIT_SUCCESS);
}
