/**+++++++++++++++++++++++++++++++++++*/
#include <stdio.h>
#include <unistd.h>
#include <pwd.h>
#include <curses.h>
#include <timers.h>
#include <stdlib.h>
#include <limits.h>
#include <termcap.h>
#include <termios.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <assert.h>

#include <sys/ioc_tty.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>

#include <minix/com.h>
#include <minix/config.h>
#include <minix/type.h>
#include <minix/endpoint.h>
#include <minix/const.h>
#include <minix/u64.h>
#include <paths.h>
#include <minix/procfs.h>

#define TIMECYCLEKEY 't'
#define ORDERKEY 'o'

#define ORDER_CPU	0
#define ORDER_MEMORY	1
#define ORDER_HIGHEST	ORDER_MEMORY
int order = ORDER_CPU;

u32_t system_hz;

/* name of cpu cycle types, in the order they appear in /psinfo. */
const char *cputimenames[] = { "user", "ipc", "kernelcall" };

#define CPUTIMENAMES (sizeof(cputimenames)/sizeof(cputimenames[0]))

#define CPUTIME(m, i) (m & (1L << (i)))

unsigned int nr_procs, nr_tasks;
int nr_total;

#define  SLOT_NR(e) (_ENDPOINT_P(e) + nr_tasks)

#define  TC_BUFFER  1024        /* Size of termcap(3) buffer    */
#define  TC_STRINGS  200        /* Enough room for cm,cl,so,se  */

char *Tclr_all;

int blockedverbose = 0;

#define  USED		0x1
#define  IS_TASK	0x2
#define  IS_SYSTEM	0x4
#define  BLOCKED	0x8

struct proc {
	int p_flags;
	endpoint_t p_endpoint;
	pid_t p_pid;
	u64_t p_cpucycles[CPUTIMENAMES];
	int p_priority;
	endpoint_t p_blocked;
	time_t p_user_time;
	vir_bytes p_memory;
	uid_t p_effuid;
	int p_nice;
	char p_name[PROC_NAME_LEN+1];
};

struct proc *proc = NULL, *prev_proc = NULL;

struct tp {
	struct proc *p;
	u64_t ticks;
};

/*+++++++++++++++++++++++++++++++++++++++++++++*/

void getkinfo(void);
int print_memory(void);
void get_procs(void);
void parse_dir(void);
void parse_file(pid_t pid);
void print_procs(struct proc *proc1, struct proc *proc2, int cputimemode);
u64_t cputicks(struct proc *p1, struct proc *p2, int timemode);

void getkinfo(void)
{
	FILE *fp;

	if ((fp = fopen("/proc/kinfo", "r")) == NULL) {
		fprintf(stderr, "opening " _PATH_PROC "kinfo failed\n");
		exit(1);
	}

	if (fscanf(fp, "%u %u", &nr_procs, &nr_tasks) != 2) {
		fprintf(stderr, "reading from " _PATH_PROC "kinfo failed\n");
		exit(1);
	}

	fclose(fp);

	nr_total = (int) (nr_procs + nr_tasks);
}

int print_memory(void)
{
	FILE *fp;
	unsigned int pagesize;
	unsigned long total, free, largest, cached;

	if ((fp = fopen("/proc/meminfo", "r")) == NULL)
		return 0;

	if (fscanf(fp, "%u %lu %lu %lu %lu", &pagesize, &total, &free,
			&largest, &cached) != 5) {
		fclose(fp);
		return 0;
	}

	fclose(fp);

	printf("main memory: %ldK total, %ldK free, %ldK contig free, "
		"%ldK cached\n",
		(pagesize * total)/1024, (pagesize * free)/1024,
		(pagesize * largest)/1024, (pagesize * cached)/1024);

	return 1;
}

void get_procs(void)
{
	struct proc *p;
	int i;

	p = prev_proc;
	prev_proc = proc;
	proc = p;

	if (proc == NULL) {
		proc = malloc(nr_total * sizeof(proc[0]));

		if (proc == NULL) {
			fprintf(stderr, "Out of memory!\n");
			exit(1);
		}
	}

	for (i = 0; i < nr_total; i++)
		proc[i].p_flags = 0;

	parse_dir();
}

void parse_dir(void)
{
	DIR *p_dir;
	struct dirent *p_ent;
	pid_t pid;
	char *end;

	if ((p_dir = opendir(".")) == NULL) {
		perror("opendir on " _PATH_PROC);
		exit(1);
	}

	for (p_ent = readdir(p_dir); p_ent != NULL; p_ent = readdir(p_dir)) {
		pid = strtol(p_ent->d_name, &end, 10);

		if (!end[0] && pid != 0)
			parse_file(pid);
	}

	closedir(p_dir);
}

void parse_file(pid_t pid)
{
	char path[PATH_MAX], name[256], type, state;
	int version, endpt, effuid;
	unsigned long cycles_hi, cycles_lo;
	FILE *fp;
	struct proc *p;
	int slot;
	int i;

	sprintf(path, "/proc%d/psinfo", pid);

	if ((fp = fopen(path, "r")) == NULL)
		return;

	if (fscanf(fp, "%d", &version) != 1) {
		fclose(fp);
		return;
	}

	if (version != PSINFO_VERSION) {
		fputs("procfs version mismatch!\n", stderr);
		exit(1);
	}

	if (fscanf(fp, " %c %d", &type, &endpt) != 2) {
		fclose(fp);
		return;
	}

	slot = SLOT_NR(endpt);

	if(slot < 0 || slot >= nr_total) {
		fprintf(stderr, "top: unreasonable endpoint number %d\n", endpt);
		fclose(fp);
		return;
	}

	p = &proc[slot];

	if (type == TYPE_TASK)
		p->p_flags |= IS_TASK;
	else if (type == TYPE_SYSTEM)
		p->p_flags |= IS_SYSTEM;

	p->p_endpoint = endpt;
	p->p_pid = pid;

	if (fscanf(fp, " %255s %c %d %d %lu %*u %lu %lu",
		name, &state, &p->p_blocked, &p->p_priority,
		&p->p_user_time, &cycles_hi, &cycles_lo) != 7) {

		fclose(fp);
		return;
	}

	strncpy(p->p_name, name, sizeof(p->p_name)-1);
	p->p_name[sizeof(p->p_name)-1] = 0;

	if (state != STATE_RUN)
		p->p_flags |= BLOCKED;
	p->p_cpucycles[0] = make64(cycles_lo, cycles_hi);
	p->p_memory = 0L;

	if (!(p->p_flags & IS_TASK)) {
		int j;
		if ((j=fscanf(fp, " %lu %*u %*u %*c %*d %*u %u %*u %d %*c %*d %*u",
			&p->p_memory, &effuid, &p->p_nice)) != 3) {

			fclose(fp);
			return;
		}

		p->p_effuid = effuid;
	} else p->p_effuid = 0;

	for(i = 1; i < CPUTIMENAMES; i++) {
		if(fscanf(fp, " %lu %lu",
			&cycles_hi, &cycles_lo) == 2) {
			p->p_cpucycles[i] = make64(cycles_lo, cycles_hi);
		} else	{
			p->p_cpucycles[i] = 0;
		}
	}

	if ((p->p_flags & IS_TASK)) {
		if(fscanf(fp, " %lu", &p->p_memory) != 1) {
			p->p_memory = 0;
		}
	}

	p->p_flags |= USED;

	fclose(fp);
}

void print_procs(struct proc *proc1, struct proc *proc2, int cputimemode)
{
	int p, nprocs;
	// u64_t idleticks = 0;
	// u64_t kernelticks = 0;
	u64_t systemticks = 0;
	u64_t userticks = 0;
	u64_t total_ticks = 0;
	int blockedseen = 0;
	static struct tp *tick_procs = NULL;

	if (tick_procs == NULL) {
		tick_procs = malloc(nr_total * sizeof(tick_procs[0]));

		if (tick_procs == NULL) {
			fprintf(stderr, "Out of memory!\n");
			exit(1);
		}
	}

	for(p = nprocs = 0; p < nr_total; p++) {
		u64_t uticks;
		if(!(proc2[p].p_flags & USED))
			continue;
		tick_procs[nprocs].p = proc2 + p;
		tick_procs[nprocs].ticks = cputicks(&proc1[p], &proc2[p], cputimemode);
		uticks = cputicks(&proc1[p], &proc2[p], 1);
		total_ticks = total_ticks + uticks;
		// if(p-NR_TASKS == IDLE) {
		// 	idleticks = uticks;
		// 	continue;
		// }
		// if(p-NR_TASKS == KERNEL) {
		// 	kernelticks = uticks;
		// }
		if(!(proc2[p].p_flags & IS_TASK)) {
			if(proc2[p].p_flags & IS_SYSTEM)
				systemticks = systemticks + tick_procs[nprocs].ticks;
			else
				userticks = userticks + tick_procs[nprocs].ticks;
		}

		nprocs++;
	}

	if (total_ticks == 0)
		return;

	//qsort(tick_procs, nprocs, sizeof(tick_procs[0]), cmp_procs);

	printf("CPU states: %6.2f%% user, ", 100.0 * userticks / total_ticks);
	printf("%6.2f%% system, ", 100.0 * systemticks / total_ticks);
	printf("%6.2f%% kernel, ", 100.0 * kernelticks/ total_ticks);
	printf("%6.2f%% idle", 100.0 * idleticks / total_ticks);
}

u64_t cputicks(struct proc *p1, struct proc *p2, int timemode)
{
	int i;
	u64_t t = 0;
	for(i = 0; i < CPUTIMENAMES; i++) {
		if(!CPUTIME(timemode, i))
			continue;
		if(p1->p_endpoint == p2->p_endpoint) {
			t = t + p2->p_cpucycles[i] - p1->p_cpucycles[i];
		} else {
			t = t + p2->p_cpucycles[i];
		}
	}

	return t;
}
