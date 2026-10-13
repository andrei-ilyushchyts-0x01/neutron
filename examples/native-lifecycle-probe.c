/* Disposable leader-first pthread_exit oracle. Never targets another process.
 * cc -std=c11 -Wall -Wextra -Werror -pthread native-lifecycle-probe.c -o probe
 * probe /absolute/private/session
 */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int marker(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    return close(fd);
}

static void *worker(void *unused) {
    (void)unused;
    struct timespec delay = {.tv_sec = 1, .tv_nsec = 0};
    while (nanosleep(&delay, &delay) != 0) {
        if (errno != EINTR) _exit(2);
    }
    if (marker("worker-after-leader") != 0) _exit(2);
    return NULL;
}

int main(int argc, char **argv) {
    if ((argc != 2 && argc != 3) || argv[1][0] != '/') {
        fprintf(stderr, "usage: probe /absolute/private/session [leader-exit|worker-exit|exit0|exit7|wait-signal]\n");
        return 2;
    }
    int directory = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (directory < 0 || fstat(directory, &st) != 0 ||
        st.st_uid != geteuid() || (st.st_mode & 0077) != 0 || fchdir(directory) != 0) return 2;
    close(directory);
    const char *mode = argc == 3 ? argv[2] : "leader-exit";
    if (marker("leader-ready") != 0) return 2;
    /* The controller attaches and opens its scenario before creating start. */
    int started = 0;
    for (int attempt = 0; attempt < 300; ++attempt) {
        if (faccessat(AT_FDCWD, "start", F_OK, AT_SYMLINK_NOFOLLOW) == 0) { started = 1; break; }
        struct timespec delay = {.tv_sec = 0, .tv_nsec = 100000000};
        nanosleep(&delay, NULL);
    }
    if (!started) return 2;
    if (strcmp(mode, "exit0") == 0) return 0;
    if (strcmp(mode, "exit7") == 0) return 7;
    if (strcmp(mode, "wait-signal") == 0) {
        sleep(10); /* bounded even if the test controller disappears */
        return 2;
    }
    if (strcmp(mode, "leader-exit") != 0 && strcmp(mode, "worker-exit") != 0) return 2;
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL) != 0) return 2;
    if (strcmp(mode, "worker-exit") == 0) {
        if (pthread_join(thread, NULL) != 0 || marker("leader-after-worker") != 0) return 2;
        return 0;
    }
    if (pthread_detach(thread) != 0) return 2;
    pthread_exit(NULL);
}
