
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc != 2) return 64;
  if (!strcmp(argv[1], "--child")) return 0;
  if (!strcmp(argv[1], "--failure")) return 7;
  if (!strcmp(argv[1], "--sleep")) { sleep(10); return 0; }
  int source = open(argv[0], O_RDONLY), image = memfd_create("trace-control", MFD_CLOEXEC);
  if (source < 0 || image < 0) return 65;
  char buffer[4096]; ssize_t size;
  while ((size = read(source, buffer, sizeof buffer)) > 0)
    if (write(image, buffer, size) != size) return 66;
  close(source);
  int child = fork();
  if (child == 0) {
    char *args[] = {"trace-control-child", "--child", NULL};
    char *env[] = {NULL};
    execveat(image, "", args, env, AT_EMPTY_PATH);
    _exit(67);
  }
  int status = 0;
  if (child < 0 || waitpid(child, &status, 0) != child || status != 0) return 68;
  const char data[] = "external control only\n";
  int output = open(argv[1], O_WRONLY|O_CREAT|O_EXCL, 0600);
  if (output < 0 || write(output, data, sizeof data - 1) != sizeof data - 1) return 69;
  close(output);
  return write(1, data, sizeof data - 1) == sizeof data - 1 ? 0 : 70;
}
