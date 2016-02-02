#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char **arv) {
  for (;;) {
    printf("%d\n", getpid());
    sleep(1);
  }
  return 0;
}
