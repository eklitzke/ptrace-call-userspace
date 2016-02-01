#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

// number of bytes in a CALL rel32 instruction
#define CALL_SZ 5

// copy in the string including the trailing null byte
static const char *format = "instruction pointer = %p\n";

// text seen in /proc/<pid>/maps for text areas
static const char *text_area = " r-xp ";

// this should be a string that will uniquely identify libc in /proc/<pid>/maps
static const char *libc_string = "/libc-2";

// find the location of a shared library in memory
void *find_library(pid_t pid, const char *libname) {
  char filename[32];
  snprintf(filename, sizeof(filename), "/proc/%d/maps", pid);
  FILE *f = fopen(filename, "r");
  char *line = NULL;
  size_t line_size = 0;

  while (getline(&line, &line_size, f) >= 0) {
    char *pos = strstr(line, libname);
    if (pos != NULL && strstr(line, text_area)) {
      long val = strtol(line, NULL, 16);
      free(line);
      fclose(f);
      return (void *)val;
    }
  }
  free(line);
  fclose(f);
  return NULL;
}

// Update the text area of pid at the area starting at where. The data copied
// should be in the new_text buffer whose size is given by len. If old_text is
// not null, the original text data will be copied into it. Therefore old_text
// must have the same size as new_text.
int poke_text(pid_t pid, void *where, void *new_text, void *old_text,
              size_t len) {
  if (len % sizeof(void *) != 0) {
    printf("invalid len, not a multiple of %zd\n", sizeof(void *));
    return -1;
  }

  long poke_data;
  for (size_t copied = 0; copied < len; copied += sizeof(poke_data)) {
    memmove(&poke_data, new_text + copied, sizeof(poke_data));
    if (old_text != NULL) {
      errno = 0;
      long peek_data = ptrace(PTRACE_PEEKTEXT, pid, where + copied, NULL);
      if (peek_data == -1 && errno) {
        perror("PTRACE_PEEKTEXT");
        return -1;
      }
      memmove(old_text + copied, &peek_data, sizeof(peek_data));
    }
    if (ptrace(PTRACE_POKETEXT, pid, where + copied, (void *)poke_data) < 0) {
      perror("PTRACE_POKETEXT");
      return -1;
    }
  }
  return 0;
}

int singlestep_once(pid_t pid) {
  int status;
  if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL)) {
    perror("PTRACE_SINGLESTEP");
    return -1;
  }
  waitpid(pid, &status, 0);
  return status;
}

int singlestep_many(pid_t pid, unsigned old_rip) {
  // Here we are going to "single step" through the process, which means that
  // it
  // will execute one x86 instruction at a time and after each instruction
  // control will return to us. We need to notice when the fprintf routine has
  // finished and returned back to the original code. That happens when rip =
  // orig_rip + 5 (the extra 5 bytes are from the size of the CALL
  // instruction).
  printf("single stepping\n");
  int status = singlestep_once(pid);
  size_t singlestep_count = 1;
  struct user_regs_struct regs;
  while (WIFSTOPPED(status)) {
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs)) {
      perror("PTRACE_GETREGS");
      return -1;
    }
    if (regs.rip == old_rip + CALL_SZ) {
      break;
    }
    status = singlestep_once(pid);
    singlestep_count++;
  }
  printf("finished single stepping after %zd instructions\n", singlestep_count);
  return 0;
}

void check_yama(void) {
  FILE *yama_file = fopen("/proc/sys/kernel/yama/ptrace_scope", "r");
  if (yama_file == NULL) {
    return;
  }
  char yama_buf[8];
  memset(yama_buf, 0, sizeof(yama_buf));
  fread(yama_buf, 1, sizeof(yama_buf), yama_file);
  if (strcmp(yama_buf, "0\n") != 0) {
    printf("\nThe likely cause of this failure is that your system has "
           "kernel.yama.ptrace_scope = %s",
           yama_buf);
    printf("If you would like to disable Yama, you can run: "
           "sudo sysctl kernel.yama.ptrace_scope=0\n");
  }
  fclose(yama_file);
}

int fprintf_process(pid_t pid, bool trap) {
  // attach to the process
  if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
    perror("PTRACE_ATTACH");
    check_yama();
    return 1;
  }

  // wait for the process to actually stop
  waitpid(pid, 0, WSTOPPED);

  // Calculate the position of the fprintf routine in the other process'
  // address
  // space. This is a little bit tricky because of ASLR on Linux. What we do
  // is
  // we find the offset in memory that libc has been loaded in their process,
  // and then we find the offset in memory that libc has been loaded in our
  // process. Then we take the delta betwen our fprintf and our libc start,
  // and
  // assume that the same delta will apply to the other process.
  //
  // For this mechanism to work, this program must be compiled with -fPIC to
  // ensure that our fprintf has an address relative to the one in libc.
  //
  // Additionally, this could fail if libc has been updated since the remote
  // process has been restarted. This is a pretty unlikely situation, but if
  // the
  // remote process has been running for a long time and you update libc, the
  // offset of the symbols could have changed slightly.
  void *their_libc = find_library(pid, libc_string);
  void *our_libc = find_library(getpid(), libc_string);
  void *their_fprintf = their_libc + ((void *)fprintf - our_libc);
  FILE *their_stderr = their_libc + ((void *)stderr - our_libc);
  printf("their libc      %p\n", their_libc);
  printf("their fprintf   %p\n", their_libc);
  printf("their stderr    %p\n", their_stderr);

  // Save the register state of the remote process.
  struct user_regs_struct oldregs;
  if (ptrace(PTRACE_GETREGS, pid, NULL, &oldregs)) {
    perror("PTRACE_GETREGS");
    goto fail;
  }
  printf("their %%rip      %p\n", (void *)oldregs.rip);

  // We want to make a call like:
  //
  //   fprintf(stderr, "instruction pointer = %p\n", rip);
  //
  // This is a little trickier than it sounds because we need to pass a string
  // into the remote process. Here's how it works. The remote process already
  // has fprintf and stderr defined, so those are easy. When we make the
  // fprintf
  // call we can pass the value of rip in via a register, so that's also easy.
  // However, the remote process doesn't have the string "instruction pointer
  // =
  // %p\n" anywhere in its memory.
  //
  // So here's what we're going to do
  //
  //  * overwrite the code current at rip with a CALL pointing to fprintf
  //  * overwrite the code after the CALLL with our format string
  //  * set up rdi = their_stderr
  //  * set up rsi = address of the string we just poked into their memory
  //  * set up rdx = rip
  //
  // Then when we resume the process the next instruction will be the CALL
  // instruction into fprintf that we added. This is great, but because we
  // overwrote data in the .text area it will leave the process' text area in
  // a
  // corrupted state. So we will have to restore the old code later.
  //
  // NOTE: If we are *really* unlucky here we could have attached to the
  // process
  // while it is actually in the middle of calling fprintf (or a function that
  // is called by fprintf). That would be disastrous because it will corrupt
  // the
  // code that fprintf needs to run. There are two ways to work around this if
  // you want to handle this case:
  //
  //   * Find some unused memory to put the new code into, or even just some
  //     text area known to not be needed by fprintf (e.g. the text for
  //     gethostbyname).
  //   * Allocate new memory, copy the code there, and then deallocate the
  //     memory when done. The easiest way to do this is to directly make a
  //     system call to mmap(2) for an anonymous page, and then munmap(2) it
  //     when you're done.
  //
  // Both of these techniques are left as an exercise to the reader.
  uint8_t new_text[32];
  uint8_t old_text[sizeof(new_text)];
  memset(new_text, 0, sizeof(new_text));

  size_t offset = 0;
  new_text[offset++] = 0xe8; // CALL rel32

  // compute the immediate relative value for the CALL rel32
  int64_t fprintf_delta =
      (int64_t)their_fprintf - (int64_t)oldregs.rip - CALL_SZ;
  if (fprintf_delta < INT_MIN || fprintf_delta > INT_MAX) {
    printf("cannot do relative jump of size %li; did you compile with -fPIC?\n",
           fprintf_delta);
    goto fail;
  }
  int32_t fprintf_delta32 = (int32_t)fprintf_delta;
  memmove(new_text + offset, &fprintf_delta32, sizeof(fprintf_delta32));
  offset += sizeof(fprintf_delta32);

  int string_offset = CALL_SZ;
  if (trap) {
    new_text[offset++] = 0xcc; // INT 3
    string_offset++;
  }

  // copy our fprintf format string right after the CALL instruction
  memmove(new_text + offset, format, strlen(format));

  // update the remote process' text area with our new code/string, and save
  // the
  // old text that had been there
  printf("poking the text of the remote process\n");
  if (poke_text(pid, (void *)oldregs.rip, new_text, old_text,
                sizeof(new_text))) {
    goto fail;
  }

  // set up our registers with the args to fprintf
  struct user_regs_struct newregs;
  memmove(&newregs, &oldregs, sizeof(newregs));
  newregs.rax = 0;                           // no vector registers are used
  newregs.rdi = (long)their_stderr;          // pointer to stderr in the caller
  newregs.rsi = oldregs.rip + string_offset; // pointer to the format string
  newregs.rdx = oldregs.rip;                 // the integer we want to print

  printf("setting the registers of the remote process\n");
  if (ptrace(PTRACE_SETREGS, pid, NULL, &newregs)) {
    perror("PTRACE_SETREGS");
    goto fail;
  }

  if (trap) {
    int wait_status;
    ptrace(PTRACE_CONT, pid, NULL, NULL);
    wait(&wait_status);
    if (WIFSTOPPED(wait_status)) {
      printf("Child got a signal: %s\n", strsignal(WSTOPSIG(wait_status)));
    } else {
      perror("wait");
      goto fail;
    }
  } else if (!singlestep_many(pid, oldregs.rip)) {
    goto fail;
  }

  // Restore the original code that we overwrote; if we don't do this, the
  // program will crash with something like SIGSEGV or SIGILL.
  printf("restoring old text\n");
  if (poke_text(pid, (void *)oldregs.rip, old_text, NULL, sizeof(old_text))) {
    goto fail;
  }

  // restore the old register state that we had clobbered
  printf("restoring old registers\n");
  if (ptrace(PTRACE_SETREGS, pid, NULL, &oldregs)) {
    perror("PTRACE_SETREGS");
    goto fail;
  }

  printf("detaching\n");
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
    perror("PTRACE_DETACH");
    goto fail;
  }
  return 0;

fail:
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
    perror("PTRACE_DETACH");
  }
  return 1;
}

int main(int argc, char **argv) {
  long pid = -1;
  bool single_step = false;
  bool trap = false;
  int c;
  opterr = 0;
  while ((c = getopt(argc, argv, "hstp:")) != -1) {
    switch (c) {
    case 'h':
      printf("Usage: %s -p <pid> [-s|-t]\n", argv[0]);
      return 0;
      break;
    case 's':
      single_step = true;
      break;
    case 't':
      trap = true;
      break;
    case 'p':
      pid = strtol(optarg, NULL, 10);
      if ((errno == ERANGE && (pid == LONG_MAX || pid == LONG_MIN)) ||
          (errno != 0 && pid == 0)) {
        perror("strtol");
        return 1;
      }
      if (pid < 0) {
        fprintf(stderr, "cannot accept negative pids\n");
        return 1;
      }
      break;
    case '?':
      if (optopt == 'p') {
        fprintf(stderr, "Option -p requreis an argument.\n");
      } else if (isprint(optopt)) {
        fprintf(stderr, "Unknown option `-%c`.\n", optopt);
      } else {
        fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
      }
      return 1;
      break;
    default:
      abort();
    }
  }
  if (single_step && trap) {
    fprintf(stderr, "options -s and -t are mutually exclusive\n");
    return 1;
  }
  if (pid == -1) {
    fprintf(stderr, "must specify a remote process with -p\n");
    return 1;
  }
  if (!single_step && !trap) {
    trap = true;
  }

  return fprintf_process((pid_t)pid, trap);
}
