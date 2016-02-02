# Using ptrace(2) To Call a Userspace Function

Unix systems define an incredibly powerful system call called
[`ptrace(2)`](http://man7.org/linux/man-pages/man2/ptrace.2.html). This system
call is available on Linux, BSD, and OS X (but note that the interface is not
exactly the same between the Linux ptrace and the BSD/OS X ptrace). Using ptrace
you can arbitrarily inspect or modify the state of another process.

While working with ptrace I found a lot of examples online of using ptrace to
make a Linux system call. However I was unable to find any examples of how to
use ptrace to call a userspace method in the remote process, which is a lot more
interesting (in my opinion) and also more difficult to do.

The purpose of this project is to demonstrate what the code looks like to do
this. This code will do the equivalent of making this function call in the
attached process:

```c
fprintf(stderr, "instruction pointer = %p\n", rip);
```

where `rip` is the value of the instruction pointer when the process was
attached. After the call to `fprintf()` completes, the program will resume
execution where it was when it was attached, as if nothing has changed.

**Note:** this code is specific to the Linux implementation of ptrace.

## How It Works

Just look at the source code. There are a *lot* of comments explaining exactly
what is going on, what caveats there are, etc.

I also wrote some articles about this program
[here (part 1)](https://eklitzke.org/ptrace) and
[here (part 2)](https://eklitzke.org/ptrace-continued).

## Usage

You can compile the code with `make`. You should see that it builds an
executable called `call-fprintf`. Invoke it like this:

    call-fprintf -p <pid>

An easy way to test this is to open two terminals, run `echo $$` in the first
terminal to get the pid of the shell, and then in the other terminal run
`call-fprintf` with the first shell's pid.

When you run the command, you will see output like this:

```
$ ./call-fprintf -p 21160
their %rip           0x7f229e153790
allocated memory at  0x7f229e669000
executing jump to mmap region
successfully jumped to mmap area
their libc           0x7f229e08b000
their fprintf        0x7f229e08b000
their stderr         0x7f229e447560
inserting code/data into the mmap area at 0x7f229e669000
setting the registers of the remote process
continuing execution
successfully caught TRAP signal
jumping back to original rip
successfully jumped back to original %rip at 0x7f229e153790
making call to mmap
munmap returned with status 0
restoring old text at 0x7f229e153790
restoring old registers
detaching
```

## Issues With Yama ptrace_scope

If you get a failure like this:
```bash
$ ./call-fprintf -p 1
PTRACE_ATTACH: Operation not permitted
```

then you are trying to trace a process that you don't have permissions to trace,
i.e. a process with a different user id than you. You can only ptrace a process
whose effective user id is the same as yours (or if you are root).

If you instead get a failure like this:
```bash
$ ./call-fprintf -p 5603
PTRACE_ATTACH: Operation not permitted

The likely cause of this failure is that your system has kernel.yama.ptrace_scope = 1
If you would like to disable Yama, you can run: sudo sysctl kernel.yama.ptrace_scope=0
```

Then the issue is that you have
[Yama ptrace_scope](https://www.kernel.org/doc/Documentation/security/Yama.txt)
configured to disallow ptrace. In particular, the default behavior of Ubuntu
since Ubuntu 10.10 has been to set `kernel.yama.ptrace_scope = 1`. If this
affects you, you can either run `call-fprintf` as root, or you can run the
command listed in the error message to disable the Yama setting.
