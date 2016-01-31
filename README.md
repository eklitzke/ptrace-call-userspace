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

Note: this code is specific to the Linux implementation of ptrace.

## How It Works

Just look at the source code. There are a *lot* of comments explaining exactly
what is going on, what caveats there are, etc.

## Usage

You can compile the code with `make`. You should see that it builds an
executable called `show_ip`. Then it's invoked like this:

    show_ip <pid>

An easy way to test this is to open two terminals, run `echo $$` in the first
terminal to get the pid of the shell, and then in the other terminal run
`show_ip` with the first shell's pid.

When you run the command, you will see output like this:

```
$ ./show_ip 5603
their libc      0x7fcbb47cc000
their fprintf   0x7fcbb47cc000
their stderr    0x7fcbb4b88560
their %rip      0x7fcbb48bebb0
poking the text of the remote process
setting the registers of the remote process
single stepping
finished single stepping after 1150 instructions
restoring old text
restoring old registers
detaching
```
