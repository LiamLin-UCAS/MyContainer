import ctypes
import os

CSIGNAL = 0x000000ff  # /* signal mask to be sent at exit */
CLONE_VM = 0x00000100  # /* set if VM shared between processes */
CLONE_FS = 0x00000200  # /* set if fs info shared between processes */
CLONE_FILES = 0x00000400  # /* set if open files shared between processes */
CLONE_SIGHAND = 0x00000800  # /* set if signal handlers and blocked signals shared */
CLONE_PTRACE = 0x00002000  # /* set if we want to let tracing continue on the child too */
CLONE_VFORK = 0x00004000  # /* set if the parent wants the child to wake it up on mm_release */
CLONE_PARENT = 0x00008000  # /* set if we want to have the same parent as the cloner */
CLONE_THREAD = 0x00010000  # /* Same thread group? */
CLONE_NEWNS = 0x00020000  # /* New mount namespace group */
CLONE_SYSVSEM = 0x00040000  # /* share system V SEM_UNDO semantics */
CLONE_SETTLS = 0x00080000  # /* create a new TLS for the child */
CLONE_PARENT_SETTID = 0x00100000  # /* set the TID in the parent */
CLONE_CHILD_CLEARTID = 0x00200000  # /* clear the TID in the child */
CLONE_NEWCGROUP = 0x02000000
CLONE_DETACHED = 0x00400000  # /* Unused, ignored */
CLONE_UNTRACED = 0x00800000  # /* set if the tracing process can't force CLONE_PTRACE on this clone */
CLONE_CHILD_SETTID = 0x01000000  # /* set the TID in the child */
CLONE_NEWUTS = 0x04000000  # /* New utsname namespace */
CLONE_NEWIPC = 0x08000000  # /* New ipc namespace */
CLONE_NEWUSER = 0x10000000  # /* New user namespace */
CLONE_NEWPID = 0x20000000  # /* New pid namespace */
CLONE_NEWNET = 0x40000000  # /* New network namespace */
CLONE_IO = 0x80000000  # /* Clone io context */
CLONE_NEWTIME	=0x00000080
libc = ctypes.CDLL("libc.so.6", use_errno=True)
libc.syscall.argtypes = [ctypes.c_int, ctypes.c_int]

def unshare(flags):
    SYS_unshare = 272  # from asm/unistd_64.h
    ret = libc.syscall(SYS_unshare, flags)
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return ret


if __name__ == '__main__':
    ret = libc.syscall(272,0x10000000)
    print(ret)
    errno = ctypes.get_errno()
    print(errno,os.strerror(errno))
