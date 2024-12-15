/*
    This file defines the kernel interface of FUSE
    Copyright (C) 2001-2008  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    This -- and only this -- header file may also be distributed under
    the terms of the BSD Licence as follows:

    Copyright (C) 2001-2007 Miklos Szeredi. All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:
    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
    OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
    HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
    OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
    SUCH DAMAGE.
*/

/*
 * This file defines the kernel interface of FUSE
 *
 * Protocol changelog:
 *
 * 7.9:
 *  - new fuse_getattr_in input argument of GETATTR
 *  - add lk_flags in fuse_lk_in
 *  - add lock_owner field to fuse_setattr_in, fuse_read_in and fuse_write_in
 *  - add blksize field to fuse_attr
 *  - add file flags field to fuse_read_in and fuse_write_in
 *
 * 7.10
 *  - add nonseekable open flag
 *
 * 7.11
 *  - add IOCTL message
 *  - add unsolicited notification support
 *  - add POLL message and NOTIFY_POLL notification
 *
 * 7.12
 *  - add umask flag to input argument of open, mknod and mkdir
 *  - add notification messages for invalidation of inodes and
 *    directory entries
 *
 * 7.13
 *  - make max number of background requests and congestion threshold
 *    tunables
 *
 * 7.14
 *  - add splice support to fuse device
 *
 * 7.15
 *  - add store notify
 *  - add retrieve notify
 *
 * 7.16
 *  - add BATCH_FORGET request
 *  - FUSE_IOCTL_UNRESTRICTED shall now return with array of 'struct
 *    fuse_ioctl_iovec' instead of ambiguous 'struct iovec'
 *  - add FUSE_IOCTL_32BIT flag
 *
 * 7.17
 *  - add FUSE_FLOCK_LOCKS and FUSE_RELEASE_FLOCK_UNLOCK
 *
 * 7.18
 *  - add FUSE_IOCTL_DIR flag
 *  - add FUSE_NOTIFY_DELETE
 *
 * 7.19
 *  - add FUSE_FALLOCATE
 *
 * 7.20
 *  - add FUSE_AUTO_INVAL_DATA
 *
 * 7.21
 *  - add FUSE_READDIRPLUS
 *  - send the requested events in POLL request
 *
 * 7.22
 *  - add FUSE_ASYNC_DIO
 *
 * 7.23
 *  - add FUSE_WRITEBACK_CACHE
 *  - add time_gran to fuse_init_out
 *  - add reserved space to fuse_init_out
 *  - add FATTR_CTIME
 *  - add ctime and ctimensec to fuse_setattr_in
 *  - add FUSE_RENAME2 request
 *  - add FUSE_NO_OPEN_SUPPORT flag
 *
 *  7.24
 *  - add FUSE_LSEEK for SEEK_HOLE and SEEK_DATA support
 *
 *  7.25
 *  - add FUSE_PARALLEL_DIROPS
 *
 *  7.26
 *  - add FUSE_HANDLE_KILLPRIV
 *  - add FUSE_POSIX_ACL
 */

/*
 * Version negotiation:
 *
 * Both the kernel and userspace send the version they support in the
 * INIT request and reply respectively.
 *
 * If the major versions match then both shall use the smallest
 * of the two minor versions for communication.
 *
 * If the kernel supports a larger major version, then userspace shall
 * reply with the major version it supports, ignore the rest of the
 * INIT message and expect a new INIT message from the kernel with a
 * matching major version.
 *
 * If the library supports a larger major version, then it shall fall
 * back to the major protocol version sent by the kernel for
 * communication and reply with that major version (and an arbitrary
 * supported minor version).
 */

use ostd::Pod;
use bitflags::bitflags;


/** Version number of this interface */
const FUSE_KERNEL_VERSION: usize = 7;

/** Minor version number of this interface */
const FUSE_KERNEL_MINOR_VERSION: usize = 26;

/** The node ID of the root inode */
const FUSE_ROOT_ID: usize = 1;

/* Make sure all structures are padded to 64bit boundary, so 32bit
   userspace works under 64bit kernels */

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseAttr {
	ino: u64,
	size: u64,
	blocks: u64,
	atime: u64,
	mtime: u64,
	ctime: u64,
	atimensec: u32,
	mtimensec: u32,
	ctimensec: u32,
	mode: u32,
	nlink: u32,
	uid: u32,
	gid: u32,
	rdev: u32,
	blksize: u32,
	padding: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseKstatfs {
	blocks: u64,
	bfree: u64,
	bavail: u64,
	files: u64,
	ffree: u64,
	bsize: u32,
	namelen: u32,
	frsize: u32,
	padding: u32,
	spare: [u32; 6],
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseFileLock {
	start: u64,
	end: u64,
	types: u32, //TODO: type
	pid: u32, /* tgid */
}


bitflags! {
/**
 * Bitmasks for FuseSetattrIn.valid
 */
    #[repr(C)]
    #[derive(Default, Pod)]
    pub struct ValidBitmasks: u32 {
        const FATTR_MODE = 1 << 0;
        const FATTR_UID = 1 << 1;
        const FATTR_GID = 1 << 2;
        const FATTR_SIZE = 1 << 3;
        const FATTR_ATIME = 1 << 4;
        const FATTR_MTIME = 1 << 5;
        const FATTR_FH = 1 << 6;
        const FATTR_ATIME_NOW = 1 << 7;
        const FATTR_MTIME_NOW = 1 << 8;
        const FATTR_LOCKOWNER = 1 << 9;
        const FATTR_CTIME = 1 << 10;
    }
}


bitflags! {
/**
 * Flags returned by the OPEN request
 *
 * FOPEN_DIRECT_IO: bypass page cache for this open file
 * FOPEN_KEEP_CACHE: don't invalidate the data cache on open
 * FOPEN_NONSEEKABLE: the file is not seekable
 */
    #[repr(C)]
    #[derive(Default, Pod)]
    pub struct OpenFlags: u32 {
        const FOPEN_DIRECT_IO = 1 << 0;
        const FOPEN_KEEP_CACHE = 1 << 1;
        const FOPEN_NONSEEKABLE = 1 << 2;
    }
}

bitflags! {
/**
 * INIT request/reply flags
 *
 * FUSE_ASYNC_READ: asynchronous read requests
 * FUSE_POSIX_LOCKS: remote locking for POSIX file locks
 * FUSE_FILE_OPS: kernel sends file handle for fstat, etc... (not yet supported)
 * FUSE_ATOMIC_O_TRUNC: handles the O_TRUNC open flag in the filesystem
 * FUSE_EXPORT_SUPPORT: filesystem handles lookups of "." and ".."
 * FUSE_BIG_WRITES: filesystem can handle write size larger than 4kB
 * FUSE_DONT_MASK: don't apply umask to file mode on create operations
 * FUSE_SPLICE_WRITE: kernel supports splice write on the device
 * FUSE_SPLICE_MOVE: kernel supports splice move on the device
 * FUSE_SPLICE_READ: kernel supports splice read on the device
 * FUSE_FLOCK_LOCKS: remote locking for BSD style file locks
 * FUSE_HAS_IOCTL_DIR: kernel supports ioctl on directories
 * FUSE_AUTO_INVAL_DATA: automatically invalidate cached pages
 * FUSE_DO_READDIRPLUS: do READDIRPLUS (READDIR+LOOKUP in one)
 * FUSE_READDIRPLUS_AUTO: adaptive readdirplus
 * FUSE_ASYNC_DIO: asynchronous direct I/O submission
 * FUSE_WRITEBACK_CACHE: use writeback cache for buffered writes
 * FUSE_NO_OPEN_SUPPORT: kernel supports zero-message opens
 * FUSE_PARALLEL_DIROPS: allow parallel lookups and readdir
 * FUSE_HANDLE_KILLPRIV: fs handles killing suid/sgid/cap on write/chown/trunc
 * FUSE_POSIX_ACL: filesystem supports posix acls
 */
    #[repr(C)]
    #[derive(Default, Pod)]
    pub struct InitFlags: u32 {
        const FUSE_ASYNC_READ = 1 << 0;
        const FUSE_POSIX_LOCKS = 1 << 1;
        const FUSE_FILE_OPS = 1 << 2;
        const FUSE_ATOMIC_O_TRUNC = 1 << 3;
        const FUSE_EXPORT_SUPPORT = 1 << 4;
        const FUSE_BIG_WRITES = 1 << 5;
        const FUSE_DONT_MASK = 1 << 6;
        const FUSE_SPLICE_WRITE = 1 << 7;
        const FUSE_SPLICE_MOVE = 1 << 8;
        const FUSE_SPLICE_READ = 1 << 9;
        const FUSE_FLOCK_LOCKS = 1 << 10;
        const FUSE_HAS_IOCTL_DIR = 1 << 11;
        const FUSE_AUTO_INVAL_DATA = 1 << 12;
        const FUSE_DO_READDIRPLUS = 1 << 13;
        const FUSE_READDIRPLUS_AUTO = 1 << 14;
        const FUSE_ASYNC_DIO = 1 << 15;
        const FUSE_WRITEBACK_CACHE = 1 << 16;
        const FUSE_NO_OPEN_SUPPORT = 1 << 17;
        const FUSE_PARALLEL_DIROPS = 1 << 18;
        const FUSE_HANDLE_KILLPRIV = 1 << 19;
        const FUSE_POSIX_ACL = 1 << 20;
    }
}

bitflags! {
/**
 * CUSE INIT request/reply flags
 *
 * CUSE_UNRESTRICTED_IOCTL:  use unrestricted ioctl
 */
    #[repr(C)]
    #[derive(Default, Pod)]
    pub struct CuseInitFlags: u32 {
        const CUSE_UNRESTRICTED_IOCTL = 1 << 0;
    }
}

bitflags! {
/**
 * Release flags
 */
    #[repr(C)]
    #[derive(Default, Pod)]
    pub struct ReleaseFlags: u32 {
        const FUSE_RELEASE_FLUSH = 1 << 0;
        const FUSE_RELEASE_FLOCK_UNLOCK = 1 << 1;
    }
}

bitflags! {
/**
 * Getattr flags
 */
    #[repr(C)]
    #[derive(Default, Pod)]
    pub struct GetattrFlags: u32 {
        const FUSE_GETATTR_FH = 1 << 0;
    }
}

bitflags! {
/**
 * Lock flags
 */
    #[repr(C)]
    #[derive(Default, Pod)]
    pub struct LockFlags: u32 {
        const FUSE_LK_FLOCK = 1 << 0;
    }
}

bitflags! {
/**
 * WRITE flags
 *
 * FUSE_WRITE_CACHE: delayed write from page cache, file handle is guessed
 * FUSE_WRITE_LOCKOWNER: lock_owner field is valid
 */
    #[repr(C)]
    #[derive(Default, Pod)]
    pub struct WriteFlags: u32 {
        const FUSE_WRITE_CACHE = 1 << 0;
        const FUSE_WRITE_LOCKOWNER = 1 << 1;
    }
}

bitflags! {
/**
 * Read flags
 */
    #[repr(C)]
    #[derive(Default, Pod)]
    pub struct ReadFlags: u32 {
        const FUSE_READ_LOCKOWNER = 1 << 1;
    }
}

bitflags! {
/**
 * Ioctl flags
 *
 * FUSE_IOCTL_COMPAT: 32bit compat ioctl on 64bit machine
 * FUSE_IOCTL_UNRESTRICTED: not restricted to well-formed ioctls, retry allowed
 * FUSE_IOCTL_RETRY: retry with new iovecs
 * FUSE_IOCTL_32BIT: 32bit ioctl
 * FUSE_IOCTL_DIR: is a directory
 *
 * FUSE_IOCTL_MAX_IOV: maximum of in_iovecs + out_iovecs
 */
    #[repr(C)]
    #[derive(Default, Pod)]
    pub struct IoctlFlags: u32 {
        const FUSE_IOCTL_COMPAT = 1 << 0;
        const FUSE_IOCTL_UNRESTRICTED = 1 << 1;
        const FUSE_IOCTL_RETRY = 1 << 2;
        const FUSE_IOCTL_32BIT = 1 << 3;
        const FUSE_IOCTL_DIR = 1 << 4;
    }
}

const FUSE_IOCTL_MAX_IOV: usize = 256;

/**
 * Poll flags
 *
 * FUSE_POLL_SCHEDULE_NOTIFY: request poll notify
 */
const FUSE_POLL_SCHEDULE_NOTIFY: usize = 1 << 0;

#[allow(non_camel_case_types)]
enum FuseOpcode {
	FUSE_LOOKUP	   = 1,
	FUSE_FORGET	   = 2,  /* no reply */
	FUSE_GETATTR	   = 3,
	FUSE_SETATTR	   = 4,
	FUSE_READLINK	   = 5,
	FUSE_SYMLINK	   = 6,
	FUSE_MKNOD	   = 8,
	FUSE_MKDIR	   = 9,
	FUSE_UNLINK	   = 10,
	FUSE_RMDIR	   = 11,
	FUSE_RENAME	   = 12,
	FUSE_LINK	   = 13,
	FUSE_OPEN	   = 14,
	FUSE_READ	   = 15,
	FUSE_WRITE	   = 16,
	FUSE_STATFS	   = 17,
	FUSE_RELEASE       = 18,
	FUSE_FSYNC         = 20,
	FUSE_SETXATTR      = 21,
	FUSE_GETXATTR      = 22,
	FUSE_LISTXATTR     = 23,
	FUSE_REMOVEXATTR   = 24,
	FUSE_FLUSH         = 25,
	FUSE_INIT          = 26,
	FUSE_OPENDIR       = 27,
	FUSE_READDIR       = 28,
	FUSE_RELEASEDIR    = 29,
	FUSE_FSYNCDIR      = 30,
	FUSE_GETLK         = 31,
	FUSE_SETLK         = 32,
	FUSE_SETLKW        = 33,
	FUSE_ACCESS        = 34,
	FUSE_CREATE        = 35,
	FUSE_INTERRUPT     = 36,
	FUSE_BMAP          = 37,
	FUSE_DESTROY       = 38,
	FUSE_IOCTL         = 39,
	FUSE_POLL          = 40,
	FUSE_NOTIFY_REPLY  = 41,
	FUSE_BATCH_FORGET  = 42,
	FUSE_FALLOCATE     = 43,
	FUSE_READDIRPLUS   = 44,
	FUSE_RENAME2       = 45,
	FUSE_LSEEK         = 46,

	/* CUSE specific operations */
	CUSE_INIT          = 4096,
}

#[allow(non_camel_case_types)]
enum FuseNotifyCode {
	FUSE_NOTIFY_POLL   = 1,
	FUSE_NOTIFY_INVAL_INODE = 2,
	FUSE_NOTIFY_INVAL_ENTRY = 3,
	FUSE_NOTIFY_STORE = 4,
	FUSE_NOTIFY_RETRIEVE = 5,
	FUSE_NOTIFY_DELETE = 6,
	FUSE_NOTIFY_CODE_MAX,
}

/* The read buffer is required to be at least 8k, but may be much larger */
const FUSE_MIN_READ_BUFFER: usize = 8192;

const FUSE_COMPAT_ENTRY_OUT_SIZE: usize = 120;

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseEntryOut {
	nodeid: u64,		/* Inode ID */
	generation: u64,	/* Inode generation: nodeid:gen must
					   be unique for the fs's lifetime */
	entry_valid: u64,	/* Cache timeout for the name */
	attr_valid: u64,	/* Cache timeout for the attributes */
	entry_valid_nsec: u32,
	attr_valid_nsec: u32,
	attr: FuseAttr,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseForgetIn {
	nlookup: u64,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseForgetOne {
	nodeid: u64,
	nlookup: u64,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseBatchForgetIn {
	count: u32,
	dummy: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseGetattrIn {
	getattr_flags: GetattrFlags,
	dummy: u32,
	fh: u64,
}

const FUSE_COMPAT_ATTR_OUT_SIZE: usize = 96;

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseAttrOut {
	attr_valid: u64,	/* Cache timeout for the attributes */
	attr_valid_nsec: u32,
	dummy: u32,
	attr: FuseAttr,
}

const FUSE_COMPAT_MKNOD_IN_SIZE: usize = 8;

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseMknodIn {
	mode: u32,
	rdev: u32,
	umask: u32,
	padding: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseMkdirIn {
	mode: u32,
	umask: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseRenameIn {
	newdir: u64,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseRename2In {
	newdir: u64,
	flags: u32,
	padding: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseLinkIn {
	oldnodeid: u64,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseSetattrIn {
	valid: ValidBitmasks,
	padding: u32,
	fh: u64,
	size: u64,
	lock_owner: u64,
	atime: u64,
	mtime: u64,
	ctime: u64,
	atimensec: u32,
	mtimensec: u32,
	ctimensec: u32,
	mode: u32,
	unused4: u32,
	uid: u32,
	gid: u32,
	unused5: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseOpenIn {
	flags: OpenFlags,
	unused: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseCreateIn {
	flags: u32,
	mode: u32,
	umask: u32,
	padding: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseOpenOut {
	fh: u64,
	open_flags: OpenFlags,
	padding: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseReleaseIn {
	fh: u64,
	flags: u32,
	release_flags: ReleaseFlags,
	lock_owner: u64,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseFlushIn {
	fh: u64,
	unused: u32,
	padding: u32,
	lock_owner: u64,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseReadIn {
	fh: u64,
	offset: u64,
	size: u32,
	read_flags: ReadFlags,
	lock_owner: u64,
	flags: u32,
	padding: u32,
}

const FUSE_COMPAT_WRITE_IN_SIZE: usize = 24;

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseWriteIn {
	fh: u64,
	offset: u64,
	size: u32,
	write_flags: WriteFlags,
	lock_owner: u64,
	flags: u32,
	padding: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseWriteOut {
	size: u32,
	padding: u32,
}

const FUSE_COMPAT_STATFS_SIZE: usize = 48;

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseStatfsOut {
	st: FuseKstatfs,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseFsyncIn {
	fh: u64,
	fsync_flags: u32,
	padding: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseSetxattrIn {
	size: u32,
	flags: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseGetxattrIn {
	size: u32,
	padding: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseGetxattrOut {
	size: u32,
	padding: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseLkIn {
	fh: u64,
	owner: u64,
	lk: FuseFileLock,
	lk_flags: u32,
	padding: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseLkOut {
	lk: FuseFileLock,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseAccessIn {
	mask: u32,
	padding: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseInitIn {
	major: u32,
	minor: u32,
	max_readahead: u32,
	flags: InitFlags,
}

const FUSE_COMPAT_INIT_OUT_SIZE: usize = 8;
const FUSE_COMPAT_22_INIT_OUT_SIZE: usize = 24;

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseInitOut {
	major: u32,
	minor: u32,
	max_readahead: u32,
	flags: InitFlags,
	max_background: u16,
	congestion_threshold: u16,
	max_write: u32,
	time_gran: u32,
	unused: [u32; 9],
}

const CUSE_INIT_INFO_MAX: usize = 4096;

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct CuseInitIn {
	major: u32,
	minor: u32,
	unused: u32,
	flags: CuseInitFlags,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct CuseInitOut {
	major: u32,
	minor: u32,
	unused: u32,
	flags: CuseInitFlags,
	max_read: u32,
	max_write: u32,
	dev_major: u32,		/* chardev major */
	dev_minor: u32,		/* chardev minor */
	spare: [u32; 10],
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseInterruptIn {
	unique: u64,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseBmapIn {
	block: u64,
	blocksize: u32,
	padding: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseBmapOut {
	block: u64,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseIoctlIn {
	fh: u64,
	flags: IoctlFlags,
	cmd: u32,
	arg: u64,
	in_size: u32,
	out_size: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseIoctlIovec {
	base: u64,
	len: u64,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseIoctlOut {
	result: i32,
	flags: IoctlFlags,
	in_iovs: u32,
	out_iovs: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FusePollIn {
	fh: u64,
	kh: u64,
	flags: u32,
	events: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FusePollOut {
	revents: u32,
	padding: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseNotifyPollWakeupOut {
	kh: u64,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseFallocateIn {
	fh: u64,
	offset: u64,
	length: u64,
	mode: u32,
	padding: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseInHeader {
	len: u32,
	opcode: u32,
	unique: u64,
	nodeid: u64,
	uid: u32,
	gid: u32,
	pid: u32,
	padding: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseOutHeader {
	len: u32,
	error: i32,
	unique: u64,
}

// #[repr(C)]
// #[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseDirent {
	ino: u64,
	off: u64,
	namelen: u32,
	types: u32, //TODO: type
	name: [char], //TODO: char name[];
}

// const FUSE_NAME_OFFSET: usize = offsetof(struct fuse_dirent, name);
// const FUSE_DIRENT_ALIGN(x): usize = \;
// 	(((x) + sizeof(uint64_t) - 1) & ~(sizeof(uint64_t) - 1))
// const FUSE_DIRENT_SIZE(d): usize = \;
// 	FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + (d)->namelen)

struct FuseDirentplus {
	entry_out: FuseEntryOut,
	dirent: FuseDirent,
}

// const FUSE_NAME_OFFSET_DIRENTPLUS: usize = \;
// 	offsetof(struct fuse_direntplus, dirent.name)
// const FUSE_DIRENTPLUS_SIZE(d): usize = \;
// 	FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET_DIRENTPLUS + (d)->dirent.namelen)

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseNotifyInvalInodeOut {
	ino: u64,
	off: i64,
	len: i64,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseNotifyInvalEntryOut {
	parent: u64,
	namelen: u32,
	padding: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseNotifyDeleteOut {
	parent: u64,
	child: u64,
	namelen: u32,
	padding: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseNotifyStoreOut {
	nodeid: u64,
	offset: u64,
	size: u32,
	padding: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseNotifyRetrieveOut {
	notify_unique: u64,
	nodeid: u64,
	offset: u64,
	size: u32,
	padding: u32,
}

/* Matches the size of fuse_write_in */
#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseNotifyRetrieveIn {
	dummy1: u64,
	offset: u64,
	size: u32,
	dummy2: u32,
	dummy3: u64,
	dummy4: u64,
}

/* Device ioctls: */
// const FUSE_DEV_IOC_CLONE: usize = _IOR(229, 0, uint32_t);

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseLseekIn {
	fh: u64,
	offset: u64,
	whence: u32,
	padding: u32,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Pod)]
pub struct FuseLseekOut {
	offset: u64,
}

