//! FUSE backend (Linux), the counterpart of `windows_mount.rs`.
//!
//! Same shape as the WinFsp backend: reads are `FsClient::read_range` round trips,
//! metadata is cached briefly on our side (`STAT_TTL`) and by the kernel (`TTL`), and
//! a file created in the mount spools into a local temp file that is handed to the
//! app's `WriteHandler` on `release` — the ordinary chunked transfer engine ships it
//! (`docs/PROTOCOL.md` §4). Writing *into* an existing remote file is refused; copies
//! of new names work, which is what "copy a file onto the drive" does.
//!
//! FUSE talks in inodes, the protocol talks in share-relative paths, so [`Inodes`]
//! keeps the two in sync. Paths are interned on lookup and never recycled.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use conduit_core::{FsAttr, FsClient, FsEntryKind, MAX_FS_READ_BYTES};
use fuser::{
    Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags, Generation, INodeNo,
    LockOwner, MountOption, OpenFlags, RenameFlags, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyStatfs, ReplyWrite, Request,
    TimeOrNow, WriteFlags,
};
use tokio::runtime::Handle;

use crate::{Error, MountOptions, Result, WriteHandler};

/// How long the kernel may trust an entry/attr reply.
const TTL: Duration = Duration::from_secs(1);

/// How long our own stat cache is trusted.
const STAT_TTL: Duration = Duration::from_secs(2);

/// Nominal volume geometry — the mount is a window onto the peer, not a disk.
const BLOCK_SIZE: u32 = 4096;
const NOMINAL_BLOCKS: u64 = (1 << 40) / BLOCK_SIZE as u64;
const NOMINAL_FREE: u64 = (512 << 30) / BLOCK_SIZE as u64;

/// Path ⇄ inode table. The root (`INodeNo::ROOT`) is the share root, `""`.
struct Inodes {
    by_ino: HashMap<u64, String>,
    by_path: HashMap<String, u64>,
    next: u64,
}

impl Inodes {
    fn new() -> Self {
        let root = u64::from(INodeNo::ROOT);
        Self {
            by_ino: HashMap::from([(root, String::new())]),
            by_path: HashMap::from([(String::new(), root)]),
            next: root + 1,
        }
    }

    fn path(&self, ino: u64) -> Option<&str> {
        self.by_ino.get(&ino).map(String::as_str)
    }

    /// Inode for `path`, allocating one the first time it is seen.
    fn intern(&mut self, path: &str) -> u64 {
        if let Some(ino) = self.by_path.get(path) {
            return *ino;
        }
        let ino = self.next;
        self.next += 1;
        self.by_ino.insert(ino, path.to_string());
        self.by_path.insert(path.to_string(), ino);
        ino
    }

    /// Drop a mapping (the path is gone: unlinked, or renamed away). Inodes of
    /// *children* of a renamed directory are left stale on purpose — they resolve to
    /// a path the peer no longer has, so they fail with ENOENT and the kernel
    /// re-looks-up through the new parent. Tracking subtrees is not worth it.
    fn forget(&mut self, path: &str) {
        if let Some(ino) = self.by_path.remove(path) {
            self.by_ino.remove(&ino);
        }
    }
}

/// A file being written into the mount, spooled locally until its handle closes.
struct Spool {
    /// Leaf name as the user named it in the mount — what the peer will receive.
    /// Only the leaf: a file created inside a subdirectory of the mount still lands
    /// in the peer's share root, because `WriteHandler` (and the transfer engine
    /// behind it) ships a single file into the inbox. The WinFsp backend does the
    /// same; placing writes into subdirectories needs a destination path on the
    /// send side, not a mount-backend change.
    name: String,
    /// Local spool file.
    path: PathBuf,
    file: std::fs::File,
    written: bool,
}

pub struct ConduitFuse {
    client: FsClient,
    rt: Handle,
    on_write: WriteHandler,
    spool_dir: PathBuf,
    spool_counter: AtomicU64,
    inodes: Mutex<Inodes>,
    stat_cache: Mutex<HashMap<String, (Instant, FsAttr)>>,
    // ponytail: one lock over all in-flight spools; split per-handle if concurrent
    // copies onto the drive ever matter (writes are local disk, shipping is async).
    spools: Mutex<HashMap<u64, Spool>>,
}

impl ConduitFuse {
    fn path_of(&self, ino: INodeNo) -> std::result::Result<String, Errno> {
        self.inodes
            .lock()
            .expect("lock")
            .path(u64::from(ino))
            .map(str::to_string)
            .ok_or(Errno::ENOENT)
    }

    /// Share-relative path of `name` inside directory inode `parent`.
    fn child_of(&self, parent: INodeNo, name: &OsStr) -> std::result::Result<String, Errno> {
        let name = name.to_str().ok_or(Errno::ENOENT)?;
        if name.is_empty() || name.contains('/') {
            return Err(Errno::EINVAL);
        }
        let parent = self.path_of(parent)?;
        Ok(if parent.is_empty() {
            name.to_string()
        } else {
            format!("{parent}/{name}")
        })
    }

    fn intern(&self, path: &str) -> u64 {
        self.inodes.lock().expect("lock").intern(path)
    }

    fn stat(&self, rel: &str) -> std::result::Result<FsAttr, Errno> {
        if let Some((at, attr)) = self.stat_cache.lock().expect("lock").get(rel) {
            if at.elapsed() < STAT_TTL {
                return Ok(*attr);
            }
        }
        let attr = self
            .rt
            .block_on(self.client.stat(rel))
            .map_err(|_| Errno::ENOENT)?;
        self.stat_cache
            .lock()
            .expect("lock")
            .insert(rel.to_string(), (Instant::now(), attr));
        Ok(attr)
    }

    fn invalidate(&self) {
        self.stat_cache.lock().expect("lock").clear();
    }

    /// Attributes of a spooling file, read from the local spool (its size changes as
    /// the copy runs, so it must never come from the peer).
    fn spool_attr(&self, ino: u64, req: &Request) -> Option<FileAttr> {
        let spools = self.spools.lock().expect("lock");
        let spool = spools.get(&ino)?;
        let size = spool.file.metadata().map(|m| m.len()).unwrap_or(0);
        Some(file_attr(
            ino,
            &FsAttr {
                kind: FsEntryKind::File,
                size,
                modified_unix: now_unix(),
            },
            req,
        ))
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn file_attr(ino: u64, attr: &FsAttr, req: &Request) -> FileAttr {
    let dir = attr.kind == FsEntryKind::Dir;
    let time = UNIX_EPOCH + Duration::from_secs(attr.modified_unix);
    FileAttr {
        ino: INodeNo(ino),
        size: attr.size,
        blocks: attr.size.div_ceil(512),
        atime: time,
        mtime: time,
        ctime: time,
        crtime: time,
        kind: if dir {
            FileType::Directory
        } else {
            FileType::RegularFile
        },
        perm: if dir { 0o755 } else { 0o644 },
        nlink: if dir { 2 } else { 1 },
        // The mount belongs to whoever is looking at it: there are no remote uids.
        uid: req.uid(),
        gid: req.gid(),
        rdev: 0,
        blksize: BLOCK_SIZE,
        flags: 0,
    }
}

impl Filesystem for ConduitFuse {
    fn lookup(&self, req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let rel = match self.child_of(parent, name) {
            Ok(rel) => rel,
            Err(e) => return reply.error(e),
        };
        let ino = self.intern(&rel);
        // A file still spooling is local-only; the peer has not seen it yet.
        if let Some(attr) = self.spool_attr(ino, req) {
            return reply.entry(&Duration::ZERO, &attr, Generation(0));
        }
        match self.stat(&rel) {
            Ok(attr) => reply.entry(&TTL, &file_attr(ino, &attr, req), Generation(0)),
            Err(e) => reply.error(e),
        }
    }

    fn getattr(&self, req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
        if let Some(attr) = self.spool_attr(u64::from(ino), req) {
            return reply.attr(&Duration::ZERO, &attr);
        }
        let rel = match self.path_of(ino) {
            Ok(rel) => rel,
            Err(e) => return reply.error(e),
        };
        match self.stat(&rel) {
            Ok(attr) => reply.attr(&TTL, &file_attr(u64::from(ino), &attr, req)),
            Err(e) => reply.error(e),
        }
    }

    /// Only truncation of a still-spooling file is honoured (`cp` truncates its
    /// destination); mode/owner/time changes are accepted as no-ops so copies do not
    /// fail on the trailing `chmod`/`utimensat`.
    #[allow(clippy::too_many_arguments)]
    fn setattr(
        &self,
        req: &Request,
        ino: INodeNo,
        _mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<TimeOrNow>,
        _mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<FileHandle>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<fuser::BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        let ino_n = u64::from(ino);
        {
            let mut spools = self.spools.lock().expect("lock");
            if let Some(spool) = spools.get_mut(&ino_n) {
                if let Some(size) = size {
                    if spool.file.set_len(size).is_err() {
                        return reply.error(Errno::EIO);
                    }
                    spool.written = true;
                }
            }
        }
        if let Some(attr) = self.spool_attr(ino_n, req) {
            return reply.attr(&Duration::ZERO, &attr);
        }
        if size.is_some() {
            return reply.error(Errno::EPERM); // no in-place remote truncate
        }
        let rel = match self.path_of(ino) {
            Ok(rel) => rel,
            Err(e) => return reply.error(e),
        };
        match self.stat(&rel) {
            Ok(attr) => reply.attr(&TTL, &file_attr(ino_n, &attr, req)),
            Err(e) => reply.error(e),
        }
    }

    fn read(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        size: u32,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyData,
    ) {
        let ino_n = u64::from(ino);
        {
            let mut spools = self.spools.lock().expect("lock");
            if let Some(spool) = spools.get_mut(&ino_n) {
                let mut buf = vec![0u8; size as usize];
                let read = spool
                    .file
                    .seek(SeekFrom::Start(offset))
                    .and_then(|_| read_filled(&mut spool.file, &mut buf));
                return match read {
                    Ok(n) => reply.data(&buf[..n]),
                    Err(_) => reply.error(Errno::EIO),
                };
            }
        }
        let rel = match self.path_of(ino) {
            Ok(rel) => rel,
            Err(e) => return reply.error(e),
        };
        match self
            .rt
            .block_on(self.client.read_range(&rel, offset, size.min(MAX_FS_READ_BYTES)))
        {
            Ok(data) => reply.data(&data),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        data: &[u8],
        _write_flags: WriteFlags,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        reply: ReplyWrite,
    ) {
        let mut spools = self.spools.lock().expect("lock");
        // Writing into an existing remote file would need a read-modify-write of the
        // whole file over the link; only freshly created files are writable (v1).
        let Some(spool) = spools.get_mut(&u64::from(ino)) else {
            return reply.error(Errno::EPERM);
        };
        let wrote = spool
            .file
            .seek(SeekFrom::Start(offset))
            .and_then(|_| spool.file.write_all(data));
        match wrote {
            Ok(()) => {
                spool.written = true;
                reply.written(data.len() as u32)
            }
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn create(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let rel = match self.child_of(parent, name) {
            Ok(rel) => rel,
            Err(e) => return reply.error(e),
        };
        let leaf = rel.rsplit('/').next().unwrap_or(&rel).to_string();
        let dir = self
            .spool_dir
            .join(self.spool_counter.fetch_add(1, Ordering::Relaxed).to_string());
        if std::fs::create_dir_all(&dir).is_err() {
            return reply.error(Errno::EIO);
        }
        let path = dir.join(&leaf);
        let Ok(file) = std::fs::File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
        else {
            return reply.error(Errno::EIO);
        };

        let ino = self.intern(&rel);
        self.spools.lock().expect("lock").insert(
            ino,
            Spool {
                name: leaf,
                path,
                file,
                written: false,
            },
        );
        let attr = file_attr(
            ino,
            &FsAttr {
                kind: FsEntryKind::File,
                size: 0,
                modified_unix: now_unix(),
            },
            req,
        );
        reply.created(
            &Duration::ZERO,
            &attr,
            Generation(0),
            FileHandle(0),
            FopenFlags::empty(),
        );
    }

    fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        let spooling = self.spools.lock().expect("lock").contains_key(&u64::from(ino));
        if !spooling && flags.acc_mode() != fuser::OpenAccMode::O_RDONLY {
            return reply.error(Errno::EPERM);
        }
        reply.opened(FileHandle(0), FopenFlags::empty());
    }

    fn flush(
        &self,
        _req: &Request,
        _ino: INodeNo,
        _fh: FileHandle,
        _lock_owner: LockOwner,
        reply: ReplyEmpty,
    ) {
        reply.ok();
    }

    fn fsync(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _datasync: bool,
        reply: ReplyEmpty,
    ) {
        let spools = self.spools.lock().expect("lock");
        match spools.get(&u64::from(ino)) {
            Some(spool) if spool.file.sync_all().is_err() => reply.error(Errno::EIO),
            _ => reply.ok(),
        }
    }

    /// The last handle on a spooled file closed: ship it to the peer. A file that was
    /// never written (or was deleted before closing) is just discarded.
    fn release(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let Some(spool) = self.spools.lock().expect("lock").remove(&u64::from(ino)) else {
            return reply.ok();
        };
        if spool.written {
            (self.on_write)(spool.name, spool.path);
            self.invalidate();
        } else {
            discard(&spool.path);
        }
        reply.ok();
    }

    fn readdir(
        &self,
        _req: &Request,
        ino: INodeNo,
        _fh: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        let rel = match self.path_of(ino) {
            Ok(rel) => rel,
            Err(e) => return reply.error(e),
        };
        let Ok(entries) = self.rt.block_on(self.client.list_dir(&rel)) else {
            return reply.error(Errno::EIO);
        };

        // "." and ".." keep `ls -a` and path resolution honest; the parent inode is
        // whatever the kernel already knows, so pointing it at ourselves is fine.
        let mut listing = vec![
            (u64::from(ino), FileType::Directory, ".".to_string()),
            (u64::from(ino), FileType::Directory, "..".to_string()),
        ];
        for entry in entries {
            let child = if rel.is_empty() {
                entry.name.clone()
            } else {
                format!("{rel}/{}", entry.name)
            };
            listing.push((
                self.intern(&child),
                match entry.kind {
                    FsEntryKind::Dir => FileType::Directory,
                    FsEntryKind::File => FileType::RegularFile,
                },
                entry.name,
            ));
        }

        for (i, (ino, kind, name)) in listing.into_iter().enumerate().skip(offset as usize) {
            // The offset is where to resume: the index *after* this entry.
            if reply.add(INodeNo(ino), i as u64 + 1, kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn mkdir(
        &self,
        req: &Request,
        parent: INodeNo,
        name: &OsStr,
        _mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let rel = match self.child_of(parent, name) {
            Ok(rel) => rel,
            Err(e) => return reply.error(e),
        };
        if self.rt.block_on(self.client.mkdir(&rel)).is_err() {
            return reply.error(Errno::EIO);
        }
        self.invalidate();
        let ino = self.intern(&rel);
        match self.stat(&rel) {
            Ok(attr) => reply.entry(&TTL, &file_attr(ino, &attr, req), Generation(0)),
            Err(e) => reply.error(e),
        }
    }

    fn unlink(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let rel = match self.child_of(parent, name) {
            Ok(rel) => rel,
            Err(e) => return reply.error(e),
        };
        let ino = self.intern(&rel);
        // Deleted before it ever shipped: forget the spool instead of asking the peer.
        if let Some(spool) = self.spools.lock().expect("lock").remove(&ino) {
            discard(&spool.path);
            self.inodes.lock().expect("lock").forget(&rel);
            return reply.ok();
        }
        if self.rt.block_on(self.client.unlink(&rel)).is_err() {
            return reply.error(Errno::EIO);
        }
        self.inodes.lock().expect("lock").forget(&rel);
        self.invalidate();
        reply.ok();
    }

    /// Removing a directory needs a protocol op the wire format does not have (the
    /// WinFsp backend refuses it too); create/rename/unlink cover the drive UX.
    fn rmdir(&self, _req: &Request, _parent: INodeNo, _name: &OsStr, reply: ReplyEmpty) {
        reply.error(Errno::EPERM);
    }

    fn rename(
        &self,
        _req: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        _flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let (from, to) = match (self.child_of(parent, name), self.child_of(newparent, newname)) {
            (Ok(from), Ok(to)) => (from, to),
            (Err(e), _) | (_, Err(e)) => return reply.error(e),
        };
        if self.rt.block_on(self.client.rename(&from, &to)).is_err() {
            return reply.error(Errno::EIO);
        }
        self.inodes.lock().expect("lock").forget(&from);
        self.invalidate();
        reply.ok();
    }

    fn statfs(&self, _req: &Request, _ino: INodeNo, reply: ReplyStatfs) {
        reply.statfs(
            NOMINAL_BLOCKS,
            NOMINAL_FREE,
            NOMINAL_FREE,
            0,
            0,
            BLOCK_SIZE,
            255,
            BLOCK_SIZE,
        );
    }
}

/// Read until the buffer is full or EOF — FUSE expects a short read only at EOF.
fn read_filled(file: &mut std::fs::File, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

fn discard(spool: &Path) {
    let _ = std::fs::remove_file(spool);
    if let Some(parent) = spool.parent() {
        let _ = std::fs::remove_dir(parent);
    }
}

pub fn mount(
    client: FsClient,
    rt: Handle,
    mountpoint: &str,
    options: MountOptions,
    on_write: WriteHandler,
) -> Result<crate::MountHandle> {
    if !Path::new("/dev/fuse").exists() {
        return Err(Error::DriverMissing {
            driver: crate::REQUIRED_DRIVER,
        });
    }
    // Unlike a Windows drive letter, a FUSE mountpoint is a directory that has to
    // exist. Creating it is friendlier than making the user mkdir first.
    std::fs::create_dir_all(mountpoint)?;

    let fs = ConduitFuse {
        client,
        rt,
        on_write,
        spool_dir: std::env::temp_dir().join("conduit-spool"),
        spool_counter: AtomicU64::new(1),
        inodes: Mutex::new(Inodes::new()),
        stat_cache: Mutex::new(HashMap::new()),
        spools: Mutex::new(HashMap::new()),
    };

    let mut config = Config::default();
    config.mount_options = vec![
        // Shows up as the source in `mount`/`df`, so the peer is named there.
        MountOption::FSName(options.volume_label),
        MountOption::Subtype("conduit".into()),
        MountOption::DefaultPermissions,
        MountOption::NoAtime,
    ];

    let mountpoint = mountpoint.to_string();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<()>>();

    // The session owns the FUSE fd; it lives on its own thread and is unmounted when
    // the handle says so, matching the WinFsp backend's lifecycle.
    let thread_mountpoint = mountpoint.clone();
    let thread = std::thread::Builder::new()
        .name("conduit-mount".into())
        .spawn(move || {
            let session = match fuser::spawn_mount(fs, &thread_mountpoint, &config) {
                Ok(session) => session,
                Err(e) => {
                    let _ = ready_tx.send(Err(Error::Mount(format!(
                        "mounting at {thread_mountpoint} failed: {e}"
                    ))));
                    return;
                }
            };
            let _ = ready_tx.send(Ok(()));
            let _ = stop_rx.recv();
            let _ = session.umount_and_join();
        })
        .map_err(Error::Io)?;

    match ready_rx.recv() {
        Ok(Ok(())) => Ok(crate::MountHandle {
            mountpoint,
            stop: Some(stop_tx),
            thread: Some(thread),
        }),
        Ok(Err(e)) => {
            let _ = thread.join();
            Err(e)
        }
        Err(_) => {
            let _ = thread.join();
            Err(Error::Mount("mount thread died before reporting".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Inodes;

    #[test]
    fn inodes_map_paths_both_ways() {
        let mut inodes = Inodes::new();
        assert_eq!(inodes.path(1), Some(""), "root is the share root");

        let a = inodes.intern("dir/a.txt");
        assert_eq!(inodes.intern("dir/a.txt"), a, "interning is stable");
        assert_ne!(inodes.intern("dir/b.txt"), a);
        assert_eq!(inodes.path(a), Some("dir/a.txt"));

        inodes.forget("dir/a.txt");
        assert_eq!(inodes.path(a), None);
        assert_ne!(inodes.intern("dir/a.txt"), a, "inodes are never recycled");
    }
}
