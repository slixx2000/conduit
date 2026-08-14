//! WinFsp backend.
//!
//! Read path: every `read` callback becomes an `FsClient::read_range` round trip
//! (bounded by the protocol's read cap); directory listings fill WinFsp's per-handle
//! `DirBuffer`. Metadata is cached briefly on our side (`STAT_TTL`) *and* by the
//! kernel (`file_info_timeout`), which keeps Explorer responsive without letting the
//! view go stale for long.
//!
//! Write path (`docs/PROTOCOL.md` §4): a file created in the mount spools into a
//! local temp file; when the handle closes, the spool is handed to the app's
//! `WriteHandler`, which ships it with the ordinary chunked transfer engine. In-place
//! overwrite of an existing remote file is refused (v1) — copies of new names work,
//! which is what "copy a file onto the drive" does.

use std::collections::HashMap;
use std::ffi::c_void;
use std::io::{Read, Seek, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use conduit_core::{FsClient, FsEntryKind, MAX_FS_READ_BYTES};
use tokio::runtime::Handle;
use windows::Win32::Foundation::{
    STATUS_ACCESS_DENIED, STATUS_DIRECTORY_NOT_EMPTY, STATUS_END_OF_FILE,
    STATUS_OBJECT_NAME_NOT_FOUND,
};
use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_DIRECTORY};
use winfsp::filesystem::{
    DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo,
    WideNameInfo,
};

use winfsp::host::{FileSystemHost, VolumeParams};
use winfsp::U16CStr;

use crate::{Error, MountOptions, Result, WriteHandler};

/// `FILE_DIRECTORY_FILE` create option: the caller wants a directory.
const CREATE_OPT_DIRECTORY: u32 = 0x0000_0001;

/// How long our own stat cache is trusted.
const STAT_TTL: Duration = Duration::from_secs(2);

/// Kernel-side metadata cache (ms) — WinFsp answers repeat stats itself within this.
const FILE_INFO_TIMEOUT_MS: u32 = 1000;

/// Seconds between the Unix and Windows (1601) epochs.
const UNIX_TO_FILETIME_SECS: u64 = 11_644_473_600;

fn filetime(unix_secs: u64) -> u64 {
    (unix_secs + UNIX_TO_FILETIME_SECS) * 10_000_000
}

pub struct ConduitFs {
    client: FsClient,
    rt: Handle,
    on_write: WriteHandler,
    spool_dir: PathBuf,
    spool_counter: AtomicU64,
    stat_cache: Mutex<HashMap<String, (Instant, conduit_core::FsAttr)>>,
    volume_label: String,
}

pub enum FileHandle {
    Remote {
        rel: String,
        is_dir: bool,
        dir_buffer: DirBuffer,
    },
    /// A file being written into the mount, spooled locally until its handle closes.
    Spool {
        name: String,
        path: PathBuf,
        file: Mutex<std::fs::File>,
        written: AtomicBool,
        cancelled: AtomicBool,
        shipped: AtomicBool,
    },
}

impl ConduitFs {
    /// Windows path (`\dir\file`) → share-relative path (`dir/file`).
    fn to_rel(name: &U16CStr) -> winfsp::Result<String> {
        let s = name.to_string_lossy();
        let trimmed = s.trim_start_matches('\\');
        if trimmed.contains(':') {
            // Alternate data streams are not a thing on this volume.
            return Err(STATUS_OBJECT_NAME_NOT_FOUND.into());
        }
        Ok(trimmed.replace('\\', "/"))
    }

    fn stat(&self, rel: &str) -> winfsp::Result<conduit_core::FsAttr> {
        if let Some((at, attr)) = self.stat_cache.lock().expect("lock").get(rel) {
            if at.elapsed() < STAT_TTL {
                return Ok(*attr);
            }
        }
        match self.rt.block_on(self.client.stat(rel)) {
            Ok(attr) => {
                self.stat_cache
                    .lock()
                    .expect("lock")
                    .insert(rel.to_string(), (Instant::now(), attr));
                Ok(attr)
            }
            Err(_) => Err(STATUS_OBJECT_NAME_NOT_FOUND.into()),
        }
    }

    fn invalidate(&self) {
        self.stat_cache.lock().expect("lock").clear();
    }

    fn fill(attr: &conduit_core::FsAttr, info: &mut FileInfo) {
        let dir = attr.kind == FsEntryKind::Dir;
        info.file_attributes = if dir {
            FILE_ATTRIBUTE_DIRECTORY.0
        } else {
            FILE_ATTRIBUTE_ARCHIVE.0
        };
        info.file_size = attr.size;
        info.allocation_size = attr.size.div_ceil(4096) * 4096;
        let t = filetime(attr.modified_unix);
        info.creation_time = t;
        info.last_access_time = t;
        info.last_write_time = t;
        info.change_time = t;
        info.index_number = 0;
        info.hard_links = 0;
        info.ea_size = 0;
        info.reparse_tag = 0;
    }

    fn fill_spool(file: &std::fs::File, info: &mut FileInfo) {
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        info.file_attributes = FILE_ATTRIBUTE_ARCHIVE.0;
        info.file_size = len;
        info.allocation_size = len.div_ceil(4096) * 4096;
        let now = filetime(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );
        info.creation_time = now;
        info.last_access_time = now;
        info.last_write_time = now;
        info.change_time = now;
        info.index_number = 0;
        info.hard_links = 0;
        info.ea_size = 0;
        info.reparse_tag = 0;
    }
}

impl FileSystemContext for ConduitFs {
    type FileContext = FileHandle;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        _security_descriptor: Option<&mut [c_void]>,
        _reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        let rel = Self::to_rel(file_name)?;
        let attr = self.stat(&rel)?;
        Ok(FileSecurity {
            reparse: false,
            sz_security_descriptor: 0,
            attributes: if attr.kind == FsEntryKind::Dir {
                FILE_ATTRIBUTE_DIRECTORY.0
            } else {
                FILE_ATTRIBUTE_ARCHIVE.0
            },
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        _create_options: u32,
        _granted_access: u32,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let rel = Self::to_rel(file_name)?;
        let attr = self.stat(&rel)?;
        Self::fill(&attr, file_info.as_mut());
        Ok(FileHandle::Remote {
            is_dir: attr.kind == FsEntryKind::Dir,
            rel,
            dir_buffer: DirBuffer::new(),
        })
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: u32,
        _file_attributes: u32,
        _security_descriptor: Option<&[c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let rel = Self::to_rel(file_name)?;
        if rel.is_empty() {
            return Err(STATUS_ACCESS_DENIED.into());
        }

        if create_options & CREATE_OPT_DIRECTORY != 0 {
            self.rt
                .block_on(self.client.mkdir(&rel))
                .map_err(|_| STATUS_ACCESS_DENIED)?;
            self.invalidate();
            let attr = self.stat(&rel)?;
            Self::fill(&attr, file_info.as_mut());
            return Ok(FileHandle::Remote {
                rel,
                is_dir: true,
                dir_buffer: DirBuffer::new(),
            });
        }

        // New file: spool locally; it ships to the peer when the handle closes.
        let name = rel.rsplit('/').next().unwrap_or(&rel).to_string();
        let spool = self
            .spool_dir
            .join(self.spool_counter.fetch_add(1, Ordering::Relaxed).to_string());
        std::fs::create_dir_all(&spool).map_err(|_| STATUS_ACCESS_DENIED)?;
        let path = spool.join(&name);
        let file = std::fs::File::create(&path).map_err(|_| STATUS_ACCESS_DENIED)?;
        Self::fill_spool(&file, file_info.as_mut());
        Ok(FileHandle::Spool {
            name,
            path,
            file: Mutex::new(file),
            written: AtomicBool::new(false),
            cancelled: AtomicBool::new(false),
            shipped: AtomicBool::new(false),
        })
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<u32> {
        match context {
            FileHandle::Remote { rel, .. } => {
                let want = (buffer.len() as u32).min(MAX_FS_READ_BYTES);
                let data = self
                    .rt
                    .block_on(self.client.read_range(rel, offset, want))
                    .map_err(|_| STATUS_END_OF_FILE)?;
                if data.is_empty() && !buffer.is_empty() {
                    return Err(STATUS_END_OF_FILE.into());
                }
                buffer[..data.len()].copy_from_slice(&data);
                Ok(data.len() as u32)
            }
            FileHandle::Spool { file, .. } => {
                let mut file = file.lock().expect("lock");
                file.seek(std::io::SeekFrom::Start(offset))
                    .map_err(|_| STATUS_END_OF_FILE)?;
                let n = file.read(buffer).map_err(|_| STATUS_END_OF_FILE)?;
                if n == 0 && !buffer.is_empty() {
                    return Err(STATUS_END_OF_FILE.into());
                }
                Ok(n as u32)
            }
        }
    }

    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        _constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<u32> {
        match context {
            FileHandle::Remote { .. } => Err(STATUS_ACCESS_DENIED.into()),
            FileHandle::Spool { file, written, .. } => {
                let mut file = file.lock().expect("lock");
                let at = if write_to_eof {
                    file.metadata().map(|m| m.len()).unwrap_or(0)
                } else {
                    offset
                };
                file.seek(std::io::SeekFrom::Start(at))
                    .map_err(|_| STATUS_ACCESS_DENIED)?;
                file.write_all(buffer).map_err(|_| STATUS_ACCESS_DENIED)?;
                written.store(true, Ordering::Release);
                Self::fill_spool(&file, file_info);
                Ok(buffer.len() as u32)
            }
        }
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        _set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        match context {
            FileHandle::Remote { .. } => Err(STATUS_ACCESS_DENIED.into()),
            FileHandle::Spool { file, written, .. } => {
                let file = file.lock().expect("lock");
                file.set_len(new_size).map_err(|_| STATUS_ACCESS_DENIED)?;
                written.store(true, Ordering::Release);
                Self::fill_spool(&file, file_info);
                Ok(())
            }
        }
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        match context {
            FileHandle::Remote { rel, .. } => {
                let attr = self.stat(rel)?;
                Self::fill(&attr, file_info);
                Ok(())
            }
            FileHandle::Spool { file, .. } => {
                Self::fill_spool(&file.lock().expect("lock"), file_info);
                Ok(())
            }
        }
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        pattern: Option<&U16CStr>,
        marker: DirMarker,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        let FileHandle::Remote {
            rel, dir_buffer, ..
        } = context
        else {
            return Err(STATUS_ACCESS_DENIED.into());
        };

        // The pattern is passed through to the filesystem and it must filter —
        // `del X:\name` and `dir X:\*.ext` come through here as patterned queries.
        if let Some(pattern) = pattern {
            let pattern = pattern.to_string_lossy();
            let entries = self
                .rt
                .block_on(self.client.list_dir(rel))
                .map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
            let after_marker = marker.inner_as_cstr().map(|m| m.to_string_lossy());

            let mut cursor = 0u32;
            let mut dir_info = DirInfo::<255>::new();
            for entry in entries {
                if let Some(after) = &after_marker {
                    // Entries are served sorted; resume strictly after the marker.
                    if entry.name.as_str() <= after.as_str() {
                        continue;
                    }
                }
                if !wildcard_match(&pattern, &entry.name) {
                    continue;
                }
                dir_info.reset();
                // set_name would store a trailing NUL inside the counted name, which
                // breaks the kernel's wildcard matching; hand it an unterminated
                // UTF-16 slice instead.
                let wide: Vec<u16> = entry.name.encode_utf16().collect();
                dir_info.set_name_raw(wide.as_slice())?;
                Self::fill(
                    &conduit_core::FsAttr {
                        kind: entry.kind,
                        size: entry.size,
                        modified_unix: entry.modified_unix,
                    },
                    dir_info.file_info_mut(),
                );
                if !dir_info.append_to_buffer(buffer, &mut cursor) {
                    return Ok(cursor); // buffer full; the marker resumes us
                }
            }
            DirInfo::<255>::finalize_buffer(buffer, &mut cursor);
            return Ok(cursor);
        }

        if marker.is_none() {
            if let Ok(lock) = dir_buffer.acquire(true, None) {
                let entries = self
                    .rt
                    .block_on(self.client.list_dir(rel))
                    .map_err(|_| STATUS_OBJECT_NAME_NOT_FOUND)?;
                let mut dir_info = DirInfo::<255>::new();
                for entry in entries {
                    dir_info.reset();
                    // set_name would store a trailing NUL inside the counted name, which
                // breaks the kernel's wildcard matching; hand it an unterminated
                // UTF-16 slice instead.
                let wide: Vec<u16> = entry.name.encode_utf16().collect();
                dir_info.set_name_raw(wide.as_slice())?;
                    Self::fill(
                        &conduit_core::FsAttr {
                            kind: entry.kind,
                            size: entry.size,
                            modified_unix: entry.modified_unix,
                        },
                        dir_info.file_info_mut(),
                    );
                    lock.write(&mut dir_info)?;
                }
            }
        }
        Ok(dir_buffer.read(marker, buffer))
    }

    fn rename(
        &self,
        _context: &Self::FileContext,
        file_name: &U16CStr,
        new_file_name: &U16CStr,
        _replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        let from = Self::to_rel(file_name)?;
        let to = Self::to_rel(new_file_name)?;
        self.rt
            .block_on(self.client.rename(&from, &to))
            .map_err(|_| STATUS_ACCESS_DENIED)?;
        self.invalidate();
        Ok(())
    }

    fn set_delete(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        delete_file: bool,
    ) -> winfsp::Result<()> {
        if !delete_file {
            return Ok(());
        }
        match context {
            // Directory deletion needs a recursive protocol op we don't have yet.
            FileHandle::Remote { is_dir: true, .. } => Err(STATUS_DIRECTORY_NOT_EMPTY.into()),
            _ => Ok(()),
        }
    }

    /// Cleanup fires deterministically when the last user handle closes; `close`
    /// can be deferred indefinitely by the kernel's file-object cache, so shipping
    /// a finished spool file to the peer happens *here*.
    fn cleanup(&self, context: &Self::FileContext, _file_name: Option<&U16CStr>, flags: u32) {
        let delete = flags & (winfsp::constants::FspCleanupFlags::FspCleanupDelete as u32) != 0;
        match context {
            FileHandle::Remote {
                rel, is_dir: false, ..
            } if delete => {
                let _ = self.rt.block_on(self.client.unlink(rel));
                self.invalidate();
            }
            FileHandle::Remote { .. } => {}
            FileHandle::Spool { cancelled, .. } if delete => {
                // Deleted before it ever shipped: forget it.
                cancelled.store(true, Ordering::Release);
            }
            FileHandle::Spool {
                name,
                path,
                written,
                cancelled,
                shipped,
                ..
            } => {
                if written.load(Ordering::Acquire)
                    && !cancelled.load(Ordering::Acquire)
                    && !shipped.swap(true, Ordering::AcqRel)
                {
                    (self.on_write)(name.clone(), path.clone());
                    self.invalidate();
                }
            }
        }
    }

    fn close(&self, context: Self::FileContext) {
        if let FileHandle::Spool {
            path,
            shipped,
            cancelled,
            ..
        } = context
        {
            // Never shipped (empty or deleted): the spool file is garbage.
            if cancelled.load(Ordering::Acquire) || !shipped.load(Ordering::Acquire) {
                let _ = std::fs::remove_file(&path);
                if let Some(parent) = path.parent() {
                    let _ = std::fs::remove_dir(parent);
                }
            }
        }
    }

    fn get_volume_info(&self, out_volume_info: &mut winfsp::filesystem::VolumeInfo) -> winfsp::Result<()> {
        // The volume is a window onto the peer; sizes are nominal.
        out_volume_info.total_size = 1 << 40;
        out_volume_info.free_size = 512 << 30;
        out_volume_info.set_volume_label(&self.volume_label);
        Ok(())
    }
}

/// Case-insensitive Win32-style wildcard match. The kernel encodes DOS wildcards as
/// `<` (DOS_STAR), `>` (DOS_QM), `"` (DOS_DOT); they are folded to their plain
/// equivalents — exact DOS 8.3 edge semantics are not worth carrying here.
fn wildcard_match(pattern: &str, name: &str) -> bool {
    fn inner(p: &[char], n: &[char]) -> bool {
        match (p.first(), n.first()) {
            (None, None) => true,
            (Some('*'), _) => {
                inner(&p[1..], n) || (!n.is_empty() && inner(p, &n[1..]))
            }
            (Some('?'), Some(_)) => inner(&p[1..], &n[1..]),
            // A trailing '?'/'.' may match nothing ("ab?" matches "ab").
            (Some('?'), None) | (Some('.'), None) => inner(&p[1..], n),
            (Some(pc), Some(nc)) if pc == nc => inner(&p[1..], &n[1..]),
            _ => false,
        }
    }
    let pattern: Vec<char> = pattern
        .chars()
        .map(|c| match c {
            '<' => '*',
            '>' => '?',
            '"' => '.',
            c => c.to_ascii_lowercase(),
        })
        .collect();
    let name: Vec<char> = name.chars().map(|c| c.to_ascii_lowercase()).collect();
    inner(&pattern, &name)
}

pub fn mount(
    client: FsClient,
    rt: Handle,
    mountpoint: &str,
    options: MountOptions,
    on_write: WriteHandler,
) -> Result<crate::MountHandle> {
    let mountpoint = mountpoint.to_string();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<()>>();

    // The host is not Send: it lives its whole life on this thread.
    let thread_mountpoint = mountpoint.clone();
    let thread = std::thread::Builder::new()
        .name("conduit-mount".into())
        .spawn(move || {
            let init = match winfsp::winfsp_init() {
                Ok(init) => init,
                Err(_) => {
                    let _ = ready_tx.send(Err(Error::DriverMissing {
                        driver: crate::REQUIRED_DRIVER,
                    }));
                    return;
                }
            };
            let _keep = init;

            let mut volume_params = VolumeParams::new();
            volume_params
                .filesystem_name("Conduit")
                .sector_size(4096)
                .sectors_per_allocation_unit(1)
                .file_info_timeout(FILE_INFO_TIMEOUT_MS)
                .case_preserved_names(true)
                .case_sensitive_search(false)
                .unicode_on_disk(true);

            let spool_dir = std::env::temp_dir().join("conduit-spool");
            let context = ConduitFs {
                client,
                rt,
                on_write,
                spool_dir,
                spool_counter: AtomicU64::new(1),
                stat_cache: Mutex::new(HashMap::new()),
                volume_label: options.volume_label,
            };

            let mut host = match FileSystemHost::<ConduitFs>::new(volume_params, context) {
                Ok(host) => host,
                Err(e) => {
                    let _ = ready_tx.send(Err(Error::Mount(format!(
                        "creating the filesystem host failed: {e}"
                    ))));
                    return;
                }
            };
            if let Err(e) = host.mount(thread_mountpoint.as_str()) {
                let _ = ready_tx.send(Err(Error::Mount(format!(
                    "mounting at {thread_mountpoint} failed: {e}"
                ))));
                return;
            }
            if let Err(e) = host.start() {
                let _ = ready_tx.send(Err(Error::Mount(format!(
                    "starting the filesystem dispatcher failed: {e}"
                ))));
                return;
            }
            let _ = ready_tx.send(Ok(()));

            // Parked until unmount (or the handle is dropped).
            let _ = stop_rx.recv();
            host.unmount();
            host.stop();
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
    use super::wildcard_match;

    #[test]
    fn wildcards_match_like_win32() {
        assert!(wildcard_match("renamed.dat", "renamed.dat"));
        assert!(wildcard_match("RENAMED.DAT", "renamed.dat"), "case-insensitive");
        assert!(wildcard_match("*.dat", "renamed.dat"));
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("r?named.*", "renamed.dat"));
        assert!(wildcard_match("*.*", "a.b"));
        assert!(!wildcard_match("*.txt", "renamed.dat"));
        assert!(!wildcard_match("other.dat", "renamed.dat"));
        // Kernel-encoded DOS wildcards fold to their plain forms.
        assert!(wildcard_match("<\"dat", "renamed.dat"));
    }
}
