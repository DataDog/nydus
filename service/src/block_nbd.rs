// Copyright (C) 2023 Alibaba Cloud. All rights reserved.
//
// SPDX-License-Identifier: (Apache-2.0)

//! Export a RAFSv6 image as a block device through NBD(Network Block Device) protocol.
//!
//! The [Network Block Device](https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md)
//! is a Linux-originated lightweight block access protocol that allows one to export a block device
//! to a client. RAFSv6 images have an block address based encoding, so an RAFSv6 image can be
//! exposed as a block device. The [NbdService] exposes a RAFSv6 image as a block device based on
//! the Linux Network Block Device driver.

use std::any::Any;
use std::fs::{self, OpenOptions};
use std::io::{Error, ErrorKind, IoSlice, IoSliceMut, Read, Result, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream as StdUnixStream};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use bytes::{Buf, BufMut};
use mio::Waker;
use nix::mount::{mount, umount, MsFlags};
use nix::sys::socket::{recvmsg, sendmsg, ControlMessage, ControlMessageOwned, MsgFlags};
use nydus_api::{BlobCacheEntry, BuildTimeInfo, NbdConfig};
use nydus_storage::utils::alloc_buf;
use tokio::io::unix::AsyncFd;
use tokio::sync::broadcast::{channel, Sender};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio_uring::net::UnixStream;

use crate::blob_cache::{generate_blob_key, BlobCacheMgr};
use crate::block_device::BlockDevice;
use crate::daemon::{
    DaemonState, DaemonStateMachineContext, DaemonStateMachineInput, DaemonStateMachineSubscriber,
    NydusDaemon,
};
use crate::nbd_netlink::{DeviceConfig, NbdNetlink};
use crate::{Error as NydusError, Result as NydusResult};

const NBD_SET_SOCK: u32 = 0;
const NBD_SET_BLOCK_SIZE: u32 = 1;
const NBD_DO_IT: u32 = 3;
const NBD_CLEAR_SOCK: u32 = 4;
const NBD_SET_BLOCKS: u32 = 7;
//const NBD_DISCONNECT: u32 = 8;
const NBD_SET_TIMEOUT: u32 = 9;
const NBD_SET_FLAGS: u32 = 10;
const NBD_FLAG_HAS_FLAGS: u32 = 0x1;
const NBD_FLAG_READ_ONLY: u32 = 0x2;
const NBD_FLAG_CAN_MULTI_CONN: u32 = 0x100;
const NBD_CMD_READ: u32 = 0;
const NBD_CMD_DISC: u32 = 2;
const NBD_REQUEST_HEADER_SIZE: usize = 28;
const NBD_REQUEST_MAGIC: u32 = 0x25609513;
const NBD_REPLY_MAGIC: u32 = 0x67446698;
const NBD_OK: u32 = 0;
const NBD_EIO: u32 = 5;
const NBD_EINVAL: u32 = 22;
/// Seconds the kernel queues the requests of a device whose server died, waiting for a new
/// server to take it over.
const NBD_DEAD_CONN_TIMEOUT: u64 = 600;
/// Bytes of the requests a worker serves at the same time. The kernel bounds the number of
/// requests of a connection; this bounds their memory when they are large.
const NBD_MAX_INFLIGHT_BYTES: u32 = 128 << 20;
/// How long a handover waits for the workers to park, then for the new server to serve.
const NBD_HANDOVER_TIMEOUT: Duration = Duration::from_secs(30);

fn nbd_ioctl(fd: RawFd, cmd: u32, arg: u64) -> nix::Result<libc::c_int> {
    let code = nix::request_code_none!(0xab, cmd);
    unsafe { nix::convert_ioctl_res!(libc::ioctl(fd, code, arg)) }
}

/// Network Block Device server to expose RAFSv6 images as block devices.
pub struct NbdService {
    active: Arc<AtomicBool>,
    blob_id: String,
    cache_mgr: Arc<BlobCacheMgr>,
    // The device configured through ioctl. A device configured through netlink is never opened:
    // opening an unconfigured device makes the kernel consider it in use.
    nbd_dev: Option<fs::File>,
    // Configuration of a device configured through netlink instead of ioctl: the device
    // outlives the server, the kernel queues its requests once the server is gone, until a new
    // server takes it over with new connections.
    netlink: Option<DeviceConfig>,
    // Kernel ends of the connections of the workers, until handed to the kernel through netlink.
    kernel_socks: Mutex<Vec<StdUnixStream>>,
    // Set while the workers park for a new server to take their connections over.
    parking: Arc<AtomicBool>,
    sender: Arc<Sender<u32>>,
}

impl NbdService {
    /// Create a new instance of [NbdService] to expose a RAFSv6 image as a block device.
    ///
    /// It opens the NBD device at `nbd_path` and initialize it according to information from
    /// the block device composed from a RAFSv6 image. The caller needs to ensure that the NBD
    /// device is available.
    pub fn new(device: Arc<BlockDevice>, nbd_path: String) -> Result<Self> {
        // Initialize the NBD device: set block size, block count and flags.
        let nbd_dev = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&nbd_path)
            .inspect_err(|_e| {
                error!("block_nbd: failed to open NBD device {}", nbd_path);
            })?;
        nbd_ioctl(nbd_dev.as_raw_fd(), NBD_SET_BLOCK_SIZE, device.block_size())?;
        nbd_ioctl(nbd_dev.as_raw_fd(), NBD_SET_BLOCKS, device.blocks() as u64)?;
        nbd_ioctl(nbd_dev.as_raw_fd(), NBD_SET_TIMEOUT, 60)?;
        nbd_ioctl(nbd_dev.as_raw_fd(), NBD_CLEAR_SOCK, 0)?;
        nbd_ioctl(
            nbd_dev.as_raw_fd(),
            NBD_SET_FLAGS,
            (NBD_FLAG_HAS_FLAGS | NBD_FLAG_READ_ONLY | NBD_FLAG_CAN_MULTI_CONN) as u64,
        )?;

        let (sender, _receiver) = channel(4);

        Ok(NbdService {
            active: Arc::new(AtomicBool::new(true)),
            blob_id: device.meta_blob_id().to_string(),
            cache_mgr: device.cache_mgr().clone(),
            nbd_dev: Some(nbd_dev),
            netlink: None,
            kernel_socks: Mutex::new(Vec::new()),
            parking: Arc::new(AtomicBool::new(false)),
            sender: Arc::new(sender),
        })
    }

    /// Create a new instance of [NbdService] configuring the NBD device at `nbd_path` through
    /// netlink, see [NbdService::connect]. A server taking the device over from a previous one
    /// must have the same `backend_id`.
    pub fn new_netlink(
        device: Arc<BlockDevice>,
        nbd_path: String,
        backend_id: String,
        timeout: u64,
    ) -> Result<Self> {
        let (sender, _receiver) = channel(4);

        Ok(NbdService {
            active: Arc::new(AtomicBool::new(true)),
            blob_id: device.meta_blob_id().to_string(),
            cache_mgr: device.cache_mgr().clone(),
            nbd_dev: None,
            netlink: Some(DeviceConfig {
                index: device_index(&nbd_path)?,
                size_bytes: device.blocks() as u64 * device.block_size(),
                block_size: device.block_size(),
                server_flags: (NBD_FLAG_HAS_FLAGS | NBD_FLAG_READ_ONLY | NBD_FLAG_CAN_MULTI_CONN)
                    as u64,
                timeout,
                dead_conn_timeout: NBD_DEAD_CONN_TIMEOUT,
                backend_id,
            }),
            kernel_socks: Mutex::new(Vec::new()),
            parking: Arc::new(AtomicBool::new(false)),
            sender: Arc::new(sender),
        })
    }

    /// Create a [NbdWorker] to run the event loop to handle NBD requests from kernel.
    pub fn create_worker(&self) -> Result<NbdWorker> {
        let (sock1, sock2) = StdUnixStream::pair()?;
        let sock_kern = if let Some(nbd_dev) = &self.nbd_dev {
            // Let the NBD driver go.
            nbd_ioctl(nbd_dev.as_raw_fd(), NBD_SET_SOCK, sock1.as_raw_fd() as u64)?;
            Some(sock1)
        } else {
            self.kernel_socks.lock().unwrap().push(sock1);
            None
        };

        Ok(self.worker(sock2, sock_kern))
    }

    /// Create a [NbdWorker] serving the connection whose user end is `sock_user`.
    fn worker(&self, sock_user: StdUnixStream, sock_kern: Option<StdUnixStream>) -> NbdWorker {
        NbdWorker {
            active: self.active.clone(),
            blob_id: self.blob_id.clone(),
            cache_mgr: self.cache_mgr.clone(),
            parking: self.parking.clone(),
            _sock_kern: sock_kern,
            sock_user,
            sender: self.sender.clone(),
        }
    }

    /// Run the event loop to handle incoming NBD requests.
    ///
    /// The caller will get blocked until the NBD device get destroyed or `NbdService::stop()` get
    /// called.
    pub fn run(&self) -> Result<()> {
        if let Some(nbd_dev) = &self.nbd_dev {
            let _ = nbd_ioctl(nbd_dev.as_raw_fd(), NBD_DO_IT, 0);
            self.active.store(false, Ordering::Release);
            let _ = self.sender.send(1);
            let _ = nbd_ioctl(nbd_dev.as_raw_fd(), NBD_CLEAR_SOCK, 0);
        }

        Ok(())
    }

    /// Hand the connections of the workers created so far to the kernel through netlink: connect
    /// the device, or take it over from a previous server which is gone.
    pub fn connect(&self) -> Result<()> {
        let Some(config) = &self.netlink else {
            return Ok(());
        };
        // The kernel holds its own references to the sockets handed over.
        let socks = std::mem::take(&mut *self.kernel_socks.lock().unwrap());
        let fds: Vec<RawFd> = socks.iter().map(|s| s.as_raw_fd()).collect();
        let mut nl = NbdNetlink::open()?;
        match nl.connect(config, &fds) {
            // The kernel only replaces dead connections and checks the backend identifier, so
            // this cannot steal a device from a live server.
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {
                warn!(
                    "block_nbd: device nbd{} is already configured, taking it over",
                    config.index
                );
                nl.reconfigure(config, &fds)
            }
            res => res,
        }
    }

    /// Shutdown the NBD session and send exit notification to workers.
    ///
    /// A device configured through netlink stays configured for a new server to take it over.
    pub fn stop(&self) {
        self.active.store(false, Ordering::Release);
        let _ = self.sender.send(0);
        if let Some(nbd_dev) = &self.nbd_dev {
            //let _ = nbd_ioctl(nbd_dev.as_raw_fd(), NBD_DISCONNECT, 0);
            let _ = nbd_ioctl(nbd_dev.as_raw_fd(), NBD_CLEAR_SOCK, 0);
        }
    }

    /// Disconnect a device configured through netlink, failing its pending requests.
    pub fn disconnect(&self) -> Result<()> {
        match &self.netlink {
            Some(config) => NbdNetlink::open()?.disconnect(config.index),
            None => Ok(()),
        }
    }
}

/// Parse the index of an NBD device from its path, e.g. 3 for `/dev/nbd3`.
fn device_index(path: &str) -> Result<u32> {
    std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str()?.strip_prefix("nbd")?.parse().ok())
        .ok_or_else(|| einval!(format!("invalid NBD device path {}", path)))
}

/// The socket a new server connects to to take the connections of the device over, next to the
/// API socket.
fn handover_path(apisock: &str) -> PathBuf {
    Path::new(apisock)
        .parent()
        .unwrap_or_else(|| Path::new("/"))
        .join("handover.sock")
}

fn send_fds(conn: &StdUnixStream, fds: &[RawFd]) -> Result<()> {
    let count = [fds.len() as u8];
    sendmsg::<()>(
        conn.as_raw_fd(),
        &[IoSlice::new(&count)],
        &[ControlMessage::ScmRights(fds)],
        MsgFlags::empty(),
        None,
    )
    .map_err(|e| eother!(e))?;
    Ok(())
}

fn recv_fds(conn: &StdUnixStream) -> Result<Vec<StdUnixStream>> {
    let mut count = [0u8; 1];
    let mut cmsg = nix::cmsg_space!([RawFd; 64]);
    let msg = recvmsg::<()>(
        conn.as_raw_fd(),
        &mut [IoSliceMut::new(&mut count)],
        Some(&mut cmsg),
        MsgFlags::MSG_CMSG_CLOEXEC,
    )
    .map_err(|e| eother!(e))?;
    let fds: Vec<RawFd> = msg
        .cmsgs()
        .find_map(|c| match c {
            ControlMessageOwned::ScmRights(fds) => Some(fds),
            _ => None,
        })
        .unwrap_or_default();
    // Safe because the received descriptors are owned by this process.
    let socks: Vec<StdUnixStream> = fds
        .into_iter()
        .map(|fd| unsafe { StdUnixStream::from_raw_fd(fd) })
        .collect();
    if socks.is_empty() || socks.len() != count[0] as usize {
        return Err(eother!("invalid NBD handover"));
    }
    Ok(socks)
}

fn is_mounted(mountpoint: &str) -> NydusResult<bool> {
    let mounts = std::fs::read_to_string("/proc/self/mounts")
        .map_err(|e| NydusError::StartService(format!("read mounts, {}", e)))?;
    Ok(mounts
        .lines()
        .any(|l| l.split_whitespace().nth(1) == Some(mountpoint)))
}

/// A worker to handle NBD requests in asynchronous mode.
pub struct NbdWorker {
    active: Arc<AtomicBool>,
    blob_id: String,
    cache_mgr: Arc<BlobCacheMgr>,
    parking: Arc<AtomicBool>,
    _sock_kern: Option<StdUnixStream>,
    sock_user: StdUnixStream,
    sender: Arc<Sender<u32>>,
}

impl NbdWorker {
    /// Run the event loop to handle NBD requests from kernel in asynchronous mode.
    ///
    /// Requests are served concurrently, up to [NBD_MAX_INFLIGHT_BYTES] at a time: the kernel
    /// sends every request of a queue on the same connection, so serving them one at a time
    /// would serialize all reads of the device, each one possibly waiting on the backend.
    ///
    /// Returns the connection when parked for a new server to take it over, see
    /// [NbdDaemon::hand_over].
    pub async fn run(self) -> Option<StdUnixStream> {
        let device =
            match BlockDevice::new_with_cache_manager(self.blob_id.clone(), self.cache_mgr.clone())
            {
                Ok(v) => Rc::new(v),
                Err(e) => {
                    error!(
                        "block_nbd: failed to create block device for {}, {}",
                        self.blob_id, e
                    );
                    return None;
                }
            };

        // Requests are read once the socket is readable, so that stopping never drops a request
        // read from the kernel; replies are written through io_uring.
        let reader = match self.sock_user.try_clone().and_then(|r| {
            r.set_nonblocking(true)?;
            AsyncFd::new(r)
        }) {
            Ok(r) => r,
            Err(e) => {
                error!(
                    "block_nbd: failed to poll connection for {}, {}",
                    self.blob_id, e
                );
                return None;
            }
        };
        // Safe because the socket is moved out of the worker, it has a single owner.
        let sock = Rc::new(unsafe { UnixStream::from_raw_fd(self.sock_user.into_raw_fd()) });
        let reply_lock = Rc::new(AsyncMutex::new(()));
        let inflight = Arc::new(Semaphore::new(NBD_MAX_INFLIGHT_BYTES as usize));
        let mut receiver = self.sender.subscribe();
        let mut buf = vec![0u8; NBD_REQUEST_HEADER_SIZE];
        let mut pos = 0;
        let mut stopping = false;
        // `&StdUnixStream` reads without a mutable borrow of the reader.
        let mut conn = reader.get_ref();

        loop {
            stopping |= !self.active.load(Ordering::Acquire);
            let res = if stopping {
                // Park between two requests: the requests not read yet stay queued on the
                // connection for the new server.
                if pos == 0 && self.parking.load(Ordering::Acquire) {
                    break;
                }
                // Serve the requests the kernel already sent before stopping: the kernel would
                // only retry an unanswered request after its timeout.
                match conn.read(&mut buf[pos..]) {
                    Err(e) if e.kind() == ErrorKind::WouldBlock && pos == 0 => break,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        if let Ok(mut guard) = reader.readable().await {
                            guard.clear_ready();
                        }
                        continue;
                    }
                    res => res,
                }
            } else {
                tokio::select! {
                    _ = receiver.recv() => {
                        stopping = true;
                        continue;
                    }
                    ready = reader.readable() => match ready {
                        Ok(mut guard) => match guard.try_io(|_| conn.read(&mut buf[pos..])) {
                            Ok(res) => res,
                            Err(_would_block) => continue,
                        },
                        Err(e) => Err(e),
                    },
                }
            };
            match res {
                Err(e) => {
                    warn!(
                        "block_nbd: failed to get request from kernel for {}, {}",
                        self.blob_id, e
                    );
                    break;
                }
                Ok(0) => break,
                Ok(sz) => {
                    pos += sz;
                    if pos == NBD_REQUEST_HEADER_SIZE {
                        pos = 0;
                        if (&buf[4..]).get_u32() == NBD_CMD_DISC {
                            break;
                        }
                        let len = (&buf[24..]).get_u32().clamp(1, NBD_MAX_INFLIGHT_BYTES);
                        let Ok(permit) = inflight.clone().acquire_many_owned(len).await else {
                            break;
                        };
                        let (request, sock, device) = (buf.clone(), sock.clone(), device.clone());
                        let (reply_lock, blob_id) = (reply_lock.clone(), self.blob_id.clone());
                        tokio_uring::spawn(async move {
                            let _permit = permit;
                            if let Err(e) =
                                Self::handle_request(&request, &sock, &device, &reply_lock).await
                            {
                                warn!("block_nbd: failed to handle request for {}, {}", blob_id, e);
                            }
                        });
                    }
                }
            }
        }

        // Let the requests being served finish before the socket gets closed.
        let _ = inflight.acquire_many(NBD_MAX_INFLIGHT_BYTES).await;
        if self.parking.load(Ordering::Acquire) {
            return Some(reader.into_inner());
        }
        None
    }

    async fn handle_request(
        mut request: &[u8],
        sock: &UnixStream,
        device: &Rc<BlockDevice>,
        reply_lock: &AsyncMutex<()>,
    ) -> Result<()> {
        let magic = request.get_u32();
        let ty = request.get_u32();
        let handle = request.get_u64();
        let pos = request.get_u64();
        let len = request.get_u32();

        let block_size = device.block_size();
        let mut code = NBD_OK;
        let mut data_buf = alloc_buf(len as usize);
        if magic != NBD_REQUEST_MAGIC || pos % block_size != 0 || len as u64 % block_size != 0 {
            warn!(
                "block_nbd: invalid request magic 0x{:x}, type {}, pos 0x{:x}, len 0x{:x}",
                magic, ty, pos, len
            );
            code = NBD_EINVAL;
        } else if ty == NBD_CMD_READ {
            let start = (pos / block_size) as u32;
            let count = len / block_size as u32;
            let (res, buf) = device.async_read(start, count, data_buf).await;
            data_buf = buf;
            match res {
                Ok(sz) => {
                    if sz != len as usize {
                        warn!("block_nbd: got 0x{:x} bytes, expect 0x{:x}", sz, len);
                        code = NBD_EIO;
                    }
                }
                Err(e) => {
                    warn!("block_nbd: failed to read data from block device, {}", e);
                    code = NBD_EIO;
                }
            }
        }

        let mut reply = Vec::with_capacity(16);
        reply.put_u32(NBD_REPLY_MAGIC);
        reply.put_u32(code);
        reply.put_u64(handle);
        assert_eq!(reply.len(), 16);
        assert_eq!(data_buf.len(), len as usize);
        // A reply header and its data must not interleave with another reply.
        let _guard = reply_lock.lock().await;
        sock.write_all(reply).await.0?;
        if code == NBD_OK {
            sock.write_all(data_buf).await.0?;
        }

        Ok(())
    }
}

/// A [NydusDaemon] implementation to expose RAFS v6 images as block devices through NBD.
pub struct NbdDaemon {
    cache_mgr: Arc<BlobCacheMgr>,
    service: Arc<NbdService>,

    bti: BuildTimeInfo,
    id: Option<String>,
    supervisor: Option<String>,

    nbd_path: String,
    mountpoint: Option<String>,
    queue_attributes: std::collections::HashMap<String, String>,
    nbd_threads: u32,
    nbd_control_thread: Mutex<Option<JoinHandle<()>>>,
    nbd_service_threads: Mutex<Vec<JoinHandle<Result<()>>>>,
    // Handover of the connections to a new server, see [NbdDaemon::hand_over].
    workers: Arc<AtomicUsize>,
    parked: (
        Mutex<std::sync::mpsc::Sender<StdUnixStream>>,
        Mutex<std::sync::mpsc::Receiver<StdUnixStream>>,
    ),
    taken_over: Mutex<Vec<StdUnixStream>>,
    takeover_conn: Mutex<Option<StdUnixStream>>,
    request_sender: Arc<Mutex<std::sync::mpsc::Sender<DaemonStateMachineInput>>>,
    result_receiver: Mutex<std::sync::mpsc::Receiver<NydusResult<()>>>,
    state: AtomicI32,
    state_machine_thread: Mutex<Option<JoinHandle<Result<()>>>>,
    waker: Arc<Waker>,
}

impl NbdDaemon {
    #[allow(clippy::too_many_arguments)]
    fn new(
        nbd_path: String,
        netlink: bool,
        mountpoint: Option<String>,
        config: NbdConfig,
        threads: u32,
        blob_entry: BlobCacheEntry,
        trigger: std::sync::mpsc::Sender<DaemonStateMachineInput>,
        receiver: std::sync::mpsc::Receiver<NydusResult<()>>,
        waker: Arc<Waker>,
        bti: BuildTimeInfo,
        id: Option<String>,
        supervisor: Option<String>,
    ) -> Result<Self> {
        let blob_id = generate_blob_key(&blob_entry.domain_id, &blob_entry.blob_id);
        let cache_mgr = Arc::new(BlobCacheMgr::new());
        cache_mgr.add_blob_entry(&blob_entry)?;
        let block_device = BlockDevice::new_with_cache_manager(blob_id.clone(), cache_mgr.clone())?;
        #[allow(clippy::arc_with_non_send_sync)]
        let block_device = Arc::new(block_device);
        let nbd_service = if netlink {
            // A new daemon serving the same image takes the device over.
            let backend_id = id.clone().unwrap_or_else(|| nbd_path.clone());
            NbdService::new_netlink(block_device, nbd_path.clone(), backend_id, config.timeout)?
        } else {
            NbdService::new(block_device, nbd_path.clone())?
        };

        Ok(NbdDaemon {
            cache_mgr,
            service: Arc::new(nbd_service),

            bti,
            id,
            supervisor,

            nbd_path,
            mountpoint,
            queue_attributes: config.queue_attributes,
            nbd_threads: threads,
            nbd_control_thread: Mutex::new(None),
            nbd_service_threads: Mutex::new(Vec::new()),
            workers: Arc::new(AtomicUsize::new(0)),
            parked: {
                let (tx, rx) = std::sync::mpsc::channel();
                (Mutex::new(tx), Mutex::new(rx))
            },
            taken_over: Mutex::new(Vec::new()),
            takeover_conn: Mutex::new(None),
            state: AtomicI32::new(DaemonState::INIT as i32),
            request_sender: Arc::new(Mutex::new(trigger)),
            result_receiver: Mutex::new(receiver),
            state_machine_thread: Mutex::new(None),
            waker,
        })
    }
}

impl NbdDaemon {
    fn spawn_worker(&self, worker: NbdWorker) -> NydusResult<()> {
        let waker = self.waker.clone();
        let active = self.service.active.clone();
        let netlink = self.service.netlink.is_some();
        let workers = self.workers.clone();
        let parked = self.parked.0.lock().unwrap().clone();
        workers.fetch_add(1, Ordering::AcqRel);
        let thread = std::thread::Builder::new()
            .name("nbd_worker".to_string())
            .spawn(move || {
                tokio_uring::start(async move {
                    let sock = worker.run().await;
                    workers.fetch_sub(1, Ordering::AcqRel);
                    if let Some(sock) = sock {
                        let _ = parked.send(sock);
                        return;
                    }
                    // Notify the daemon controller that one working thread has exited. With
                    // netlink, only when the device went away, e.g. it was disconnected: after
                    // an exit, a new daemon takes the device over, the controller must not
                    // disconnect it.
                    if !netlink || active.load(Ordering::Acquire) {
                        if let Err(err) = waker.wake() {
                            error!("block_nbd: fail to exit daemon, error: {:?}", err);
                        }
                    }
                });
                Ok(())
            })
            .map_err(NydusError::ThreadSpawn)?;
        self.nbd_service_threads.lock().unwrap().push(thread);
        Ok(())
    }

    /// Hand the connections of the device over to a new server connected on `conn`: the workers
    /// park between two requests once their requests are served, the connections are sent to the
    /// new server, which serves the requests queued meanwhile, and the process exits. The
    /// workers resume serving if the new server fails before serving.
    fn hand_over(&self, conn: StdUnixStream) -> Result<()> {
        let count = self.workers.load(Ordering::Acquire);
        self.service.parking.store(true, Ordering::Release);
        self.service.active.store(false, Ordering::Release);
        let _ = self.service.sender.send(2);
        let mut socks = Vec::with_capacity(count);
        let parked = self.parked.1.lock().unwrap();
        for _ in 0..count {
            match parked.recv_timeout(NBD_HANDOVER_TIMEOUT) {
                Ok(sock) => socks.push(sock),
                Err(_) => break,
            }
        }
        drop(parked);

        let fds: Vec<RawFd> = socks.iter().map(|s| s.as_raw_fd()).collect();
        let res = if socks.len() == count {
            send_fds(&conn, &fds).and_then(|_| {
                let mut ack = [0u8; 1];
                conn.set_read_timeout(Some(NBD_HANDOVER_TIMEOUT))?;
                (&conn).read_exact(&mut ack)
            })
        } else {
            Err(eother!("not all the workers parked"))
        };
        if res.is_ok() {
            info!("block_nbd: NBD connections handed over, exit");
            std::process::exit(0);
        }

        self.service.parking.store(false, Ordering::Release);
        self.service.active.store(true, Ordering::Release);
        for sock in socks {
            self.spawn_worker(self.service.worker(sock, None))
                .map_err(|e| eother!(e))?;
        }
        res
    }

    fn sys_block_dir(&self) -> String {
        let name = std::path::Path::new(&self.nbd_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        format!("/sys/block/{}", name)
    }

    // Wait until the kernel serves the device: it exposes the pid of its server once started,
    // immediately with netlink, once the control thread entered NBD_DO_IT with ioctl.
    fn wait_device(&self) -> NydusResult<()> {
        let pid = format!("{}/pid", self.sys_block_dir());
        for _ in 0..100 {
            if std::path::Path::new(&pid).exists() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Err(NydusError::StartService(format!(
            "NBD device {} not started",
            self.nbd_path
        )))
    }
}

impl DaemonStateMachineSubscriber for NbdDaemon {
    fn on_event(&self, event: DaemonStateMachineInput) -> NydusResult<()> {
        self.request_sender
            .lock()
            .expect("block_nbd: failed to lock request sender!")
            .send(event)
            .map_err(NydusError::ChannelSend)?;

        self.result_receiver
            .lock()
            .expect("block_nbd: failed to lock result receiver!")
            .recv()
            .map_err(NydusError::ChannelReceive)?
    }
}

impl NydusDaemon for NbdDaemon {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn id(&self) -> Option<String> {
        self.id.clone()
    }

    fn version(&self) -> BuildTimeInfo {
        self.bti.clone()
    }

    fn get_state(&self) -> DaemonState {
        self.state.load(Ordering::Relaxed).into()
    }

    fn set_state(&self, state: DaemonState) {
        self.state.store(state as i32, Ordering::Relaxed);
    }

    fn start(&self) -> NydusResult<()> {
        let taken_over = std::mem::take(&mut *self.taken_over.lock().unwrap());
        if !taken_over.is_empty() {
            info!("serve the {} NBD connections taken over", taken_over.len());
            for sock in taken_over {
                self.spawn_worker(self.service.worker(sock, None))?;
            }
            // The previous server exits once it knows the connections are served. The device and
            // its mount stay as they were.
            if let Some(mut conn) = self.takeover_conn.lock().unwrap().take() {
                conn.write_all(&[1])
                    .map_err(|e| NydusError::StartService(format!("ack handover, {}", e)))?;
            }
            return Ok(());
        }

        info!("start NBD service with {} worker threads", self.nbd_threads);
        for _ in 0..self.nbd_threads {
            let worker = self
                .service
                .create_worker()
                .map_err(|e| NydusError::StartService(format!("{}", e)))?;
            self.spawn_worker(worker)?;
        }

        if self.service.netlink.is_some() {
            self.service
                .connect()
                .map_err(|e| NydusError::StartService(format!("connect NBD device, {}", e)))?;
        } else {
            let nbd = self.service.clone();
            let thread = std::thread::spawn(move || {
                if let Err(e) = nbd.run() {
                    error!("block_nbd: failed to run NBD control loop, {e}");
                }
            });
            *self.nbd_control_thread.lock().unwrap() = Some(thread);
        }

        if self.mountpoint.is_none() && self.queue_attributes.is_empty() {
            return Ok(());
        }
        self.wait_device()?;
        // Only tunings: the device works with the kernel defaults.
        for (attr, value) in &self.queue_attributes {
            let path = format!("{}/queue/{}", self.sys_block_dir(), attr);
            if let Err(e) = fs::write(&path, value) {
                warn!("block_nbd: failed to write {}, {}", path, e);
            }
        }
        // A daemon taking over the device after a crash finds the image still mounted.
        match &self.mountpoint {
            Some(mp) if !is_mounted(mp)? => mount(
                Some(self.nbd_path.as_str()),
                mp.as_str(),
                Some("erofs"),
                MsFlags::MS_RDONLY,
                None::<&str>,
            )
            .map_err(|e| {
                NydusError::StartService(format!("mount {} on {}, {}", self.nbd_path, mp, e))
            }),
            _ => Ok(()),
        }
    }

    fn umount(&self) -> NydusResult<()> {
        if let Some(mp) = &self.mountpoint {
            if is_mounted(mp)? {
                umount(mp.as_str())
                    .map_err(|e| NydusError::StartService(format!("umount {}, {}", mp, e)))?;
            }
        }
        self.service
            .disconnect()
            .map_err(|e| NydusError::StartService(format!("disconnect NBD device, {}", e)))
    }

    fn stop(&self) {
        self.service.stop();
    }

    fn wait(&self) -> NydusResult<()> {
        self.wait_state_machine()?;
        self.wait_service()
    }

    fn wait_service(&self) -> NydusResult<()> {
        loop {
            let handle = self.nbd_service_threads.lock().unwrap().pop();
            if let Some(handle) = handle {
                handle
                    .join()
                    .map_err(|e| {
                        let e = *e
                            .downcast::<Error>()
                            .unwrap_or_else(|e| Box::new(eother!(e)));
                        NydusError::WaitDaemon(e)
                    })?
                    .map_err(NydusError::WaitDaemon)?;
            } else {
                // No more handles to wait
                break;
            }
        }

        Ok(())
    }

    fn wait_state_machine(&self) -> NydusResult<()> {
        let mut guard = self.state_machine_thread.lock().unwrap();
        if let Some(handler) = guard.take() {
            let result = handler.join().map_err(|e| {
                let e = *e
                    .downcast::<Error>()
                    .unwrap_or_else(|e| Box::new(eother!(e)));
                NydusError::WaitDaemon(e)
            })?;
            result.map_err(NydusError::WaitDaemon)
        } else {
            Ok(())
        }
    }

    fn supervisor(&self) -> Option<String> {
        self.supervisor.clone()
    }

    // The kernel holds the state of the device: a new daemon takes it over without any.
    fn save(&self) -> NydusResult<()> {
        Err(NydusError::Unsupported)
    }

    fn restore(&self) -> NydusResult<()> {
        Err(NydusError::Unsupported)
    }

    fn get_blob_cache_mgr(&self) -> Option<Arc<BlobCacheMgr>> {
        Some(self.cache_mgr.clone())
    }
}

/// Create and start a [NbdDaemon] instance to expose a RAFS v6 image as a block device through NBD.
#[allow(clippy::too_many_arguments)]
pub fn create_nbd_daemon(
    device: String,
    netlink: bool,
    upgrade: bool,
    apisock: Option<String>,
    mountpoint: Option<String>,
    config: NbdConfig,
    threads: u32,
    blob_entry: BlobCacheEntry,
    bti: BuildTimeInfo,
    id: Option<String>,
    supervisor: Option<String>,
    waker: Arc<Waker>,
) -> Result<Arc<dyn NydusDaemon>> {
    let (trigger, events_rx) = std::sync::mpsc::channel::<DaemonStateMachineInput>();
    let (result_sender, result_receiver) = std::sync::mpsc::channel::<NydusResult<()>>();
    let daemon = NbdDaemon::new(
        device,
        netlink,
        mountpoint,
        config,
        threads,
        blob_entry,
        trigger,
        result_receiver,
        waker,
        bti,
        id,
        supervisor,
    )?;
    let daemon = Arc::new(daemon);
    // Take the connections of the device over from the server listening for a handover.
    let handover = apisock.filter(|_| netlink).map(|s| handover_path(&s));
    if upgrade {
        let path = handover
            .as_ref()
            .ok_or_else(|| einval!("upgrading an NBD daemon requires --netlink and --apisock"))?;
        let conn = StdUnixStream::connect(path)?;
        *daemon.taken_over.lock().unwrap() = recv_fds(&conn)?;
        *daemon.takeover_conn.lock().unwrap() = Some(conn);
    }
    let machine = DaemonStateMachineContext::new(daemon.clone(), events_rx, result_sender);
    let machine_thread = machine.kick_state_machine()?;
    *daemon.state_machine_thread.lock().unwrap() = Some(machine_thread);
    daemon
        .on_event(DaemonStateMachineInput::Mount)
        .map_err(|e| eother!(e))?;
    daemon
        .on_event(DaemonStateMachineInput::Start)
        .map_err(|e| eother!(e))?;

    // Serve the handover of the connections to a new server.
    if let Some(path) = handover {
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        let d = daemon.clone();
        std::thread::Builder::new()
            .name("nbd_handover".to_string())
            .spawn(move || {
                for conn in listener.incoming().flatten() {
                    if let Err(e) = d.hand_over(conn) {
                        warn!("block_nbd: NBD handover failed, keep serving, {}", e);
                    }
                }
            })?;
    }

    Ok(daemon)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob_cache::{generate_blob_key, BlobCacheMgr};
    use nydus_api::BlobCacheEntry;
    use std::fs;
    use std::path::PathBuf;
    use std::time::Duration;
    use vmm_sys_util::tempdir::TempDir;

    #[allow(clippy::arc_with_non_send_sync)]
    fn create_block_device(tmpdir: PathBuf) -> Result<Arc<BlockDevice>> {
        let root_dir = &std::env::var("CARGO_MANIFEST_DIR").expect("$CARGO_MANIFEST_DIR");
        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/blobs/be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef");
        let mut dest_path = tmpdir.clone();
        dest_path.push("be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef");
        fs::copy(&source_path, &dest_path).unwrap();

        let mut source_path = PathBuf::from(root_dir);
        source_path.push("../tests/texture/bootstrap/rafs-v6-2.2.boot");
        let config = r#"
        {
            "type": "bootstrap",
            "id": "rafs-v6",
            "domain_id": "domain2",
            "config_v2": {
                "version": 2,
                "id": "factory1",
                "backend": {
                    "type": "localfs",
                    "localfs": {
                        "dir": "/tmp/nydus"
                    }
                },
                "cache": {
                    "type": "filecache",
                    "filecache": {
                        "work_dir": "/tmp/nydus"
                    }
                },
                "metadata_path": "RAFS_V5"
            }
          }"#;
        let content = config
            .replace("/tmp/nydus", tmpdir.as_path().to_str().unwrap())
            .replace("RAFS_V5", &source_path.display().to_string());
        let mut entry: BlobCacheEntry = serde_json::from_str(&content).unwrap();
        assert!(entry.prepare_configuration_info());

        let mgr = BlobCacheMgr::new();
        mgr.add_blob_entry(&entry).unwrap();
        let blob_id = generate_blob_key(&entry.domain_id, &entry.blob_id);
        assert!(mgr.get_config(&blob_id).is_some());

        // Check existence of data blob referenced by the bootstrap.
        let key = generate_blob_key(
            &entry.domain_id,
            "be7d77eeb719f70884758d1aa800ed0fb09d701aaec469964e9d54325f0d5fef",
        );
        assert!(mgr.get_config(&key).is_some());

        let mgr = Arc::new(mgr);
        let device = BlockDevice::new_with_cache_manager(blob_id.clone(), mgr).unwrap();

        Ok(Arc::new(device))
    }

    #[test]
    fn test_device_index() {
        let tests = [
            ("/dev/nbd0", Some(0)),
            ("/dev/nbd17", Some(17)),
            ("nbd3", Some(3)),
            ("/dev/sda", None),
            ("/dev/nbd", None),
        ];
        for (path, want) in tests {
            assert_eq!(device_index(path).ok(), want, "{path}");
        }
    }

    // Requires root and the nbd module.
    #[ignore]
    #[test]
    fn test_nbd_device() {
        // Configured devices expose the pid of their server until disconnected.
        let connected = || std::path::Path::new("/sys/block/nbd15/pid").exists();
        tokio_uring::start(async {
            let tmpdir = TempDir::new().unwrap();
            let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
            let nbd =
                NbdService::new_netlink(device, "/dev/nbd15".to_string(), "test".to_string(), 0)
                    .unwrap();
            let start = |nbd: &NbdService| {
                for _ in 0..2 {
                    let worker = nbd.create_worker().unwrap();
                    tokio_uring::spawn(async move { worker.run().await });
                }
                nbd.connect().unwrap();
            };
            assert!(!connected());
            start(&nbd);
            assert!(connected());
            tokio::time::sleep(Duration::from_millis(100)).await;
            // A new server takes the device over once the previous one stopped.
            nbd.stop();
            tokio::time::sleep(Duration::from_millis(100)).await;
            start(&nbd);
            nbd.disconnect().unwrap();
            // The device goes back to the pool: it must survive the disconnect.
            for _ in 0..50 {
                if !connected() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert!(!connected());
            assert!(std::path::Path::new("/sys/block/nbd15").exists());
        })
    }
}
