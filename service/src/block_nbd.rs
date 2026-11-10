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
use std::io::{Error, Result};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, RawFd};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use bytes::{Buf, BufMut};
use mio::Waker;
use nix::mount::{mount, umount, MsFlags};
use nydus_api::{BlobCacheEntry, BuildTimeInfo};
use tokio::sync::broadcast::{channel, Sender};
use tokio::sync::{Mutex as AsyncMutex, Semaphore};
use tokio_uring::buf::IoBuf;
use tokio_uring::net::UnixStream;

use crate::blob_cache::{generate_blob_key, BlobCacheMgr};
use crate::block_device::BlockDevice;
use crate::daemon::{
    DaemonState, DaemonStateMachineContext, DaemonStateMachineInput, DaemonStateMachineSubscriber,
    NydusDaemon,
};
use crate::nbd_netlink::{DeviceConfig, NbdNetlink};
use crate::{Error as NydusError, Result as NydusResult};

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
/// Requests are read in pieces of this size at most, see [BlockDevice::async_read_pieces].
const NBD_READ_PIECE: u64 = 1 << 20;

/// Network Block Device server to expose RAFSv6 images as block devices.
///
/// The device is configured through the NBD netlink interface, so it outlives the server: the
/// kernel queues its requests once the server died, until a new server reconfigures it with new
/// connections. Its configuration lives in the kernel, servers keep no state.
pub struct NbdService {
    active: Arc<AtomicBool>,
    blob_id: String,
    cache_mgr: Arc<BlobCacheMgr>,
    config: DeviceConfig,
    // Kernel ends of the connections of the workers, until handed to the kernel.
    kernel_socks: Mutex<Vec<StdUnixStream>>,
    sender: Arc<Sender<u32>>,
}

impl NbdService {
    /// Create a new instance of [NbdService] to expose a RAFSv6 image as a block device.
    ///
    /// The NBD device at `nbd_path` gets configured by [NbdService::connect]. A server taking the
    /// device over from a previous one must have the same `backend_id`.
    pub fn new(device: Arc<BlockDevice>, nbd_path: String, backend_id: String) -> Result<Self> {
        let (sender, _receiver) = channel(4);
        Ok(NbdService {
            active: Arc::new(AtomicBool::new(true)),
            blob_id: device.meta_blob_id().to_string(),
            cache_mgr: device.cache_mgr().clone(),
            config: DeviceConfig {
                index: device_index(&nbd_path)?,
                size_bytes: device.blocks() as u64 * device.block_size(),
                block_size: device.block_size(),
                server_flags: (NBD_FLAG_HAS_FLAGS | NBD_FLAG_READ_ONLY | NBD_FLAG_CAN_MULTI_CONN)
                    as u64,
                dead_conn_timeout: NBD_DEAD_CONN_TIMEOUT,
                backend_id,
            },
            kernel_socks: Mutex::new(Vec::new()),
            sender: Arc::new(sender),
        })
    }

    /// Create a [NbdWorker] to run the event loop to handle NBD requests from kernel.
    pub fn create_worker(&self) -> Result<NbdWorker> {
        let (sock1, sock2) = StdUnixStream::pair()?;
        self.kernel_socks.lock().unwrap().push(sock1);

        Ok(NbdWorker {
            active: self.active.clone(),
            blob_id: self.blob_id.clone(),
            cache_mgr: self.cache_mgr.clone(),
            sock_user: sock2,
            sender: self.sender.clone(),
        })
    }

    /// Hand the connections of the workers created so far to the kernel: connect the device, or
    /// take it over from a previous server which died or exited.
    pub fn connect(&self) -> Result<()> {
        // The kernel holds its own references to the sockets handed over.
        let socks = std::mem::take(&mut *self.kernel_socks.lock().unwrap());
        let fds: Vec<RawFd> = socks.iter().map(|s| s.as_raw_fd()).collect();
        let mut nl = NbdNetlink::open()?;
        match nl.connect(&self.config, &fds) {
            // The kernel only replaces dead connections and checks the backend identifier, so
            // this cannot steal a device from a live server.
            Err(e) if e.raw_os_error() == Some(libc::EBUSY) => {
                warn!(
                    "block_nbd: device nbd{} is already configured, taking it over",
                    self.config.index
                );
                nl.reconfigure(&self.config, &fds)
            }
            res => res,
        }
    }

    /// Stop serving the device, keeping it configured: once its connections are dead, the kernel
    /// queues requests until a new server takes the device over.
    pub fn stop(&self) {
        self.active.store(false, Ordering::Release);
        let _ = self.sender.send(0);
    }

    /// Disconnect the device, failing its pending requests.
    pub fn disconnect(&self) -> Result<()> {
        NbdNetlink::open()?.disconnect(self.config.index)
    }
}

/// Parse the index of an NBD device from its path, e.g. 3 for `/dev/nbd3`.
fn is_mounted(mountpoint: &str) -> NydusResult<bool> {
    let mounts = std::fs::read_to_string("/proc/self/mounts")
        .map_err(|e| NydusError::StartService(format!("read mounts, {}", e)))?;
    Ok(mounts
        .lines()
        .any(|l| l.split_whitespace().nth(1) == Some(mountpoint)))
}

fn device_index(path: &str) -> Result<u32> {
    std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str()?.strip_prefix("nbd")?.parse().ok())
        .ok_or_else(|| einval!(format!("invalid NBD device path {}", path)))
}

/// A worker to handle NBD requests in asynchronous mode.
pub struct NbdWorker {
    active: Arc<AtomicBool>,
    blob_id: String,
    cache_mgr: Arc<BlobCacheMgr>,
    sock_user: StdUnixStream,
    sender: Arc<Sender<u32>>,
}

impl NbdWorker {
    /// Run the event loop to handle NBD requests from kernel in asynchronous mode.
    ///
    /// Requests are served concurrently, up to [NBD_MAX_INFLIGHT_BYTES] at a time: the kernel
    /// sends every request of a queue on the same connection, so serving them one at a time
    /// would serialize all reads of the device, each one possibly waiting on the backend.
    pub async fn run(self) {
        let device =
            match BlockDevice::new_with_cache_manager(self.blob_id.clone(), self.cache_mgr.clone())
            {
                Ok(v) => Rc::new(v),
                Err(e) => {
                    error!(
                        "block_nbd: failed to create block device for {}, {}",
                        self.blob_id, e
                    );
                    return;
                }
            };

        // Safe because the socket is moved out of the worker, it has a single owner.
        let sock = Rc::new(unsafe { UnixStream::from_raw_fd(self.sock_user.into_raw_fd()) });
        let reply_lock = Rc::new(AsyncMutex::new(()));
        let inflight = Arc::new(Semaphore::new(NBD_MAX_INFLIGHT_BYTES as usize));
        let mut receiver = self.sender.subscribe();
        let mut buf = vec![0u8; NBD_REQUEST_HEADER_SIZE];
        let mut pos = 0;

        while self.active.load(Ordering::Acquire) {
            tokio::select! {
                (res, s) = sock.read(buf.slice(pos..)) => {
                    match res {
                        Err(e) => {
                            warn!("block_nbd: failed to get request from kernel for {}, {}", self.blob_id, e);
                            break;
                        }
                        Ok(0) => break,
                        Ok(sz) => {
                            buf = s.into_inner();
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
                                    if let Err(e) = Self::handle_request(&request, &sock, &device, &reply_lock).await {
                                        warn!("block_nbd: failed to handle request for {}, {}", blob_id, e);
                                    }
                                });
                            }
                        }
                    }
                }
                _ = receiver.recv() => {
                   break;
                }
            }
        }

        // Let the requests being served finish before the socket gets closed.
        let _ = inflight.acquire_many(NBD_MAX_INFLIGHT_BYTES).await;
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
        let mut data = Vec::new();
        if magic != NBD_REQUEST_MAGIC || pos % block_size != 0 || len as u64 % block_size != 0 {
            warn!(
                "block_nbd: invalid request magic 0x{:x}, type {}, pos 0x{:x}, len 0x{:x}",
                magic, ty, pos, len
            );
            code = NBD_EINVAL;
        } else if ty == NBD_CMD_READ {
            let start = (pos / block_size) as u32;
            let count = len / block_size as u32;
            match device.async_read_pieces(start, count, NBD_READ_PIECE).await {
                Ok(v) => data = v,
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
        // A reply header and its data must not interleave with another reply.
        let _guard = reply_lock.lock().await;
        sock.write_all(reply).await.0?;
        if code == NBD_OK {
            for buf in data {
                sock.write_all(buf).await.0?;
            }
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
    nbd_threads: u32,
    nbd_service_threads: Mutex<Vec<JoinHandle<Result<()>>>>,
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
        mountpoint: Option<String>,
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
        // A new daemon serving the same image takes the device over.
        let backend_id = id.clone().unwrap_or_else(|| nbd_path.clone());
        #[allow(clippy::arc_with_non_send_sync)]
        let nbd_service = NbdService::new(Arc::new(block_device), nbd_path.clone(), backend_id)?;

        Ok(NbdDaemon {
            cache_mgr,
            service: Arc::new(nbd_service),

            bti,
            id,
            supervisor,

            nbd_path,
            mountpoint,
            nbd_threads: threads,
            nbd_service_threads: Mutex::new(Vec::new()),
            state: AtomicI32::new(DaemonState::INIT as i32),
            request_sender: Arc::new(Mutex::new(trigger)),
            result_receiver: Mutex::new(receiver),
            state_machine_thread: Mutex::new(None),
            waker,
        })
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
        info!("start NBD service with {} worker threads", self.nbd_threads);
        for _ in 0..self.nbd_threads {
            let waker = self.waker.clone();
            let active = self.service.active.clone();
            let worker = self
                .service
                .create_worker()
                .map_err(|e| NydusError::StartService(format!("{}", e)))?;
            let thread = std::thread::Builder::new()
                .name("nbd_worker".to_string())
                .spawn(move || {
                    tokio_uring::start(async move {
                        worker.run().await;
                        // Notify the daemon controller that the device went away, e.g. it was
                        // disconnected. Workers stopped on purpose must not: the controller would
                        // stop the daemon and disconnect the device, which a new daemon takes
                        // over after an exit.
                        if active.load(Ordering::Acquire) {
                            if let Err(err) = waker.wake() {
                                error!("block_nbd: fail to exit daemon, error: {:?}", err);
                            }
                        }
                    });
                    Ok(())
                })
                .map_err(NydusError::ThreadSpawn)?;
            self.nbd_service_threads.lock().unwrap().push(thread);
        }

        self.service
            .connect()
            .map_err(|e| NydusError::StartService(format!("connect NBD device, {}", e)))?;
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
    mountpoint: Option<String>,
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
        mountpoint,
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
    let machine = DaemonStateMachineContext::new(daemon.clone(), events_rx, result_sender);
    let machine_thread = machine.kick_state_machine()?;
    *daemon.state_machine_thread.lock().unwrap() = Some(machine_thread);
    daemon
        .on_event(DaemonStateMachineInput::Mount)
        .map_err(|e| eother!(e))?;
    daemon
        .on_event(DaemonStateMachineInput::Start)
        .map_err(|e| eother!(e))?;

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
                NbdService::new(device, "/dev/nbd15".to_string(), "test".to_string()).unwrap();
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
