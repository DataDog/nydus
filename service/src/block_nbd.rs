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
use std::io::{Error, Result};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use bytes::{Buf, BufMut};
use mio::Waker;
use nydus_api::{BlobCacheEntry, BuildTimeInfo};
use nydus_storage::utils::alloc_buf;
use tokio::sync::broadcast::{channel, Sender};
use tokio_uring::buf::IoBuf;
use tokio_uring::net::UnixStream;

use crate::blob_cache::{generate_blob_key, BlobCacheMgr};
use crate::block_device::BlockDevice;
use crate::daemon::{
    DaemonState, DaemonStateMachineContext, DaemonStateMachineInput, DaemonStateMachineSubscriber,
    NydusDaemon,
};
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
/// Maximum size of the read buffers of the requests a worker serves at the same time, in units
/// of [NBD_INFLIGHT_UNIT]. The kernel bounds the number of requests of a connection; this bounds
/// their memory when they are large.
const NBD_MAX_INFLIGHT_UNITS: u32 = (128 << 20) / NBD_INFLIGHT_UNIT;
const NBD_INFLIGHT_UNIT: u32 = 4096;

fn nbd_ioctl(fd: RawFd, cmd: u32, arg: u64) -> nix::Result<libc::c_int> {
    let code = nix::request_code_none!(0xab, cmd);
    unsafe { nix::convert_ioctl_res!(libc::ioctl(fd, code, arg)) }
}

/// Network Block Device server to expose RAFSv6 images as block devices.
pub struct NbdService {
    active: Arc<AtomicBool>,
    blob_id: String,
    cache_mgr: Arc<BlobCacheMgr>,
    nbd_dev: fs::File,
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
            nbd_dev,
            sender: Arc::new(sender),
        })
    }

    /// Create a [NbdWorker] to run the event loop to handle NBD requests from kernel.
    pub fn create_worker(&self) -> Result<NbdWorker> {
        // Let the NBD driver go.
        let (sock1, sock2) = std::os::unix::net::UnixStream::pair()?;
        nbd_ioctl(
            self.nbd_dev.as_raw_fd(),
            NBD_SET_SOCK,
            sock1.as_raw_fd() as u64,
        )?;

        Ok(NbdWorker {
            active: self.active.clone(),
            blob_id: self.blob_id.clone(),
            cache_mgr: self.cache_mgr.clone(),
            _sock_kern: sock1,
            sock_user: sock2,
            sender: self.sender.clone(),
        })
    }

    /// Run the event loop to handle incoming NBD requests.
    ///
    /// The caller will get blocked until the NBD device get destroyed or `NbdService::stop()` get
    /// called.
    pub fn run(&self) -> Result<()> {
        let _ = nbd_ioctl(self.nbd_dev.as_raw_fd(), NBD_DO_IT, 0);
        self.active.store(false, Ordering::Release);
        let _ = self.sender.send(1);
        let _ = nbd_ioctl(self.nbd_dev.as_raw_fd(), NBD_CLEAR_SOCK, 0);

        Ok(())
    }

    /// Shutdown the NBD session and send exit notification to workers.
    pub fn stop(&self) {
        self.active.store(false, Ordering::Release);
        let _ = self.sender.send(0);
        //let _ = nbd_ioctl(self.nbd_dev.as_raw_fd(), NBD_DISCONNECT, 0);
        let _ = nbd_ioctl(self.nbd_dev.as_raw_fd(), NBD_CLEAR_SOCK, 0);
    }
}

/// A worker to handle NBD requests in asynchronous mode.
pub struct NbdWorker {
    active: Arc<AtomicBool>,
    blob_id: String,
    cache_mgr: Arc<BlobCacheMgr>,
    _sock_kern: std::os::unix::net::UnixStream,
    sock_user: std::os::unix::net::UnixStream,
    sender: Arc<Sender<u32>>,
}

impl NbdWorker {
    /// Run the event loop to handle NBD requests from kernel in asynchronous mode.
    ///
    /// Requests are served concurrently, up to [NBD_MAX_INFLIGHT_UNITS] of data at a time: the
    /// kernel sends every request of a queue on the same connection, so serving them one at a
    /// time would serialize all reads of the device, each one possibly waiting on the backend.
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

        // Safe because the RawFd is valid during the lifetime of run().
        let sock = Rc::new(unsafe { UnixStream::from_raw_fd(self.sock_user.as_raw_fd()) });
        // Serializes replies, a reply header and its data must not interleave with another reply.
        let reply_lock = Rc::new(tokio::sync::Mutex::new(()));
        let inflight = Arc::new(tokio::sync::Semaphore::new(NBD_MAX_INFLIGHT_UNITS as usize));
        let mut receiver = self.sender.subscribe();
        let mut buf = vec![0u8; NBD_REQUEST_HEADER_SIZE];
        let mut pos = 0;

        while self.active.load(Ordering::Acquire) {
            tokio::select! {
                (res, s) = sock.read(buf.slice(pos..)) => {
                    buf = s.into_inner();
                    match res {
                        Err(e) => {
                            warn!("block_nbd: failed to get request from kernel for {}, {}", self.blob_id, e);
                            break;
                        }
                        Ok(0) => break,
                        Ok(sz) => {
                            pos += sz;
                            if pos < NBD_REQUEST_HEADER_SIZE {
                                continue;
                            }
                            pos = 0;
                            let request = NbdRequest::parse(&buf);
                            if request.ty == NBD_CMD_DISC {
                                break;
                            }
                            let units = request
                                .len
                                .div_ceil(NBD_INFLIGHT_UNIT)
                                .clamp(1, NBD_MAX_INFLIGHT_UNITS);
                            let permit = match inflight.clone().acquire_many_owned(units).await {
                                Ok(v) => v,
                                Err(_) => break,
                            };
                            let (device, sock, reply_lock) = (device.clone(), sock.clone(), reply_lock.clone());
                            let blob_id = self.blob_id.clone();
                            tokio_uring::spawn(async move {
                                let _permit = permit;
                                let (code, data) = request.serve(&device).await;
                                let _guard = reply_lock.lock().await;
                                if let Err(e) = request.reply(&sock, code, data).await {
                                    warn!("block_nbd: failed to reply to request for {}, {}", blob_id, e);
                                }
                            });
                        }
                    }
                }
                _ = receiver.recv() => {
                   break;
                }
            }
        }

        // Let the requests being served finish before the socket gets closed.
        let _ = inflight.acquire_many(NBD_MAX_INFLIGHT_UNITS).await;
    }
}

/// A request received from the kernel NBD driver.
struct NbdRequest {
    magic: u32,
    ty: u32,
    handle: u64,
    pos: u64,
    len: u32,
}

impl NbdRequest {
    fn parse(mut header: &[u8]) -> Self {
        NbdRequest {
            magic: header.get_u32(),
            ty: header.get_u32(),
            handle: header.get_u64(),
            pos: header.get_u64(),
            len: header.get_u32(),
        }
    }

    /// Serve the request, returning the reply code and the data read.
    async fn serve(&self, device: &BlockDevice) -> (u32, Vec<u8>) {
        let block_size = device.block_size();
        let data_buf = alloc_buf(self.len as usize);
        if self.magic != NBD_REQUEST_MAGIC
            || self.pos % block_size != 0
            || self.len as u64 % block_size != 0
        {
            warn!(
                "block_nbd: invalid request magic 0x{:x}, type {}, pos 0x{:x}, len 0x{:x}",
                self.magic, self.ty, self.pos, self.len
            );
            return (NBD_EINVAL, data_buf);
        }
        if self.ty != NBD_CMD_READ {
            return (NBD_OK, data_buf);
        }

        let start = (self.pos / block_size) as u32;
        let count = self.len / block_size as u32;
        let (res, data_buf) = device.async_read(start, count, data_buf).await;
        match res {
            Ok(sz) if sz == self.len as usize => (NBD_OK, data_buf),
            Ok(sz) => {
                warn!("block_nbd: got 0x{:x} bytes, expect 0x{:x}", sz, self.len);
                (NBD_EIO, data_buf)
            }
            Err(e) => {
                warn!("block_nbd: failed to read data from block device, {}", e);
                (NBD_EIO, data_buf)
            }
        }
    }

    async fn reply(&self, sock: &UnixStream, code: u32, data: Vec<u8>) -> Result<()> {
        let mut reply = Vec::with_capacity(16);
        reply.put_u32(NBD_REPLY_MAGIC);
        reply.put_u32(code);
        reply.put_u64(self.handle);
        assert_eq!(data.len(), self.len as usize);
        sock.write_all(reply).await.0?;
        if code == NBD_OK && self.ty == NBD_CMD_READ {
            sock.write_all(data).await.0?;
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

    nbd_threads: u32,
    nbd_control_thread: Mutex<Option<JoinHandle<()>>>,
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
        let nbd_service = NbdService::new(Arc::new(block_device), nbd_path)?;

        Ok(NbdDaemon {
            cache_mgr,
            service: Arc::new(nbd_service),

            bti,
            id,
            supervisor,

            nbd_threads: threads,
            nbd_control_thread: Mutex::new(None),
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
            let worker = self
                .service
                .create_worker()
                .map_err(|e| NydusError::StartService(format!("{}", e)))?;
            let thread = std::thread::Builder::new()
                .name("nbd_worker".to_string())
                .spawn(move || {
                    tokio_uring::start(async move {
                        worker.run().await;
                        // Notify the daemon controller that one working thread has exited.
                        if let Err(err) = waker.wake() {
                            error!("block_nbd: fail to exit daemon, error: {:?}", err);
                        }
                    });
                    Ok(())
                })
                .map_err(NydusError::ThreadSpawn)?;
            self.nbd_service_threads.lock().unwrap().push(thread);
        }

        let nbd = self.service.clone();
        let thread = std::thread::spawn(move || {
            if let Err(e) = nbd.run() {
                error!("block_nbd: failed to run NBD control loop, {e}");
            }
        });
        *self.nbd_control_thread.lock().unwrap() = Some(thread);

        Ok(())
    }

    fn umount(&self) -> NydusResult<()> {
        Ok(())
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

    fn save(&self) -> NydusResult<()> {
        unimplemented!()
    }

    fn restore(&self) -> NydusResult<()> {
        unimplemented!()
    }

    fn get_blob_cache_mgr(&self) -> Option<Arc<BlobCacheMgr>> {
        Some(self.cache_mgr.clone())
    }
}

/// Create and start a [NbdDaemon] instance to expose a RAFS v6 image as a block device through NBD.
#[allow(clippy::too_many_arguments)]
pub fn create_nbd_daemon(
    device: String,
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

    /*
    // TODO: support crash recover and hot-upgrade.
    // Without api socket, nydusd can't do neither live-upgrade nor failover, so the helper
    // finding a victim is not necessary.
    if (api_sock.as_ref().is_some() && !upgrade && !is_crashed(&mnt, api_sock.as_ref().unwrap())?)
        || api_sock.is_none()
    {
        if let Some(cmd) = mount_cmd {
            daemon.service.mount(cmd)?;
        }
        daemon
            .service
            .session
            .lock()
            .unwrap()
            .mount()
            .map_err(|e| eother!(e))?;
        daemon
            .on_event(DaemonStateMachineInput::Mount)
            .map_err(|e| eother!(e))?;
        daemon
            .on_event(DaemonStateMachineInput::Start)
            .map_err(|e| eother!(e))?;
        daemon
            .service
            .conn
            .store(calc_fuse_conn(mnt)?, Ordering::Relaxed);
    }
     */

    Ok(daemon)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob_cache::{generate_blob_key, BlobCacheMgr};
    use nydus_api::BlobCacheEntry;
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

    #[ignore]
    #[test]
    fn test_nbd_device() {
        tokio_uring::start(async {
            let tmpdir = TempDir::new().unwrap();
            let device = create_block_device(tmpdir.as_path().to_path_buf()).unwrap();
            let nbd = NbdService::new(device, "/dev/nbd15".to_string()).unwrap();
            let nbd = Arc::new(nbd);
            let nbd2 = nbd.clone();
            let worker1 = nbd.create_worker().unwrap();
            let worker2 = nbd.create_worker().unwrap();

            tokio_uring::spawn(async move { worker1.run().await });
            tokio_uring::spawn(async move { worker2.run().await });
            std::thread::spawn(move || {
                nbd2.run().unwrap();
            });
            tokio::time::sleep(Duration::from_micros(100000)).await;
            nbd.stop();
        })
    }
}
