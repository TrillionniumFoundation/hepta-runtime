// Fixed test-only FD5 setup capability and read-only observations. Every
// handler, original mutex operation, SDK serve loop and runtime Drop is real.
type WaitGuards = Arc<std::sync::Mutex<Vec<Option<tokio::sync::OwnedMutexGuard<()>>>>>;
struct WaitCommand {
    sequence: u64,
    operation: u64,
    slot: usize,
    payload: Vec<u8>,
    reply: std::sync::mpsc::Sender<Result<Vec<u8>>>,
}
fn wait_validate_capabilities() -> Result<()> {
    let flags = unsafe { libc::fcntl(5, libc::F_GETFL) };
    if flags < 0 || flags & libc::O_ACCMODE != libc::O_RDWR || flags & libc::O_NONBLOCK != 0 {
        bail!("fixed blocking FD5 capability missing");
    }
    let mut kind: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let result = unsafe { libc::getsockopt(5, libc::SOL_SOCKET, libc::SO_TYPE,
        (&mut kind as *mut libc::c_int).cast(), &mut size) };
    if result != 0 || kind != libc::SOCK_STREAM
        || size as usize != std::mem::size_of::<libc::c_int>() {
        bail!("fixed FD5 is not a stream socket");
    }
    let trace = unsafe { libc::fcntl(4, libc::F_GETFL) };
    if trace < 0 || trace & libc::O_ACCMODE == libc::O_RDONLY {
        bail!("fixed writable FD4 observation capability missing");
    }
    Ok(())
}
fn wait_snapshot(server: &OctofsServer, guards: &WaitGuards, phase: u64, sequence: u64) -> Result<Vec<u8>> {
    let held = guards.lock().map_err(|_| anyhow::anyhow!("fixture guard storage poisoned"))?
        .iter().map(Option::is_some).collect::<Vec<_>>();
    Ok(serde_json::to_vec(&json!({
        "schema":"hepta.runtime.original-extract-wait-observation.v1",
        "phase":phase,"sequence":sequence,"fixture_holders":held,
        "cache_snapshot_hex":hex(&fs::delta::fixture_snapshot(&server.view_cache,phase)),
        "history_snapshot_hex":hex(&fs::core::fixture_history_snapshot(phase,sequence)),
        "lock_snapshot_hex":hex(&fs::text_editing::fixture_lock_snapshot(phase,sequence)),
        "session":{"root":server.workdir.root.to_string_lossy(),
            "current":server.workdir.current.read().ok().and_then(|v|v.clone()).map(|p|p.to_string_lossy().to_string()),
            "effective":server.workdir.get_current().to_string_lossy(),
            "session_applied":server.session_applied.load(Ordering::SeqCst),
            "poisoned":server.workdir.current.is_poisoned()},
        "observer_task_scope_unbound":request_ctx::with_view_cache(|_|false).is_none()
    }))?)
}
fn wait_reply(sequence: u64, operation: u64, slot: usize, phase: u64,
    output: &[u8], snapshot: &[u8]) -> Vec<u8> {
    let mut raw = b"HXLTR001".to_vec();
    for value in [sequence,operation,slot as u64,0,output.len() as u64,
        32+snapshot.len() as u64,phase] { raw.extend_from_slice(&value.to_le_bytes()); }
    raw.extend_from_slice(output);
    raw.extend_from_slice(b"HXLTS001");
    for value in [1u64,snapshot.len() as u64,0] { raw.extend_from_slice(&value.to_le_bytes()); }
    raw.extend_from_slice(snapshot);
    raw
}
async fn wait_apply(server: &OctofsServer, guards: &WaitGuards,
    command: &WaitCommand) -> Result<Vec<u8>> {
    let output = match command.operation {
        1 => {
            if command.payload.is_empty() || guards.lock().unwrap()[command.slot].is_some() {
                bail!("fixture holder slot already occupied or empty key");
            }
            let path = PathBuf::from(std::str::from_utf8(&command.payload)?);
            if !path.is_absolute() { bail!("fixture holder key must be absolute"); }
            let source = fs::PathSource::Local(path);
            // lock_owned consumes the only acquired Arc. Its guard carries one
            // strong reference, exactly like one native fixture-held lease.
            let lease = fs::text_editing::acquire_file_lock(&source).await?;
            let guard = lease.lock_owned().await;
            let prior = guards.lock().unwrap()[command.slot].replace(guard);
            if prior.is_some() { bail!("fixture holder changed during acquisition"); }
            Vec::new()
        }
        2 => {
            if !command.payload.is_empty() { bail!("fixture release payload"); }
            let guard = guards.lock().unwrap()[command.slot].take()
                .ok_or_else(|| anyhow::anyhow!("fixture holder slot empty"))?;
            drop(guard);
            Vec::new()
        }
        3 => {
            if command.slot != 0 || !command.payload.is_empty() { bail!("fixture observation frame"); }
            Vec::new()
        }
        4 => {
            if command.slot != 0 || command.payload.len() < 48
                || &command.payload[..8] != b"HVCACH01"
                || !(1..=2).contains(&word(&command.payload,8)) {
                bail!("fixture cache setup frame");
            }
            fs::delta::fixture_apply(&server.view_cache,&command.payload)?
        }
        _ => bail!("fixture command outside frozen domain"),
    };
    let snapshot = wait_snapshot(server,guards,0,command.sequence)?;
    Ok(wait_reply(command.sequence,command.operation,command.slot,0,&output,&snapshot))
}
async fn wait_controller(server: OctofsServer, guards: WaitGuards,
    mut receiver: tokio::sync::mpsc::UnboundedReceiver<WaitCommand>,
    sequence: Arc<std::sync::atomic::AtomicU64>) {
    while let Some(command) = receiver.recv().await {
        let expected = sequence.load(Ordering::SeqCst).checked_add(1);
        let result = if expected != Some(command.sequence) {
            Err(anyhow::anyhow!("fixture command sequence"))
        } else {
            sequence.store(command.sequence,Ordering::SeqCst);
            wait_apply(&server,&guards,&command).await
        };
        let failed = result.is_err();
        let _ = command.reply.send(result);
        if failed { break; }
    }
}
fn wait_control_thread(mut control: std::os::unix::net::UnixStream,
    sender: tokio::sync::mpsc::UnboundedSender<WaitCommand>) -> Result<()> {
    use std::io::Read;
    loop {
        let mut head = [0u8;64];
        let count = loop {
            match control.read(&mut head[..1]) {
                Err(e) if e.kind()==std::io::ErrorKind::Interrupted => continue,
                result => break result?,
            }
        };
        if count == 0 { return Ok(()); }
        control.read_exact(&mut head[1..])?;
        if &head[..8] != b"HXLTQ001" || head[40..] != [0u8;24] {
            bail!("fixed control frame header");
        }
        let sequence = word(&head,8);
        let operation = word(&head,16);
        let slot = usize::try_from(word(&head,24))?;
        let length = usize::try_from(word(&head,32))?;
        if !(1..=4).contains(&operation) || slot >= 4 || length > 3072 {
            bail!("fixed control frame domain");
        }
        let mut payload = vec![0u8;length];
        control.read_exact(&mut payload)?;
        let (reply, receive) = std::sync::mpsc::channel();
        if sender.send(WaitCommand{sequence,operation,slot,payload,reply}).is_err() {
            return Ok(());
        }
        let answer = match receive.recv() { Ok(result) => result?, Err(_) => return Ok(()) };
        control.write_all(&answer)?;
        control.flush()?;
    }
}
