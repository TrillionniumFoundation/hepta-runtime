// Fixture-only byte relay to the same actual rmcp AsyncRwTransport.
// Neither request parsing nor response counts nor tool results live here.
fn run_actual_wait_stdio(server: OctofsServer, executor: tokio::runtime::Runtime) -> Result<()> {
    use std::os::fd::FromRawFd;
    wait_validate_capabilities()?;
    let control = unsafe { std::os::unix::net::UnixStream::from_raw_fd(5) };
    let stop_control = control.try_clone()?;
    let (control_sender, control_receiver) = tokio::sync::mpsc::unbounded_channel();
    let control_thread = std::thread::spawn(move || wait_control_thread(control,control_sender));
    let guards: WaitGuards = Arc::new(std::sync::Mutex::new((0..4).map(|_|None).collect()));
    let held = guards.clone();
    let sequence = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let active_sequence = sequence.clone();
    let observer = server.clone();
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<std::io::Result<Vec<u8>>>();
    std::thread::spawn(move || {
        let input = std::io::stdin();
        let mut input = input.lock();
        let mut buffer = [0u8; 65536];
        loop {
            match std::io::Read::read(&mut input, &mut buffer) {
                Ok(0) => break,
                Ok(count) => { if sender.send(Ok(buffer[..count].to_vec())).is_err() { break; } }
                Err(error) => { let _ = sender.send(Err(error)); break; }
            }
        }
    });
    let outcome = executor.block_on(async move {
        // Only this new test task owns setup/observation commands. The
        // following actual SDK and stdin/stdout relay blocks remain exact.
        let _control_task = tokio::spawn(wait_controller(server.clone(),held,
            control_receiver,active_sequence));
        let (client, transport) = tokio::io::duplex(65536);
        let (mut reader, mut writer) = tokio::io::split(client);
        let server_task = tokio::spawn(async move {
            let running = server.serve(transport).await.map_err(|e| e.to_string())?;
            running.waiting().await.map(|_| ()).map_err(|e| format!("{e:?}"))
        });
        let input_task = tokio::spawn(async move {
            while let Some(raw) = receiver.recv().await { writer.write_all(&raw?).await?; }
            writer.shutdown().await?;
            Ok::<(), std::io::Error>(())
        });
        let output_task = tokio::spawn(async move {
            let mut buffer = [0u8; 65536];
            loop {
                let count = tokio::io::AsyncReadExt::read(&mut reader, &mut buffer).await?;
                if count == 0 { break; }
                let output = std::io::stdout();
                let mut output = output.lock();
                output.write_all(&buffer[..count])?;
                output.flush()?;
            }
            Ok::<(), std::io::Error>(())
        });
        let outcome = server_task.await?;
        input_task.abort();
        let _ = input_task.await;
        output_task.await??;
        outcome.map_err(anyhow::Error::msg)
    });
    // Runtime Drop destroys every pending real SDK handler future while the
    // outer fixture guards still own their acquired mutex Arcs.
    drop(executor);
    let mut trace = unsafe { std::fs::File::from_raw_fd(4) };
    let last = sequence.load(Ordering::SeqCst);
    let snapshot = wait_snapshot(&observer,&guards,90,last)?;
    trace.write_all(&wait_reply(last,90,0,90,&[],&snapshot))?;
    trace.flush()?;
    {
        let mut held = guards.lock().map_err(|_| anyhow::anyhow!("fixture guard storage poisoned"))?;
        for guard in held.iter_mut() { drop(guard.take()); }
    }
    let snapshot = wait_snapshot(&observer,&guards,91,last)?;
    trace.write_all(&wait_reply(last,91,0,91,&[],&snapshot))?;
    trace.flush()?;
    let _ = stop_control.shutdown(std::net::Shutdown::Both);
    match control_thread.join() {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(error),
        Err(_) => bail!("fixture control thread panicked"),
    }
    outcome
}
