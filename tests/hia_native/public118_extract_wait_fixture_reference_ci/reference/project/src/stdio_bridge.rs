// Fixture-only byte relay to the same actual rmcp AsyncRwTransport.
// Neither request parsing nor response counts nor tool results live here.
fn run_actual_stdio(server: OctofsServer, executor: tokio::runtime::Runtime) -> Result<()> {
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
    executor.block_on(async move {
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
    })
}
