//! Owned-process observations of target transport, codec, and normal shutdown.
#![allow(deprecated)]
mod message_model;
use anyhow::{Context,ensure};
use rmcp::{RoleServer,Service,ErrorData,
    model::{ClientJsonRpcMessage,ClientRequest,ClientNotification,ServerConfig,ServerResult,ServerJsonRpcMessage},
    service::{RequestContext,NotificationContext,serve_directly_with_ct},
    transport::{Transport,async_rw::{AsyncRwTransport,JsonRpcMessageCodec}}};
use serde_json::{json,Value};
use std::{io::{BufRead,Write},pin::Pin,sync::{Arc,Mutex},task::{Context as TaskContext,Poll},time::Duration};
use tokio::{io::{AsyncRead,AsyncWrite,AsyncWriteExt,ReadBuf,DuplexStream},sync::Semaphore};
use tokio_util::{bytes::BytesMut,codec::Decoder,sync::CancellationToken};

#[derive(Default)]
struct Output {
    bytes:Vec<u8>, events:Vec<Value>, flushes:usize, shutdowns:usize,
    closed:bool, child_tokens:Vec<CancellationToken>, external:Option<CancellationToken>,
}
struct Writer { state:Arc<Mutex<Output>>, closed:Arc<Semaphore> }
impl AsyncWrite for Writer {
    fn poll_write(self:Pin<&mut Self>,_:&mut TaskContext<'_>,buf:&[u8])->Poll<std::io::Result<usize>>{
        let mut state=self.state.lock().unwrap();
        state.bytes.extend_from_slice(buf);
        state.events.push(json!({"event":"write","bytes":buf.len()}));
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self:Pin<&mut Self>,_:&mut TaskContext<'_>)->Poll<std::io::Result<()>>{
        let mut state=self.state.lock().unwrap();state.flushes+=1;state.events.push(json!({"event":"flush"}));Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self:Pin<&mut Self>,_:&mut TaskContext<'_>)->Poll<std::io::Result<()>>{
        let mut state=self.state.lock().unwrap();state.shutdowns+=1;state.events.push(json!({"event":"poll_shutdown"}));Poll::Ready(Ok(()))
    }
}
impl Drop for Writer {
    fn drop(&mut self){
        let mut state=self.state.lock().unwrap();state.closed=true;
        let child_flags:Vec<bool>=state.child_tokens.iter().map(CancellationToken::is_cancelled).collect();
        let outer=state.external.as_ref().map(CancellationToken::is_cancelled);
        state.events.push(json!({"event":"writer_drop","children_cancelled":child_flags,"external_cancelled":outer}));
        self.closed.add_permits(1);
    }
}
struct Reader { inner:DuplexStream,state:Arc<Mutex<Output>>,eof:Arc<Semaphore>,seen:bool }
impl AsyncRead for Reader {
    fn poll_read(mut self:Pin<&mut Self>,cx:&mut TaskContext<'_>,buf:&mut ReadBuf<'_>)->Poll<std::io::Result<()>>{
        let before=buf.filled().len();
        let result=Pin::new(&mut self.inner).poll_read(cx,buf);
        if matches!(result,Poll::Ready(Ok(()))) && before==buf.filled().len() && !self.seen {
            self.seen=true;self.state.lock().unwrap().events.push(json!({"event":"read_eof"}));self.eof.add_permits(1);
        }
        result
    }
}
fn input(case:&Value)->anyhow::Result<Vec<u8>>{
    let path=case["input_file"].as_str().context("input_file")?;
    let path=std::path::Path::new(path);
    ensure!(path.starts_with("cases/inputs") && path.components().all(|p|matches!(p,std::path::Component::Normal(_))),"owned relative fixture input");
    Ok(std::fs::read(path)?)
}
async fn observe_transport(case:&Value)->anyhow::Result<Value>{
    let data=input(case)?;
    let input_bytes=data.len();
    let chunk=case["chunk_size"].as_u64().unwrap_or(8192) as usize;
    ensure!(chunk>0,"chunk_size");
    let split=case["cancel_receive_after"].as_u64().map(|n|n as usize);
    let ready=Arc::new(Semaphore::new(0));let resume=Arc::new(Semaphore::new(0));
    let output=Arc::new(Mutex::new(Output::default()));let closed=Arc::new(Semaphore::new(0));
    let (mut peer,stream)=tokio::io::duplex(65536);
    let writer_ready=ready.clone();let writer_resume=resume.clone();
    let producer=tokio::spawn(async move {
        let mut offset=0;
        if let Some(at)=split {
            peer.write_all(&data[..at]).await?;offset=at;writer_ready.add_permits(1);
            writer_resume.acquire().await.unwrap().forget();
        }
        for bytes in data[offset..].chunks(chunk){peer.write_all(bytes).await?;tokio::task::yield_now().await;}
        peer.shutdown().await
    });
    let read=Reader{inner:stream,state:output.clone(),eof:Arc::new(Semaphore::new(0)),seen:false};
    let mut transport=AsyncRwTransport::new_server(read,Writer{state:output.clone(),closed:closed.clone()});
    if let Some(max)=case["max_line_length"].as_u64(){transport=transport.with_max_line_length(max as usize);}
    let mut cancelled_pending=false;
    if split.is_some(){
        ready.acquire().await?.forget();
        {
            let receive=transport.receive();tokio::pin!(receive);
            cancelled_pending=matches!(futures::poll!(&mut receive),Poll::Pending);
            ensure!(cancelled_pending,"ordinary partial receive was pending");
        }
        resume.add_permits(1);
    }
    let mut messages=Vec::new();
    while let Some(message)=transport.receive().await{
        messages.push(serde_json::to_string(&message)?);
        if let ClientJsonRpcMessage::Request(request)=message {
            ensure!(matches!(request.request,ClientRequest::PingRequest(_)),"ordinary transport fixture uses ping only");
            transport.send(ServerJsonRpcMessage::response(ServerResult::empty(()),request.id)).await?;
        }
    }
    producer.await??;
    transport.close().await?;
    closed.acquire().await?.forget();
    let out=output.lock().unwrap();
    Ok(json!({"mode":"async","input_bytes":input_bytes,"messages":messages,
        "cancelled_pending_receive":cancelled_pending,"writer_closed":out.closed,
        "writer_bytes":String::from_utf8(out.bytes.clone())?,"poll_shutdown_calls":out.shutdowns,
        "events":out.events,"default_max_line_length":rmcp::transport::async_rw::DEFAULT_MAX_LINE_LENGTH}))
}
fn observe_codec(case:&Value)->anyhow::Result<Value>{
    let data=input(case)?;let input_bytes=data.len();
    let mut bytes=BytesMut::from(data.as_slice());
    let mut codec=JsonRpcMessageCodec::<ClientJsonRpcMessage>::new();
    let default_max=codec.max_length();
    let mut messages=Vec::new();
    while let Some(message)=codec.decode_eof(&mut bytes)?{messages.push(serde_json::to_string(&message)?);}
    Ok(json!({"mode":"codec-eof","input_bytes":input_bytes,"messages":messages,"remaining_bytes":bytes.len(),"default_max_length":default_max}))
}
#[derive(Clone)]
struct ShutdownService { state:Arc<Mutex<Output>>,started:Arc<Semaphore>,release_ready:Arc<Semaphore> }
impl Service<RoleServer> for ShutdownService {
    async fn handle_request(&self,_:ClientRequest,context:RequestContext<RoleServer>)->Result<ServerResult,ErrorData>{
        let ready=context.id.to_string()=="ready";
        {
            let mut state=self.state.lock().unwrap();state.child_tokens.push(context.ct.clone());
            state.events.push(json!({"event":"handler_started","id":context.id}));
        }
        self.started.add_permits(1);
        if ready {
            self.release_ready.acquire().await.unwrap().forget();
            self.state.lock().unwrap().events.push(json!({"event":"ready_handler_return"}));
        }else{
            context.ct.cancelled().await;
            self.state.lock().unwrap().events.push(json!({"event":"pending_handler_observed_cancel"}));
        }
        Ok(ServerResult::empty(()))
    }
    async fn handle_notification(&self,_:ClientNotification,_:NotificationContext<RoleServer>)->Result<(),ErrorData>{Ok(())}
    fn get_info(&self)->ServerConfig{ServerConfig::default()}
}
async fn observe_shutdown()->anyhow::Result<Value>{
    let outer=CancellationToken::new();
    let state=Arc::new(Mutex::new(Output{external:Some(outer.clone()),..Default::default()}));
    let started=Arc::new(Semaphore::new(0));let ready=Arc::new(Semaphore::new(0));
    let eof=Arc::new(Semaphore::new(0));let closed=Arc::new(Semaphore::new(0));
    let (mut peer,stream)=tokio::io::duplex(65536);
    let transport=AsyncRwTransport::new_server(Reader{inner:stream,state:state.clone(),eof:eof.clone(),seen:false},Writer{state:state.clone(),closed:closed.clone()});
    let service=ShutdownService{state:state.clone(),started:started.clone(),release_ready:ready.clone()};
    let running=serve_directly_with_ct(service,transport,None,outer.clone());
    peer.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":\"ready\",\"method\":\"ping\"}\n{\"jsonrpc\":\"2.0\",\"id\":\"waiting\",\"method\":\"ping\"}\n").await?;
    started.acquire_many(2).await?.forget();
    peer.shutdown().await?;
    eof.acquire().await?.forget();
    ready.add_permits(1);
    closed.acquire().await?.forget();
    let external_before_waiting=outer.is_cancelled();
    let quit=running.waiting().await?;
    tokio::task::yield_now().await;
    let out=state.lock().unwrap();
    Ok(json!({"mode":"shutdown","quit":format!("{quit:?}"),"events":out.events,
        "writer_bytes":String::from_utf8(out.bytes.clone())?,"poll_shutdown_calls":out.shutdowns,
        "external_before_waiting":external_before_waiting,"external_after_waiting":outer.is_cancelled()}))
}
#[tokio::main(flavor="current_thread")]
async fn main()->anyhow::Result<()>{
    let stdin=std::io::stdin();let mut stdout=std::io::BufWriter::new(std::io::stdout().lock());
    for line in stdin.lock().lines(){
        let case:Value=serde_json::from_str(&line?)?;
        let mode=case["mode"].as_str().unwrap_or("model");
        let mut row=match mode {
            "model"=>message_model::observe(case.clone())?,
            "async"=>tokio::time::timeout(Duration::from_secs(60),observe_transport(&case)).await??,
            "codec-eof"=>observe_codec(&case)?,
            "shutdown"=>tokio::time::timeout(Duration::from_secs(15),observe_shutdown()).await??,
            _=>anyhow::bail!("unsupported ordinary fixture mode"),
        };
        row["label"]=case["label"].clone();
        serde_json::to_writer(&mut stdout,&row)?;stdout.write_all(b"\n")?;stdout.flush()?;
    }
    Ok(())
}
