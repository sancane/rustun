use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use stun_agent::{
    StunAgentError, StunAttributes, StunClient, StunPacket, StunTransactionError, StuntClientEvent,
};
use stun_rs::{MessageClass, MessageMethod, StunMessage, TransactionId};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::task::JoinHandle;

type StuntClientResult = Result<Option<StunMessage>, StunClientError>;
type StunClientTx = oneshot::Sender<StuntClientResult>;

pub trait StunClientHandler {
    fn now(&self) -> Instant;
    fn send_stun_packet(&self);
}

#[derive(Debug)]
pub enum StunClientError {
    AgentError(StunAgentError),
    ClientDropped,
    RetryTransaction,
    TransactionFailed(StunTransactionError),
    UnssuportedMessageClass(MessageClass),
}

struct SendStunMessage {
    class: MessageClass,
    method: MessageMethod,
    attributes: StunAttributes,
    buffer: Vec<u8>,
    tx: StunClientTx,
}

struct OnBufferMessage {
    buffer: Vec<u8>,
    tx: oneshot::Sender<Result<(), StunClientError>>,
}

enum StuntClientRequestMessages {
    SendStunMessage(SendStunMessage),
    ProcessRecvBuffer(OnBufferMessage),
}

struct TimeoutHandler {
    tid: TransactionId,
    task: JoinHandle<()>,
}
struct StuntClientActor<T: StunClientHandler> {
    client: StunClient,
    handler: T,
    on_timeout: Arc<Notify>,
    rx: mpsc::Receiver<StuntClientRequestMessages>,
    timeout: Option<TimeoutHandler>,
    transactions: HashMap<TransactionId, StunClientTx>,
}

impl<T: StunClientHandler> StuntClientActor<T> {
    pub fn new(
        client: StunClient,
        handler: T,
        rx: mpsc::Receiver<StuntClientRequestMessages>,
    ) -> Self {
        StuntClientActor {
            client,
            handler,
            on_timeout: Arc::new(Notify::new()),
            rx,
            timeout: None,
            transactions: HashMap::new(),
        }
    }

    async fn send_packet(&mut self, tid: TransactionId, packet: StunPacket) {
        // TODO:
    }

    fn abort_timeout(&mut self) {
        if let Some(handler) = self.timeout.take() {
            // Cancel previous timeout
            handler.task.abort();
        }
    }

    async fn set_timeout(&mut self, tid: TransactionId, duration: Duration) {
        if let Some(handler) = self.timeout.as_ref() {
            if handler.tid == tid {
                // The timeout is already set for the same transaction
                return;
            }
        }

        self.abort_timeout();
        println!("Setting new timeout for {tid} of {:?}", duration);

        let notify = self.on_timeout.clone();
        self.timeout = Some(TimeoutHandler {
            tid,
            task: tokio::spawn(async move {
                tokio::time::sleep(duration).await;
                notify.notify_one();
            }),
        });
    }

    fn response(&mut self, tid: &TransactionId, result: StuntClientResult) {
        if let Some(tx) = self.transactions.remove(&tid) {
            if let Err(err) = tx.send(result) {
                // TODO: Add warning log
            }
        }
    }

    async fn process_events(&mut self) {
        let mut events = self.client.events();
        while let Some(event) = events.pop_front() {
            match event {
                StuntClientEvent::OutputPacket((tid, packet)) => self.send_packet(tid, packet).await,
                StuntClientEvent::RestransmissionTimeOut((tid, duration)) => {
                    self.set_timeout(tid, duration).await
                }
                StuntClientEvent::Retry(tid) => {
                    self.response(&tid, Err(StunClientError::RetryTransaction));
                }
                StuntClientEvent::TransactionFailed((tid, e)) => {
                    self.response(&tid, Err(StunClientError::TransactionFailed(e)));
                }
                StuntClientEvent::StunMessageReceived(msg) => {
                    // TODO: Move this code into a macro so that we can reuse the response code avoiding borrowing problems
                    if let Some(tx) = self.transactions.remove(msg.transaction_id()) {
                        if let Err(err) = tx.send(Ok(Some(msg))) {
                            // TODO: Add warning log
                        }
                    }
                }
            }
        }
    }

    fn send_request(&mut self, msg: SendStunMessage) {
        match self
            .client
            .send_request(msg.method, msg.attributes, msg.buffer, self.handler.now())
        {
            Ok(tid) => {
                self.transactions.insert(tid, msg.tx);
            }
            Err(e) => {
                let _ = msg.tx.send(Err(StunClientError::AgentError(e)));
            }
        }
    }

    fn send_indication(&mut self, msg: SendStunMessage) {
        if let Err(e) = self
            .client
            .send_indication(msg.method, msg.attributes, msg.buffer)
        {
            let _ = msg.tx.send(Err(StunClientError::AgentError(e)));
        }
    }

    async fn send_message(&mut self, msg: SendStunMessage) {
        match msg.class {
            MessageClass::Request => self.send_request(msg),
            MessageClass::Indication => self.send_indication(msg),
            class => {
                let _ = msg
                    .tx
                    .send(Err(StunClientError::UnssuportedMessageClass(class)));
                return;
            }
        }
        self.process_events().await;
    }

    async fn process_buffer_recv(&mut self, msg: OnBufferMessage) {
        if let Err(e) = self.client.on_buffer_recv(&msg.buffer, Instant::now()) {
            // Return the buffer
            let _ = msg.tx.send(Err(StunClientError::AgentError(e)));
        }

        self.process_events().await;
    }

    async fn on_timeout(&mut self) {
        self.abort_timeout();
        self.client.on_timeout(self.handler.now());
        self.process_events().await;
    }

    pub async fn main_loop(&mut self) {
        loop {
            tokio::select! {
                _ = self.on_timeout.notified() => {
                    println!("Timeout!!");
                    self.on_timeout().await;
                }
                value = self.rx.recv() => {
                    match value {
                        Some(StuntClientRequestMessages::SendStunMessage(msg)) => {
                            self.send_message(msg).await;
                        }
                        Some(StuntClientRequestMessages::ProcessRecvBuffer(msg)) => {
                            self.process_buffer_recv(msg).await;
                        }
                        None => {
                            break;
                        }
                    }
                }
            }
        }
        println!("Client actor finished");
    }
}

fn spawn_stun_client_actor<T: StunClientHandler + Send + 'static>(
    client: StunClient,
    handler: T,
    rx: mpsc::Receiver<StuntClientRequestMessages>,
) -> JoinHandle<()> {
    let mut actor = StuntClientActor::new(client, handler, rx);

    tokio::spawn(async move {
        actor.main_loop().await;
    })
}

#[derive(Clone)]
pub struct StuntClientAgent {
    handler: Arc<JoinHandle<()>>,
    tx_req: mpsc::Sender<StuntClientRequestMessages>,
}

impl StuntClientAgent {
    pub fn new<T: StunClientHandler + Send + 'static>(client: StunClient, handler: T) -> Self {
        let (tx_req, rx_req) = mpsc::channel(10);
        let handler = spawn_stun_client_actor(client, handler, rx_req);
        StuntClientAgent {
            handler: Arc::new(handler),
            tx_req,
        }
    }

    async fn send_msg(
        &self,
        class: MessageClass,
        method: MessageMethod,
        attributes: StunAttributes,
        buffer: Vec<u8>,
    ) -> StuntClientResult {
        let (tx, rx) = oneshot::channel();
        self.tx_req
            .send(StuntClientRequestMessages::SendStunMessage(
                SendStunMessage {
                    class,
                    method,
                    attributes,
                    buffer,
                    tx,
                },
            ))
            .await
            .map_err(|_| StunClientError::ClientDropped)?;
        rx.await.map_err(|_| StunClientError::ClientDropped)?
    }

    pub async fn send_request(
        &self,
        method: MessageMethod,
        attributes: StunAttributes,
        buffer: Vec<u8>,
    ) -> StuntClientResult {
        self.send_msg(MessageClass::Request, method, attributes, buffer)
            .await
    }

    pub async fn send_indication(
        &self,
        method: MessageMethod,
        attributes: StunAttributes,
        buffer: Vec<u8>,
    ) -> StuntClientResult {
        self.send_msg(MessageClass::Indication, method, attributes, buffer)
            .await
    }
}
