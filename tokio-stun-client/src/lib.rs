use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use stun_agent::{
    StunAgentError, StunAttributes, StunClient, StunPacket, StunTransactionError, StuntClientEvent,
};
use stun_rs::{MessageClass, MessageMethod, StunMessage, TransactionId};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

struct SendStunPacketMessage {
    packet: StunPacket,
    tx: oneshot::Sender<bool>,
}

struct SetTimeoutMessage {
    instant: Instant,
    duration: Duration,
    tx: oneshot::Sender<bool>,
}

pub enum StuntClientEventMessages {
    SendStunPacket(SendStunPacketMessage),
    SetTimeout(SetTimeoutMessage),
}

type StuntClientResult = Result<Option<StunMessage>, StunClientError>;
type StunClientTx = oneshot::Sender<StuntClientResult>;

trait StunClientEventsHandler {
    fn set_timeout(&self);
    fn send_packet(&self);
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

struct StuntClientActor {
    client: StunClient,
    rx: mpsc::Receiver<StuntClientRequestMessages>,
    timeout: Option<TransactionId>,
    transactions: HashMap<TransactionId, StunClientTx>,
    tx: mpsc::Sender<StuntClientEventMessages>,
}

impl StuntClientActor {
    pub fn new(
        client: StunClient,
        rx: mpsc::Receiver<StuntClientRequestMessages>,
        tx: mpsc::Sender<StuntClientEventMessages>,
    ) -> Self {
        StuntClientActor {
            client,
            rx,
            timeout: None,
            transactions: HashMap::new(),
            tx,
        }
    }

    fn response(&mut self, tid: &TransactionId, result: StuntClientResult) {
        if let Some(tx) = self.transactions.remove(&tid) {
            if let Err(err) = tx.send(result) {
                // TODO: Add warning log
            }
        }
    }

    async fn send_packet(&mut self, packet: StunPacket) {
        let (tx, rx) = oneshot::channel();
        let msg = SendStunPacketMessage { packet, tx };
        if let Err(e) = self
            .tx
            .send(StuntClientEventMessages::SendStunPacket(msg))
            .await
        {
            // TODO: Debug error
        } else {
            match rx.await {
                Ok(true) => {
                    // TODO: Debug no packet sent
                }
                Ok(false) => {
                    // TODO: Debug no packet sent
                }
                Err(e) => {
                    // TODO: Debug no packet sent
                }
            }
        }
    }

    async fn set_timeout(&mut self, tid: TransactionId, duration: Duration) {
        if let Some(t) = &self.timeout {
            if t == &tid {
                // Timeout already scheduled
                return;
            }
        }
        let (tx, rx) = oneshot::channel();
        let msg = SetTimeoutMessage {
            instant: Instant::now(),
            duration,
            tx,
        };
        if let Err(e) = self
            .tx
            .send(StuntClientEventMessages::SetTimeout(msg))
            .await
        {
            // TODO: Debug error
        } else {
            match rx.await {
                Ok(true) => self.timeout = Some(tid.clone()),
                Ok(false) => {
                    // TODO: Debug no timeout set
                }
                Err(e) => {
                    // TODO: Debug no timeout set
                }
            }
        }
    }

    async fn process_events(&mut self) {
        let mut events = self.client.events();
        while !events.is_empty() {
            // TODO: Change this to VecDeque so that there is no reallocation
            let event = events.remove(0);
            match event {
                StuntClientEvent::OutputPacket(packet) => self.send_packet(packet).await,
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
            .send_request(msg.method, msg.attributes, msg.buffer, Instant::now())
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

    pub async fn main_loop(&mut self) {
        loop {
            match self.rx.recv().await {
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

fn spawn_stun_client_actor(
    client: StunClient,
    rx: mpsc::Receiver<StuntClientRequestMessages>,
    tx: mpsc::Sender<StuntClientEventMessages>,
) -> JoinHandle<()> {
    let mut actor = StuntClientActor::new(client, rx, tx);

    tokio::spawn(async move {
        actor.main_loop().await;
    })
}

#[derive(Clone)]
struct StuntClient {
    handler: Arc<JoinHandle<()>>,
    tx_req: mpsc::Sender<StuntClientRequestMessages>,
}

impl StuntClient {
    pub fn new(client: StunClient, tx_evt: mpsc::Sender<StuntClientEventMessages>) -> Self {
        let (tx_req, rx_req) = mpsc::channel(10);
        let handler = spawn_stun_client_actor(client, rx_req, tx_evt);
        StuntClient {
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

    pub async fn send_indicationt(
        &self,
        method: MessageMethod,
        attributes: StunAttributes,
        buffer: Vec<u8>,
    ) -> StuntClientResult {
        self.send_msg(MessageClass::Indication, method, attributes, buffer)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
