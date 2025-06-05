use axum::{routing::{get, post}, Router};
use axum::Json as AxumJson;
use serde::{Deserialize, Serialize};
use bytes::Bytes;

#[derive(Serialize, Deserialize, Debug)]
struct GetAllInterfacesResponse {
    interfaces: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SendPacketRequest {
    interface: String,
    packet: Bytes,
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(root_handler))
        .route("/interfaces", get(get_all_interfaces))
        .route("/send-packet", post(send_packet));

    axum::serve(
        tokio::net::TcpListener::bind("127.0.0.1:3000").await.unwrap(),
        app,
    )
    .await
    .unwrap();
}

async fn root_handler() -> &'static str {
    "Hello, World!"
}

async fn get_all_interfaces() -> AxumJson<GetAllInterfacesResponse> {
    let interfaces = pcap::Device::list().unwrap();
    let response = GetAllInterfacesResponse {
        interfaces: interfaces.iter().map(|i| i.name.clone()).collect(),
    };
    AxumJson(response)
}

async fn send_packet(AxumJson(request): AxumJson<SendPacketRequest>) -> AxumJson<&'static str> {
    println!("Sending packet to interface: {}", request.interface);
    println!("Packet: {:?}", request.packet);
    let mut handle = pcap::Capture::from_device(request.interface.as_str())
        .unwrap()
        .open()
        .unwrap();
    handle.sendpacket(&request.packet[..]).unwrap();
    AxumJson("Packet sent")
}