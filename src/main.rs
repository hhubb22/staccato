use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json as AxumJson, Router,
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tracing::{error, info, instrument};

// --- Error Handling ---
#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("PCAP error: {0}")]
    Pcap(#[from] pcap::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("Internal server error: {0}")]
    Internal(String), // For other general errors
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Pcap(e) => {
                error!("PCAP operation failed: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("PCAP error: {}", e))
            }
            AppError::Io(e) => {
                error!("IO operation failed: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("IO error: {}", e))
            }
            AppError::InterfaceNotFound(iface) => {
                error!("Interface not found: {}", iface);
                (StatusCode::BAD_REQUEST, format!("Interface '{}' not found", iface))
            }
            AppError::Internal(msg) => {
                error!("Internal server error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, msg)
            }
        };

        (status, AxumJson(ErrorResponse { error: error_message })).into_response()
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// --- Request/Response Structs ---
#[derive(Serialize, Deserialize, Debug)]
struct GetAllInterfacesResponse {
    interfaces: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SendPacketRequest {
    interface: String,
    packet: Bytes, // Bytes is efficient for binary data
}

#[derive(Serialize, Deserialize, Debug)]
struct SendPacketResponse {
    message: String,
    bytes_sent: usize,
}

#[tokio::main]
async fn main() -> Result<(), AppError> {
    // Initialize tracing subscriber
    tracing_subscriber::fmt().init();

    let app = Router::new()
        .route("/", get(root_handler))
        .route("/interfaces", get(get_all_interfaces_handler))
        .route("/send-packet", post(send_packet_handler));

    let addr_str = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let addr: SocketAddr = addr_str.parse().expect("Invalid LISTEN_ADDR format");

    info!("Listening on {}", addr);
    info!("Note: Sending raw packets typically requires administrator/root privileges.");

    axum::serve(tokio::net::TcpListener::bind(addr).await?, app)
        .await?;

    Ok(())
}

// --- Handlers ---
async fn root_handler() -> &'static str {
    "Hello, Network Tool API!"
}

#[instrument] // Automatically logs entry/exit and arguments
async fn get_all_interfaces_handler() -> Result<AxumJson<GetAllInterfacesResponse>, AppError> {
    info!("Fetching all network interfaces");
    let devices = pcap::Device::list()?; // Uses `?` and `AppError::from(pcap::Error)`

    let response = GetAllInterfacesResponse {
        interfaces: devices.into_iter().map(|d| d.name).collect(),
    };
    info!("Found {} interfaces", response.interfaces.len());
    Ok(AxumJson(response))
}

#[instrument(skip(request), fields(interface = %request.interface, packet_len = request.packet.len()))]
async fn send_packet_handler(
    AxumJson(request): AxumJson<SendPacketRequest>,
) -> Result<AxumJson<SendPacketResponse>, AppError> {
    info!("Attempting to send packet");

    // Validate if interface exists (optional but good practice)
    let _device = pcap::Device::list()?
        .into_iter()
        .find(|d| d.name == request.interface)
        .ok_or_else(|| AppError::InterfaceNotFound(request.interface.clone()))?;

    // from_device can take &str
    let mut cap = pcap::Capture::from_device(request.interface.as_str())?
        // .promisc(true) // Set promiscuous mode if needed for capture (not send)
        // .snaplen(65535) // Max snapshot length
        // .timeout(0) // Non-blocking open, or timeout in ms
        .open()?; // This opens an "inactive" capture that can be used for sending

    let packet_data = &request.packet[..];
    cap.sendpacket(packet_data)?;

    info!(
        "Packet ({} bytes) sent successfully to interface: {}",
        packet_data.len(),
        request.interface
    );

    let response = SendPacketResponse {
        message: "Packet sent successfully".to_string(),
        bytes_sent: packet_data.len(),
    };
    Ok(AxumJson(response))
}