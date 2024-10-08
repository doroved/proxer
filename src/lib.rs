use base64::{engine::general_purpose::STANDARD as b64, Engine as _};
use chrono::Local;
use clap::Parser;
use hyper::{Body, Client, Method, Request, Response, StatusCode};
use rand::{rngs::StdRng, thread_rng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    option,
    process::Command,
    string::FromUtf8Error,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use tokio_native_tls::{native_tls, TlsConnector};
use toml::from_str;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    Resolver, TokioAsyncResolver,
};
use wildmatch::WildMatch;

//
#[derive(Default, Debug, Clone)]
pub struct DpiBypassOptions {
    pub tcp_fragmentation: bool,
    pub keep_alive_fragmentation: bool,
    pub replace_host_header: bool,
    pub remove_space_in_host_header: bool,
    // add_space_in_method: bool,
    pub mix_host_header_case: bool,
    pub send_fake_packets: bool,
}

impl DpiBypassOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enable_all(&mut self) {
        self.tcp_fragmentation = true;
        self.keep_alive_fragmentation = true;
        self.replace_host_header = true;
        self.remove_space_in_host_header = true;
        // self.add_space_in_method = true;
        self.mix_host_header_case = true;
        self.send_fake_packets = true;
    }
}

// Struct for storing package information
#[derive(Debug, Deserialize)]
pub struct CargoToml {
    pub package: Package,
}

#[derive(Debug, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
}

// Struct for storing proxy configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
struct AuthCredentials {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Filter {
    name: String,
    domains: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProxyConfig {
    name: String,
    enabled: bool,
    scheme: String,
    host: String,
    port: u16,
    auth_credentials: AuthCredentials,
    filter: Vec<Filter>,
}

pub struct Proxy {
    pub interface: String,
    pub server: String,
    pub port: u16,
}

#[derive(Parser, Debug, Clone)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    /// Delay in milliseconds
    #[clap(short, long, default_value_t = 1000)]
    delay: u64,

    /// DNS over HTTPS
    #[clap(long)]
    doh: bool,

    /// DNS over TLS
    #[clap(long)]
    dot: bool,

    /// Fragment size
    #[clap(long)]
    fragment_size: Option<i32>,

    /// Size of the first fragment
    #[clap(long, default_value_t = 1)]
    first_fragment_size: usize,
}

// Handle HTTP and HTTPS requests
pub async fn handle_request(
    req: Request<Body>,
    config: Arc<Vec<ProxyConfig>>,
    options: Arc<DpiBypassOptions>,
    args: Args,
) -> Result<Response<Body>, hyper::Error> {
    let addr = req.uri().authority().unwrap().to_string();
    let time = formatted_time();

    if req.method() == Method::CONNECT {
        if let Some(_) = req.uri().authority().map(|auth| auth.to_string()) {
            let config_clone = Arc::clone(&config);
            let options_clone = Arc::clone(&options);

            tokio::spawn(async move {
                match tunnel(req, config_clone, options_clone, &args).await {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("\x1B[31m\x1B[1m[{time}] {} -> {}\x1B[0m", addr, e);
                    }
                }
            });

            Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap())
        } else {
            Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Invalid CONNECT request"))
                .unwrap())
        }
    } else {
        println!("HTTP request {}", req.uri().to_string());
        // TODO: Proxy HTTP requests based on allow_hosts

        // Create client for HTTP request
        let client = Client::new();

        // Copy the necessary data from req
        let method = req.method().clone();
        let uri = req.uri().clone();
        let headers = req.headers().clone();
        let body = req.into_body();

        // Create a new request
        let mut new_req = match Request::builder().method(method).uri(uri).body(body) {
            Ok(req) => req,
            Err(e) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Body::from(format!("Error creating request: {}", e)))
                    .unwrap())
            }
        };

        // Copy headers
        new_req.headers_mut().extend(headers);

        // Send the request and return the response
        client.request(new_req).await
    }
}

async fn tunnel(
    req: Request<Body>,
    config: Arc<Vec<ProxyConfig>>,
    options: Arc<DpiBypassOptions>,
    args: &Args,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = req.uri().authority().unwrap().to_string();
    let host = req.uri().host().unwrap();

    let host_ip = resolve_host(host, &args).await?;
    let resolve_addr = format!("{}:{}", host_ip, req.uri().port_u16().unwrap_or(80));

    let time = formatted_time();

    match find_matching_proxy(config.as_ref(), host) {
        Some(proxy) => {
            println!(
                "\x1B[34m\x1B[1m[{time}] {} ({}) -> {} · {}\x1B[0m",
                addr, host_ip, proxy.name, proxy.scheme
            );

            let proxy_addr = format!("{}:{}", proxy.host, proxy.port);
            let proxy_user = proxy.auth_credentials.username;
            let proxy_pass = proxy.auth_credentials.password;

            let tcp_stream =
                timeout(Duration::from_secs(10), TcpStream::connect(&proxy_addr)).await??;

            match proxy.scheme.as_str() {
                "HTTP" => {
                    handle_http_proxy(req, tcp_stream, &resolve_addr, &proxy_user, &proxy_pass)
                        .await?;
                }
                "HTTPS" => {
                    handle_https_proxy(
                        req,
                        tcp_stream,
                        &resolve_addr,
                        &proxy.host,
                        &proxy_user,
                        &proxy_pass,
                    )
                    .await?;
                }
                _ => return Err(format!("Unsupported proxy scheme: {}", proxy.scheme).into()),
            }

            return Ok(());
        }
        None => {
            println!("[{time}] {} ({}) -> Direct connection", addr, host_ip);

            // Connect to the server
            let mut server =
                timeout(Duration::from_secs(10), TcpStream::connect(&resolve_addr)).await??;

            // Get the upgraded connection from the client
            let upgraded = hyper::upgrade::on(req).await?;
            let (mut client_reader, mut client_writer) = tokio::io::split(upgraded);

            // Buffer for reading the first bytes of Client Hello
            let mut buffer = [0u8; 1024];
            let mut bytes_read = 0;

            // Read the first bytes of Client Hello
            // while bytes_read < 5 {
            //     // Minimum length of TLS record
            //     let n = client_reader.read(&mut buffer[bytes_read..]).await?;
            //     if n == 0 {
            //         return Err("Connection closed".into());
            //     }
            //     bytes_read += n;
            // }
            // Читаем первый пакет данных
            while bytes_read < buffer.len() {
                let n = client_reader.read(&mut buffer[bytes_read..]).await?;
                if n == 0 {
                    break;
                }
                bytes_read += n;
            }

            let mut modified_buffer = buffer[..bytes_read].to_vec();

            // Применяем методы обхода DPI
            if options.replace_host_header {
                replace_host_header(&mut modified_buffer);
            }
            if options.remove_space_in_host_header {
                remove_space_in_host_header(&mut modified_buffer);
            }
            // if options.add_space_in_method {
            //     add_space_in_method(&mut modified_buffer);
            // }
            if options.mix_host_header_case {
                mix_host_header_case(&mut modified_buffer);
            }

            // Отправка фейковых пакетов
            // if options.send_fake_packets {
            //     // send_fake_packets(&addr, rng).await?;
            //     add_fake_data(&mut modified_buffer);
            // }

            if let Some(fragment_size) = args.fragment_size {
                println!("Set fragment_size");
                // Разделяем пакет на мелкие фрагменты и отправляем их с задержками
                let fragments = split_into_fragments(&modified_buffer, fragment_size);
                for fragment in fragments {
                    server.write_all(&fragment).await?;

                    // Случайная задержка между фрагментами
                    // let delay = thread_rng().gen_range(10..100);
                    // tokio::time::sleep(Duration::from_millis(1)).await;

                    // Отправка "мусорных" данных
                    // if thread_rng().gen_bool(0.5) {
                    //     let junk = generate_junk_data();
                    //     server.write_all(&junk).await?;
                    // }
                }
            } else {
                println!("Set first_fragment_size");

                // TCP-level fragmentation
                if options.tcp_fragmentation {
                    // let first_fragment_size = 1;
                    let first_fragment_size = args.first_fragment_size;

                    server
                        .write_all(&modified_buffer[..first_fragment_size])
                        .await?;
                    tokio::time::sleep(Duration::from_millis(args.delay)).await;
                    server
                        .write_all(&modified_buffer[first_fragment_size..])
                        .await?;
                } else {
                    server.write_all(&modified_buffer).await?;
                }
            }

            //
            // Отправка "мусорных" данных
            // if thread_rng().gen_bool(0.5) {
            //     let junk = generate_junk_data();
            //     server.write_all(&junk).await?;
            // }

            // Send the first byte to the server
            // server.write_all(&modified_buffer[..1]).await?;

            // Send the rest of the bytes to the server
            // server.write_all(&modified_buffer[1..]).await?;

            // Split the server connection into reader and writer
            let (mut server_reader, mut server_writer) = server.split();

            // Copy data from client to server
            // let client_to_server = async {
            //     tokio::io::copy(&mut client_reader, &mut server_writer).await?;
            //     server_writer.shutdown().await
            // };
            let client_to_server = async {
                if options.keep_alive_fragmentation {
                    handle_keep_alive_fragmentation(&mut client_reader, &mut server_writer).await?;
                } else {
                    tokio::io::copy(&mut client_reader, &mut server_writer).await?;
                }
                server_writer.shutdown().await
            };

            // Copy data from server to client
            let server_to_client = async {
                tokio::io::copy(&mut server_reader, &mut client_writer).await?;
                client_writer.shutdown().await
            };

            // Wait for both tasks to complete
            tokio::try_join!(client_to_server, server_to_client)?;

            return Ok(());
        }
    };
}

pub fn get_default_interface() -> String {
    // Use networksetup to get the default interface
    let output = Command::new("bash")
        .arg("-c")
        .arg("networksetup -listnetworkserviceorder | grep `(route -n get default | grep 'interface' || route -n get -inet6 default | grep 'interface') | cut -d ':' -f2` -B 1 | head -n 1 | cut -d ' ' -f 2-")
        .output()
        .expect("Failed to get default interface");

    // Convert the result to a string
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn package_info() -> Package {
    let content = include_str!("../Cargo.toml");

    // Parse the content of the file
    let cargo: CargoToml = from_str(&content).expect("Error parsing Cargo.toml");

    // Return the package information
    cargo.package
}

pub fn terminate_proxer() {
    let _ = Command::new("sh")
        .args(&["-c", "kill $(pgrep proxer)"])
        .output()
        .expect("Failed to execute `kill $(pgrep proxer)` command to terminate proxer processes");
}

fn is_host_allowed(req_host: &str, allowed_hosts: &[String]) -> bool {
    for allowed_host in allowed_hosts {
        if WildMatch::new(allowed_host).matches(req_host) {
            return true;
        }
    }
    false
}

// Implement a function to load the configuration from a JSON file and search for a matching proxy
pub fn find_matching_proxy(config_file: &[ProxyConfig], req_host: &str) -> Option<ProxyConfig> {
    // Read the contents of the file proxer.json5
    for config in config_file {
        // Skip disabled proxies
        if !config.enabled {
            continue;
        }

        // Find by filters
        for filter in &config.filter {
            if is_host_allowed(req_host, &filter.domains) {
                return Some(config.clone());
            }
        }
    }

    None
}

fn formatted_time() -> String {
    let now = Local::now();
    now.format("%H:%M:%S").to_string()
    // now.format("%Y-%m-%d %H:%M:%S").to_string()
}

async fn handle_http_proxy(
    req: Request<Body>,
    mut tcp_stream: TcpStream,
    addr: &str,
    proxy_user: &str,
    proxy_pass: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    send_connect_request(req, &mut tcp_stream, addr, proxy_user, proxy_pass).await?;
    Ok(())
}

async fn handle_https_proxy(
    req: Request<Body>,
    tcp_stream: TcpStream,
    addr: &str,
    proxy_host: &str,
    proxy_user: &str,
    proxy_pass: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let connector = TlsConnector::from(native_tls::TlsConnector::new()?);
    let mut tls_stream = timeout(
        Duration::from_secs(10),
        connector.connect(proxy_host, tcp_stream),
    )
    .await??;

    send_connect_request(req, &mut tls_stream, addr, proxy_user, proxy_pass).await?;
    Ok(())
}

async fn send_connect_request<T>(
    req: Request<Body>,
    stream: &mut T,
    addr: &str,
    proxy_user: &str,
    proxy_pass: &str,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    let package = package_info();
    let auth = b64.encode(format!("{}:{}", proxy_user, proxy_pass));
    let connect_req = format!(
        "CONNECT {} HTTP/1.1\r\n\
        Host: {}\r\n\
        Proxy-Connection: Keep-Alive\r\n\
        Proxy-Authorization: Basic {}\r\n\
        User-Agent: {}/{}\r\n\
        \r\n",
        addr, addr, auth, package.name, package.version
    );

    stream.write_all(connect_req.as_bytes()).await?;

    let mut response = [0u8; 1024];
    let n = timeout(Duration::from_secs(5), stream.read(&mut response)).await??;

    if !response[..n].starts_with(b"HTTP/1.1 200") {
        return Err(format!(
            "Proxy connection failed: {:?}",
            String::from_utf8_lossy(&response[..n])
        )
        .into());
    }

    let upgraded = hyper::upgrade::on(req).await?;

    let (mut proxy_reader, mut proxy_writer) = tokio::io::split(stream);
    let (mut client_reader, mut client_writer) = tokio::io::split(upgraded);

    let client_to_server = tokio::io::copy(&mut client_reader, &mut proxy_writer);
    let server_to_client = tokio::io::copy(&mut proxy_reader, &mut client_writer);

    tokio::try_join!(client_to_server, server_to_client)?;

    Ok(())
}

impl Proxy {
    pub fn init(interface: String, server: &str, port: u16) -> Self {
        Proxy {
            interface,
            server: String::from(server),
            port,
        }
    }

    pub fn set(&self) {
        // Define proxy types
        let proxy_types = self.get_proxy_types();

        // Go through each proxy type and set server and port
        for proxy_type in proxy_types.iter() {
            let command = format!("-set{}", proxy_type);

            let _ = self
                .execute_command(&[
                    &command,
                    &self.interface,
                    &self.server,
                    &self.port.to_string(),
                ])
                .expect(&format!("Failed to set {}", proxy_type));
        }
    }

    pub fn set_state(&self, state: &str) {
        let proxy_types = self.get_proxy_types();

        for proxy_type in proxy_types.iter() {
            let command = format!("-set{}state", proxy_type);

            let _ = self
                .execute_command(&[&command, &self.interface, state])
                .expect(&format!("Failed to set {} state", proxy_type));
        }
    }

    fn get_proxy_types(&self) -> [&'static str; 2] {
        ["webproxy", "securewebproxy"]
    }

    fn execute_command(&self, args: &[&str]) -> Result<String, FromUtf8Error> {
        let output = Command::new("networksetup")
            .args(args)
            .output()
            .expect("Failed to execute command");

        String::from_utf8(output.stdout)
    }
}

///////
fn replace_host_header(buffer: &mut Vec<u8>) {
    let host_header = b"Host:";
    if let Some(pos) = find_subsequence(buffer, host_header) {
        buffer[pos + 2] = b'S';
    }
}

fn remove_space_in_host_header(buffer: &mut Vec<u8>) {
    let host_header = b"Host: ";
    if let Some(pos) = find_subsequence(buffer, host_header) {
        buffer.remove(pos + 4);
    }
}

// fn add_space_in_method(buffer: &mut Vec<u8>) {
//     let methods = vec![b"GET ", b"POST ", b"PUT ", b"DELETE "];
//     for method in &methods {
//         if let Some(pos) = find_subsequence(buffer, method) {
//             buffer.insert(pos + method.len() - 1, b' ');
//             break;
//         }
//     }
// }

fn mix_host_header_case(buffer: &mut Vec<u8>) {
    let host_header = b"Host:";
    if let Some(pos) = find_subsequence(buffer, host_header) {
        let end = buffer[pos..]
            .iter()
            .position(|&x| x == b'\r')
            .unwrap_or(buffer.len() - pos)
            + pos;
        for i in pos + 5..end {
            if buffer[i].is_ascii_alphabetic() {
                buffer[i] ^= 0x20;
            }
        }
    }
}

async fn handle_keep_alive_fragmentation<R, W>(
    reader: &mut R,
    writer: &mut W,
) -> Result<(), std::io::Error>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let mut buffer = vec![0u8; 4096];
    loop {
        let n = reader.read(&mut buffer).await?;
        if n == 0 {
            break;
        }

        let first_fragment_size = 1;
        writer.write_all(&buffer[..first_fragment_size]).await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        writer.write_all(&buffer[first_fragment_size..n]).await?;
    }
    Ok(())
}

async fn send_fake_packets(addr: &str, rng: &mut StdRng) -> Result<(), std::io::Error> {
    // let mut rng = thread_rng();
    let fake_data: Vec<u8> = (0..100).map(|_| rng.gen()).collect();
    println!("fake_data: {:?}", fake_data);

    let socket = TcpStream::connect(addr).await?;
    socket.set_ttl(1)?;

    let (mut reader, mut writer) = socket.into_split();

    writer.write_all(&fake_data).await?;

    let mut response = vec![0u8; 1024];
    // let _ = tokio::time::timeout(Duration::from_millis(100), reader.read(&mut response)).await;
    let resp = tokio::time::timeout(Duration::from_millis(100), reader.read(&mut response)).await;
    println!("resp: {:?}", resp);

    Ok(())
}

fn add_fake_data(buffer: &mut Vec<u8>) {
    let mut rng = rand::thread_rng();
    let fake_data_length = rng.gen_range(10..=100);
    let fake_data: Vec<u8> = (0..fake_data_length).map(|_| rng.gen()).collect();
    buffer.extend_from_slice(&fake_data);
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn split_into_fragments(buffer: &[u8], fragment_size: i32) -> Vec<Vec<u8>> {
    // let mut rng = thread_rng();
    let mut fragments = Vec::new();
    let mut start = 0;
    while start < buffer.len() {
        // let fragment_size = rng.gen_range(1..=100);
        let end = (start + fragment_size as usize).min(buffer.len()); // 2
        fragments.push(buffer[start..end].to_vec());
        start = end;
    }
    // println!("fragments: {:?}", fragments);
    fragments
}

fn generate_junk_data() -> Vec<u8> {
    let mut rng = thread_rng();
    let junk_size = rng.gen_range(1..=10);
    (0..junk_size).map(|_| rng.gen()).collect()
}

// pub async fn resolve_host(host: &str) -> Result<IpAddr, std::io::Error> {
//     // let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
//     // let lookup = resolver.lookup_ip(host).await?;

//     // Construct a new Resolver with default configuration options
//     let resolver = TokioAsyncResolver::tokio(
//         ResolverConfig::cloudflare_tls(), // Use Cloudflare DNS
//         ResolverOpts::default(),
//     );

//     // On Unix/Posix systems, this will read the /etc/resolv.conf
//     // let  resolver = Resolver::from_system_conf().unwrap();

//     // Lookup the IP addresses associated with a name.
//     let response = resolver.lookup_ip(host).await?;
//     let address = response.iter().next().expect("no addresses returned!");
//     // println!("HOST: {}, IP: {}", host, address);

//     // There can be many addresses associated with the name,
//     //  this can return IPv4 and/or IPv6 addresses
//     // let address = response.iter().next().expect("no addresses returned!");
//     // if address.is_ipv4() {
//     //     assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
//     // } else {
//     //     assert_eq!(
//     //         address,
//     //         IpAddr::V6(Ipv6Addr::new(
//     //             0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946
//     //         ))
//     //     );
//     // }
//     Ok(address)
// }

pub async fn resolve_host(host: &str, args: &Args) -> Result<IpAddr, std::io::Error> {
    let resolver = if args.doh {
        println!("Set DoH");
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default())
    } else if args.dot {
        println!("Set DoT");
        TokioAsyncResolver::tokio(ResolverConfig::cloudflare_tls(), ResolverOpts::default())
    } else {
        TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default())
    };

    let response = resolver.lookup_ip(host).await?;
    let address = response.iter().next().expect("no addresses returned!");
    Ok(address)
}
