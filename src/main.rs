use clap::Parser;
use futures::stream::StreamExt;
use hyper::{
    service::{make_service_fn, service_fn},
    Server,
};
use port_check::*;
use proxer::{
    get_default_interface, handle_request, resolve_host, terminate_proxer, Args, DpiBypassOptions,
    Proxy, ProxyConfig,
};
use signal_hook::consts::signal::*;
use signal_hook_tokio::Signals;
use std::sync::Arc;
use std::{fs, net::SocketAddr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Close all proxer processes
    terminate_proxer();

    // Read the config file
    // let config_file = "proxer.json5";
    let config_str = r#"
        [
        {
        name: "My dumbproxy [NL]",
        enabled: false, // false to disable
        scheme: "HTTPS", // HTTP, HTTPS
        host: "proxy.example.com",
        port: 8443,
        auth_credentials: {
          username: "admin",
          password: "hello",
        },
          filter: [
            {
              name: "Test",
              domains: ["2ip.io", "whoer.net", "*.facebook.com", "twitter.com"],
            },
          ],
        },
      ]
        "#;
    // let config = fs::read_to_string(config_file).expect("Error reading config file");
    let parsed_config: Vec<ProxyConfig> =
        json5::from_str(&config_str).expect("Error parsing config file");
    let shared_config = Arc::new(parsed_config);

    // Get the default interface
    let interface = get_default_interface();

    // Check if the default interface is empty
    if interface.is_empty() {
        eprintln!("Failed to find default interface. If you have VPN enabled, try disabling it and running the program again.");
        return Ok(());
    } else {
        println!("Default interface: {}", interface);
    }

    // Find a free port
    let port = free_local_port().unwrap();

    // Create a system proxy with the default interface and the free port
    let system_proxy = Proxy::init(interface, "127.0.0.1", port);
    system_proxy.set();
    system_proxy.set_state("on");

    // Create an Arc around the system proxy
    let system_proxy_arc = Arc::new(system_proxy);

    // Set up signal handling
    let mut signals = Signals::new(&[SIGINT, SIGTERM, SIGQUIT])?;
    let handle = signals.handle();

    // Start signal handler in a separate task
    let signals_task = tokio::spawn(async move {
        while let Some(signal) = signals.next().await {
            match signal {
                SIGINT | SIGTERM | SIGQUIT => {
                    system_proxy_arc.set_state("off");
                    std::process::exit(0);
                }
                _ => unreachable!(),
            }
        }
    });

    // Create a server and bind it to the socket address
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let mut options = DpiBypassOptions::new();
    options.tcp_fragmentation = true;
    options.keep_alive_fragmentation = false;
    options.replace_host_header = false;
    options.remove_space_in_host_header = false;
    // options.add_space_in_method = false;
    options.mix_host_header_case = false;
    options.send_fake_packets = false;
    // options.enable_all();

    let options = Arc::new(options);

    // Create a service builder to handle incoming connections
    // let make_svc = make_service_fn(move |_conn| {
    //     let config = Arc::clone(&shared_config);
    //     let options = Arc::clone(&options);

    //     async {
    //         Ok::<_, hyper::Error>(service_fn(move |req| {
    //             handle_request(req, Arc::clone(&config), Arc::clone(&options))
    //         }))
    //     }
    // });

    // Create a service builder to handle incoming connections
    let make_svc = make_service_fn(move |_conn| {
        let config = Arc::clone(&shared_config);
        let options = Arc::clone(&options);
        let args = args.clone();

        async move {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                let config = Arc::clone(&config);
                let options = Arc::clone(&options);
                let args = args.clone();
                async move { handle_request(req, config, options, args).await }
            }))
        }
    });

    // Bind the server to the socket address and start listening
    let server = Server::bind(&addr).serve(make_svc);

    println!("Listening on http://{}", addr);

    // Run the server and wait for the error
    if let Err(e) = server.await {
        eprintln!("Server error: {}", e);
    }

    // Terminate the signal stream.
    handle.close();
    signals_task.await?;

    Ok(())
}
