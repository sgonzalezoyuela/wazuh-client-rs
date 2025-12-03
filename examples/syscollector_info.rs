//! Syscollector information example for the Wazuh Rust client
//!
//! This example demonstrates:
//! - Complete system inventory collection
//! - Hardware information gathering (CPU, RAM, motherboard)
//! - OS and system information
//! - Network topology discovery (interfaces, addresses, protocols)
//! - System users and groups enumeration
//! - Running services detection
//! - Windows hotfix/patch status
//! - Browser extensions inventory

use std::env;
use tracing::error;
use wazuh_client::{WazuhClientFactory, VulnerabilityClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    println!("🔍 Wazuh Rust Client - Syscollector Information Example");
    println!("========================================================");

    let factory = create_client_factory();

    // Test connectivity
    println!("🔍 Testing connectivity...");
    let connectivity = factory.test_connectivity().await?;
    if !connectivity.api_connected {
        error!(
            "❌ Cannot connect to Wazuh API: {}",
            connectivity.api_error.as_deref().unwrap_or("Unknown error")
        );
        return Err("API connectivity failed".into());
    }
    println!("✅ Connected to Wazuh API");

    let mut vulnerability_client = factory.create_vulnerability_client();
    let mut agents_client = factory.create_agents_client();

    println!("\n🤖 Selecting Active Agents");
    println!("===========================");

    let agents = agents_client.get_active_agents().await?;

    if agents.is_empty() {
        println!("❌ No active agents found");
        return Ok(());
    }

    println!("✅ Found {} active agents", agents.len());

    // Determine how many agents to process
    let agents_to_process = std::cmp::min(3, agents.len());
    println!("📋 Will display detailed information for the first {} agent(s)\n", agents_to_process);

    // Process first 3 agents
    for (idx, agent) in agents.iter().take(agents_to_process).enumerate() {
        println!("\n{}", "=".repeat(70));
        println!("📊 Agent #{}: {}", idx + 1, agent.name);
        println!("   ID: {}", agent.id);
        println!("   IP: {}", agent.ip.as_deref().unwrap_or("N/A"));
        println!("   Status: {}", agent.status);
        println!("{}", "=".repeat(70));

        display_agent_syscollector_info(&mut vulnerability_client, &agent.id).await;

        // Add spacing between agents
        if idx < agents_to_process - 1 {
            println!("\n");
        }
    }



    // Summary across all agents
    println!("\n\n🌍 Fleet-Wide System Inventory Summary");
    println!("======================================");
    println!("Processing {} agents for inventory overview...\n", agents.len());

    let mut os_distribution: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let mut total_cpu_cores = 0;
    let mut total_ram_gb = 0.0;
    let mut agents_processed = 0;

    for agent in agents.iter().take(10) {
        // Get OS info
        if let Ok(os_list) = vulnerability_client
            .get_os_info(&agent.id, None, None, None)
            .await
        {
            if let Some(os_info) = os_list.first() {
                if let Some(os) = &os_info.os {
                    let os_key = format!(
                        "{} {}",
                        os.name.as_deref().unwrap_or("Unknown"),
                        os.version.as_deref().unwrap_or("")
                    );
                    *os_distribution.entry(os_key).or_insert(0) += 1;
                }
            }
        }

        // Get hardware info
        if let Ok(hw_list) = vulnerability_client
            .get_hardware_info(&agent.id, None, None, None)
            .await
        {
            if let Some(hardware) = hw_list.first() {
                if let Some(cpu) = &hardware.cpu {
                    if let Some(cores) = cpu.cores {
                        total_cpu_cores += cores;
                    }
                }
                if let Some(ram) = &hardware.ram {
                    if let Some(total) = ram.total {
                        total_ram_gb += total as f64 / 1024.0 / 1024.0;
                    }
                }
            }
        }

        agents_processed += 1;
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
    }

    println!("📊 Infrastructure Statistics:");
    println!("   Agents Processed: {}", agents_processed);
    println!("   Total CPU Cores: {}", total_cpu_cores);
    println!("   Total RAM: {:.2} GB", total_ram_gb);

    if !os_distribution.is_empty() {
        println!("\n💿 Operating System Distribution:");
        let mut os_vec: Vec<_> = os_distribution.iter().collect();
        os_vec.sort_by(|a, b| b.1.cmp(a.1));
        for (os, count) in os_vec {
            println!("   {} - {} agent(s)", os.trim(), count);
        }
    }

    println!("\n✅ Syscollector information gathering complete!");

    Ok(())
}

/// Display comprehensive syscollector information for a single agent
async fn display_agent_syscollector_info(vulnerability_client: &mut VulnerabilityClient, agent_id: &str) {
    // Hardware Information
    println!("\n💻 Hardware Information");
    println!("----------------------");
    match vulnerability_client
        .get_hardware_info(agent_id, None, None, None)
        .await
    {
        Ok(hardware_list) => {
            if let Some(hardware) = hardware_list.first() {
                if let Some(cpu) = &hardware.cpu {
                    println!("CPU:");
                    if let Some(name) = &cpu.name {
                        println!("  Name: {}", name);
                    }
                    if let Some(cores) = cpu.cores {
                        println!("  Cores: {}", cores);
                    }
                    if let Some(mhz) = cpu.mhz {
                        println!("  Frequency: {:.2} MHz", mhz);
                    }
                }
                if let Some(ram) = &hardware.ram {
                    println!("RAM:");
                    if let Some(total) = ram.total {
                        println!("  Total: {} KB ({:.2} GB)", total, total as f64 / 1024.0 / 1024.0);
                    }
                    if let Some(free) = ram.free {
                        println!("  Free: {} KB ({:.2} GB)", free, free as f64 / 1024.0 / 1024.0);
                    }
                    if let Some(usage) = ram.usage {
                        println!("  Usage: {}%", usage);
                    }
                }
                if let Some(board_serial) = &hardware.board_serial {
                    if !board_serial.is_empty() {
                        println!("Board Serial: {}", board_serial);
                    }
                }
            } else {
                println!("  No hardware information available");
            }
        }
        Err(e) => println!("  ❌ Failed to get hardware info: {}", e),
    }

    // OS Information
    println!("\n🖥️  Operating System Information");
    println!("-------------------------------");
    match vulnerability_client
        .get_os_info(agent_id, None, None, None)
        .await
    {
        Ok(os_list) => {
            if let Some(os_info) = os_list.first() {
                if let Some(hostname) = &os_info.hostname {
                    println!("Hostname: {}", hostname);
                }
                if let Some(architecture) = &os_info.architecture {
                    println!("Architecture: {}", architecture);
                }
                if let Some(sysname) = &os_info.sysname {
                    println!("System Name: {}", sysname);
                }
                if let Some(os) = &os_info.os {
                    if let Some(name) = &os.name {
                        println!("OS Name: {}", name);
                    }
                    if let Some(platform) = &os.platform {
                        println!("Platform: {}", platform);
                    }
                    if let Some(version) = &os.version {
                        println!("Version: {}", version);
                    }
                    if let Some(codename) = &os.codename {
                        println!("Codename: {}", codename);
                    }
                }
            } else {
                println!("  No OS information available");
            }
        }
        Err(e) => println!("  ❌ Failed to get OS info: {}", e),
    }

    // Network Interfaces
    println!("\n🌐 Network Interfaces");
    println!("--------------------");
    match vulnerability_client
        .get_network_interfaces(agent_id, Some(5), None, None)
        .await
    {
        Ok(interfaces) => {
            if interfaces.is_empty() {
                println!("  No network interfaces found");
            } else {
                println!("  Found {} interface(s) (showing first 5):", interfaces.len());
                for (idx, iface) in interfaces.iter().enumerate() {
                    println!("\n  Interface #{}:", idx + 1);
                    if let Some(name) = &iface.name {
                        println!("    Name: {}", name);
                    }
                    if let Some(iface_type) = &iface.interface_type {
                        println!("    Type: {}", iface_type);
                    }
                    if let Some(state) = &iface.state {
                        println!("    State: {}", state);
                    }
                    if let Some(mac) = &iface.mac {
                        println!("    MAC: {}", mac);
                    }
                    if let Some(mtu) = iface.mtu {
                        println!("    MTU: {}", mtu);
                    }
                    if let Some(rx) = &iface.rx {
                        if let Some(bytes) = rx.bytes {
                            println!("    RX: {} bytes", bytes);
                        }
                    }
                    if let Some(tx) = &iface.tx {
                        if let Some(bytes) = tx.bytes {
                            println!("    TX: {} bytes", bytes);
                        }
                    }
                }
            }
        }
        Err(e) => println!("  ❌ Failed to get network interfaces: {}", e),
    }

    // Network Addresses
    println!("\n📍 Network Addresses");
    println!("-------------------");
    match vulnerability_client
        .get_network_addresses(agent_id, Some(10), None, None)
        .await
    {
        Ok(addresses) => {
            if addresses.is_empty() {
                println!("  No network addresses found");
            } else {
                for addr in addresses.iter() {
                    if let (Some(iface), Some(address)) = (&addr.iface, &addr.address) {
                        print!("  {} -> {}", iface, address);
                        if let Some(netmask) = &addr.netmask {
                            print!(" / {}", netmask);
                        }
                        if let Some(proto) = &addr.proto {
                            print!(" ({})", proto);
                        }
                        println!();
                    }
                }
            }
        }
        Err(e) => println!("  ❌ Failed to get network addresses: {}", e),
    }

    // System Users (top 5)
    println!("\n👥 System Users (Top 5)");
    println!("----------------------");
    match vulnerability_client
        .get_users(agent_id, Some(5), None, None)
        .await
    {
        Ok(users) => {
            if users.is_empty() {
                println!("  No user information found");
            } else {
                for user_info in users.iter() {
                    if let Some(user) = &user_info.user {
                        if let Some(name) = &user.name {
                            print!("  • {}", name);
                            if let Some(id) = user.id {
                                print!(" (UID: {})", id);
                            }
                            if let Some(home) = &user.home {
                                print!(" - Home: {}", home);
                            }
                            println!();
                        }
                    }
                }
            }
        }
        Err(e) => println!("  ❌ Failed to get users: {}", e),
    }

    // Running Services (top 10)
    println!("\n⚙️  Running Services (Top 10)");
    println!("--------------------------");
    match vulnerability_client
        .get_services(agent_id, Some(10), None, None)
        .await
    {
        Ok(services) => {
            if services.is_empty() {
                println!("  No service information found");
            } else {
                for svc_info in services.iter() {
                    if let Some(service) = &svc_info.service {
                        if let Some(name) = &service.name {
                            print!("  • {}", name);
                            if let Some(state) = &service.state {
                                print!(" [{}]", state);
                            }
                            println!();
                        }
                    }
                }
            }
        }
        Err(e) => println!("  ❌ Failed to get services: {}", e),
    }

    // Windows Hotfixes (if applicable)
    println!("\n🔧 Windows Hotfixes");
    println!("------------------");
    match vulnerability_client
        .get_hotfixes(agent_id, Some(5), None, None)
        .await
    {
        Ok(hotfixes) => {
            if hotfixes.is_empty() {
                println!("  Not applicable (not a Windows agent)");
            } else {
                println!("  Found {} hotfix(es) (showing first 5):", hotfixes.len());
                for hotfix in hotfixes.iter() {
                    if let Some(kb) = &hotfix.hotfix {
                        println!("  • {}", kb);
                    }
                }
            }
        }
        Err(e) => {
            if !e.to_string().contains("404") {
                println!("  ❌ Failed to get hotfixes: {}", e);
            } else {
                println!("  Not applicable (not a Windows agent)");
            }
        }
    }

    // Browser Extensions
    println!("\n🔍 Browser Extensions");
    println!("--------------------");
    match vulnerability_client
        .get_browser_extensions(agent_id, Some(5), None, None)
        .await
    {
        Ok(extensions) => {
            if extensions.is_empty() {
                println!("  No browser extensions found");
            } else {
                println!("  Found {} extension(s) (showing first 5):", extensions.len());
                for ext in extensions.iter() {
                    if let Some(package) = &ext.package {
                        if let Some(name) = &package.name {
                            print!("  • {}", name);
                            if let Some(version) = &package.version {
                                print!(" v{}", version);
                            }
                            if let Some(browser) = &ext.browser {
                                if let Some(browser_name) = &browser.name {
                                    print!(" ({})", browser_name);
                                }
                            }
                            println!();
                        }
                    }
                }
            }
        }
        Err(e) => {
            if !e.to_string().contains("404") {
                println!("  ❌ Failed to get browser extensions: {}", e);
            } else {
                println!("  No browser extension data available");
            }
        }
    }
}

fn create_client_factory() -> WazuhClientFactory {
    let api_host = env::var("WAZUH_API_HOST").unwrap_or_else(|_| "localhost".to_string());
    let api_port: u16 = env::var("WAZUH_API_PORT")
        .unwrap_or_else(|_| "55000".to_string())
        .parse()
        .unwrap_or(55000);
    let api_username = env::var("WAZUH_API_USERNAME").unwrap_or_else(|_| "wazuh".to_string());
    let api_password = env::var("WAZUH_API_PASSWORD").unwrap_or_else(|_| "wazuh".to_string());

    let indexer_host = env::var("WAZUH_INDEXER_HOST").unwrap_or_else(|_| "localhost".to_string());
    let indexer_port: u16 = env::var("WAZUH_INDEXER_PORT")
        .unwrap_or_else(|_| "9200".to_string())
        .parse()
        .unwrap_or(9200);
    let indexer_username =
        env::var("WAZUH_INDEXER_USERNAME").unwrap_or_else(|_| "admin".to_string());
    let indexer_password =
        env::var("WAZUH_INDEXER_PASSWORD").unwrap_or_else(|_| "admin".to_string());

    let verify_ssl = env::var("WAZUH_VERIFY_SSL")
        .unwrap_or_else(|_| "false".to_string())
        .parse()
        .unwrap_or(false);

    WazuhClientFactory::builder()
        .api_host(api_host)
        .api_port(api_port)
        .api_credentials(api_username, api_password)
        .indexer_host(indexer_host)
        .indexer_port(indexer_port)
        .indexer_credentials(indexer_username, indexer_password)
        .verify_ssl(verify_ssl)
        .protocol("https")
        .build()
}
