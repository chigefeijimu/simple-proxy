use pingora::prelude::*;
use simple_proxy::SimpleProxy;
use tracing::info;
use tracing_subscriber::fmt::time::ChronoLocal;

fn main() -> Result<()> {
    // 配置日志使用本地时间
    tracing_subscriber::fmt()
        .with_timer(ChronoLocal::rfc_3339())
        .with_thread_ids(true)
        .with_target(true)
        .with_file(true)
        .with_line_number(true)
        .init();

    let mut server = Server::new(None)?;
    server.bootstrap();

    let proxy_addr = "0.0.0.0:8999";
    let sp = SimpleProxy {};
    let mut proxy = http_proxy_service(&server.configuration, sp);
    proxy.add_tcp(proxy_addr);
    info!("proxy server is running on {}", proxy_addr);
    server.add_service(proxy);
    
    server.run_forever()
}
