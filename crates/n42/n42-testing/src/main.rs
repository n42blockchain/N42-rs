mod dev;
mod utils;

#[tokio::main]
async fn main() {
    println!("Hello, world!");
}

#[tokio::test]
async fn test_main() {
    println!("test_main");
}

