sudo apt install git curl build-essential
curl --proto '=https' --tlsv1.2 https://sh.rustup.rs -sSf | sh
git clone https://github.com/tedkim97/adcache.git
cd adcache
cargo build --release
# sudo ./target/release/adcache --listener-addr XXX --forward-addr XXX

# dnsperf -s XXXX -d perfinput.txt -T X -q X -n X
