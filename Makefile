.PHONY: client client-test secretstore secretstore-test default

default:
	@echo "Please specify the target directly"
	@echo "client			Builds the client"
	@echo "client-test		Runs client tests"
	@echo "secretstore		Builds secretstore server"
	@echo "secretstore-test	Runs secretstore server tests"
	exit 1


build-secret-store-server: build_res/configuration.rs build_res/server.rs build_res/Cargo.toml
	cp -f build_res/configuration.rs openethereum/parity/configuration.rs
	cp -f build_res/server.rs openethereum/parity/secretstore/server.rs
	cp -f build_res/Cargo.toml openethereum/Cargo.toml
	cd openethereum; cargo build --features "secretstore" --release -p openethereum; cd ..

client:
	cargo +nightly build -p client --release

client-test: build-secret-store-server
	cp -f openethereum/target/release/openethereum client/test_res/openethereum_with_secretstore
	cargo +nightly test -p client

secretstore: build-secret-store-server
	mkdir -p target
	cp -f openethereum/target/release/openethereum target/secretstore

secretstore-test:
	cargo test -p parity-secretstore
