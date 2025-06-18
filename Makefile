

ebpf_list = simple-ebpf complex-ebpf


build: $(ebpf_list)

$(ebpf_list):
	cargo +nightly build -p $@ --target=bpfel-unknown-none -Z build-std=core --release
	@echo "Built $@ successfully"
	rust-objdump -dr target/bpfel-unknown-none/release/$@ 
# cargo +nightly build -p simple-ebpf --target=bpfel-unknown-none -Z build-std=core --release
# rust-objdump -dr target/bpfel-unknown-none/release/simple-ebpf



.PHONY: simple-ebpf