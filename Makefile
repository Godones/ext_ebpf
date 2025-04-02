



simple-ebpf:
	cargo +nightly build -p simple-ebpf --target=bpfel-unknown-none -Z build-std=core --release




.PHONY: simple-ebpf