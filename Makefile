.PHONY: all
all: c csharp go java nim nodejs python rust

.PHONY: c
c:
	@echo "[+] Building and testing $@"
	@make -C src

.PHONY: csharp
csharp:
	@echo "[+] Building and testing $@"
	@make -C bindings/csharp

.PHONY: go
go:
	@echo "[+] Building and testing $@"
	@cd bindings/go && go clean -cache && go test

.PHONY: java
java:
	@echo "[+] Building and testing $@"
	@make -C bindings/java

.PHONY: nim
nim:
	@echo "[+] Building and testing $@"
	@cd bindings/nim && nim test

.PHONY: nodejs
nodejs:
	@echo "[+] Building and testing $@"
	@make -C bindings/node.js

.PHONY: python
python:
	@echo "[+] Building and testing $@"
	@make -C bindings/python

.PHONY: rust
rust:
	@echo "[+] Building and testing $@"
	@cargo test --features generate-bindings
	@cargo bench --no-run
	@cd fuzz && cargo build