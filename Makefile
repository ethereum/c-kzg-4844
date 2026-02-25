.PHONY: all
all: c csharp elixir go java nim nodejs python rust

.PHONY: c
c:
	@$(MAKE) -C src

.PHONY: csharp
csharp:
	@$(MAKE) -C bindings/csharp

.PHONY: elixir
elixir:
	@mix deps.get && mix test

.PHONY: go
go:
	@cd bindings/go && go clean -cache && go test

.PHONY: java
java:
	@$(MAKE) -C bindings/java build test

.PHONY: nim
nim:
	@cd bindings/nim && nim test

.PHONY: nodejs
nodejs:
	@$(MAKE) -C bindings/node.js

.PHONY: python
python:
	@$(MAKE) -C bindings/python

.PHONY: rust
rust:
	@cargo test --features generate-bindings
	@cargo bench --no-run
	@cd fuzz && cargo build
