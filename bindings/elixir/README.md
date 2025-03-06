# Elixir Bindings for the C-KZG Library

This directory contains Elixir bindings for the C-KZG-4844 library.

## Prerequisites

Make sure `elixir` and `erlang` are installed. You can learn how to do so [here](https://elixir-lang.org/install.html).

## Installation

If [available in Hex](https://hex.pm/docs/publish), the package can be installed
by adding `ckzg` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ckzg, "~> 0.2.1"}
  ]
end
```

## Build

```sh
mix deps.get
mix compile
```

## Test

```sh
mix test
```
