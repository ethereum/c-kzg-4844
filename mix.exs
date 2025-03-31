defmodule CKZG.MixProject do
  use Mix.Project

  @version "2.1.1"

  def project do
    # Make cwd always `bindings/elixir`.
    cwd = File.cwd!()
    elixir_path = Path.join(["bindings", "elixir"])

    with false <- String.ends_with?(cwd, elixir_path),
         true <- File.dir?(Path.join(cwd, elixir_path)) do
      File.cd!(Path.join(cwd, elixir_path))
    end

    [
      app: :ckzg,
      compilers: [:elixir_make] ++ Mix.compilers(),
      make_precompiler_url:
        "https://github.com/ethereum/c-kzg-4844/releases/download/v#{@version}/@{artefact_filename}",
      make_precompiler_filename: "nif",
      make_precompiler: {:nif, CCPrecompiler},
      make_precompiler_priv_paths: ["ckzg_nif.*"],
      make_force_build: Mix.env() == :test,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp deps do
    [
      {:cc_precompiler, "~> 0.1.10", runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:elixir_make, "~> 0.4", runtime: false},
      {:yaml_elixir, "~> 2.11.0", only: [:dev, :test], runtime: false}
    ]
  end
end
