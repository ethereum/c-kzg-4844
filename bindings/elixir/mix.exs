defmodule KZG.MixProject do
  use Mix.Project

  @version "0.1.0-dev"

  def project do
    [
      app: :kzg,
      compilers: [:elixir_make] ++ Mix.compilers(),
      make_precompiler: {:nif, CCPrecompiler},
      make_precompiler_priv_paths: ["ckzg_nif.*"],
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
