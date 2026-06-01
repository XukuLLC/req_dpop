defmodule ReqDPoP.MixProject do
  @moduledoc false
  use Mix.Project

  @version "0.5.0"
  @url "https://github.com/neilberkman/req_dpop"
  @maintainers ["Neil Berkman"]

  def project do
    [
      name: "ReqDPoP",
      app: :req_dpop,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      description: "Req plugin for OAuth 2.0 DPoP client proof generation.",
      package: package(),
      source_url: @url,
      homepage_url: @url,
      maintainers: @maintainers,
      deps: deps(),
      elixirc_paths: elixirc_paths(Mix.env()),
      docs: docs(),
      aliases: aliases()
    ]
  end

  def cli do
    [
      preferred_envs: [precommit: :test]
    ]
  end

  def application do
    [
      extra_applications: [:crypto, :logger]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test_support"]
  defp elixirc_paths(_env), do: ["lib"]

  defp deps do
    [
      {:req, "~> 0.5"},
      {:jose, "~> 1.11"},
      {:jason, "~> 1.4"},

      # test-only interop: prove generated proofs pass Attesto's server verifier
      # without making Attesto a runtime dependency of this client package.
      {:attesto, "~> 0.6", only: :test, runtime: false},

      # dev / quality
      {:ex_doc, "~> 0.40", only: :dev, runtime: false},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:quokka, "~> 2.12", only: [:dev, :test], runtime: false}
    ]
  end

  defp aliases do
    [
      precommit: [
        "format --check-formatted",
        "compile --warnings-as-errors",
        "credo --strict",
        "test"
      ]
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @url,
      extras: ["README.md", "CHANGELOG.md", "LICENSE"],
      groups_for_extras: [
        Changelog: ~r/CHANGELOG\.md/,
        License: ~r/LICENSE/
      ]
    ]
  end

  defp package do
    [
      maintainers: @maintainers,
      licenses: ["MIT"],
      links: %{
        "Changelog" => "https://hexdocs.pm/req_dpop/changelog.html",
        "GitHub" => @url
      },
      files: ~w(lib LICENSE mix.exs README.md CHANGELOG.md)
    ]
  end
end
