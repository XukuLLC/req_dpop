defmodule ReqDPoP do
  @moduledoc """
  Req plugin for OAuth 2.0 DPoP client proof generation.

  Attach the plugin to a `Req.Request` with `attach/2`:

      key = ReqDPoP.Key.generate(:es256)

      client =
        Req.new(base_url: "https://api.example.com")
        |> ReqDPoP.attach(key: key, access_token: access_token)

      Req.get!(client, url: "/resource")

  To use proof-only mode for token endpoint requests, omit `:access_token`.
  """

  alias ReqDPoP.Error
  alias ReqDPoP.Key
  alias ReqDPoP.Nonce

  @type alg :: :es256 | :rs256
  @type clock :: (-> integer()) | (Req.Request.t() -> integer())
  @type jti :: (-> binary()) | (Req.Request.t() -> binary())
  @type proof_option ::
          {:key, Key.t() | JOSE.JWK.t() | map()}
          | {:access_token, binary() | (-> binary() | nil) | (Req.Request.t() -> binary() | nil)}
          | {:nonce, binary() | (-> binary() | nil) | (Req.Request.t() -> binary() | nil)}
          | {:clock, clock()}
          | {:jti, jti()}
          | {:alg, alg()}

  @type attach_option ::
          proof_option()
          | {:retry_on_nonce, boolean()}
          | {:max_nonce_retries, non_neg_integer()}

  @default_alg :es256
  @default_max_nonce_retries 1
  @option :req_dpop

  @doc """
  Attaches DPoP proof generation to a `Req.Request`.

  Options:

    * `:key` - required DPoP private key. Accepts `ReqDPoP.Key`, `JOSE.JWK`,
      or a JWK map.
    * `:access_token` - optional token string or function. When present, the
      plugin adds `Authorization: DPoP ...` and computes the proof `ath` claim.
    * `:nonce` - optional static nonce or function.
    * `:retry_on_nonce` - retries once on DPoP nonce challenges by default.
    * `:max_nonce_retries` - defaults to `1`.
    * `:clock` - injectable Unix-second clock for tests.
    * `:jti` - injectable JTI generator for tests.
    * `:alg` - `:es256` by default. `:rs256` is also supported.
  """
  @spec attach(Req.Request.t(), [attach_option()]) :: Req.Request.t()
  def attach(%Req.Request{} = request, opts) when is_list(opts) do
    config = config!(opts)

    request
    |> Req.Request.register_options([@option])
    |> Req.Request.merge_options([{@option, config}])
    |> Req.Request.append_request_steps(req_dpop: &put_dpop_headers/1)
    |> Req.Request.prepend_response_steps(req_dpop_nonce_retry: &retry_nonce_challenge/1)
  end

  @doc """
  Builds a compact DPoP proof JWT.

  Required options are `:key`, `:htm`, and `:htu`. `:access_token` adds `ath`;
  `:nonce` adds `nonce`.
  """
  @spec proof([proof_option() | {:htm, binary() | atom()} | {:htu, binary()}]) ::
          {:ok, binary()} | {:error, Error.t()}
  def proof(opts) when is_list(opts) do
    {:ok, build_proof!(nil, config!(opts), opts)}
  rescue
    error in Error -> {:error, error}
  end

  @doc """
  Builds a compact DPoP proof JWT or raises `ReqDPoP.Error`.
  """
  @spec proof!([proof_option() | {:htm, binary() | atom()} | {:htu, binary()}]) :: binary()
  def proof!(opts) when is_list(opts) do
    build_proof!(nil, config!(opts), opts)
  end

  @doc false
  def ath(access_token) when is_binary(access_token) do
    :crypto.hash(:sha256, access_token)
    |> Base.url_encode64(padding: false)
  end

  @doc false
  def normalize_htu(%URI{} = uri) do
    uri
    |> Map.put(:fragment, nil)
    |> URI.to_string()
  end

  defp put_dpop_headers(%Req.Request{} = request) do
    config = Req.Request.fetch_option!(request, @option)
    access_token = resolve_optional(config.access_token, request)

    proof =
      build_proof!(request, config,
        htm: request.method,
        htu: normalize_htu(request.url),
        access_token: access_token,
        nonce: retry_nonce(request) || resolve_optional(config.nonce, request)
      )

    request = Req.Request.put_header(request, "dpop", proof)

    if is_binary(access_token) and access_token != "" do
      Req.Request.put_header(request, "authorization", "DPoP " <> access_token)
    else
      request
    end
  end

  defp retry_nonce(request) do
    Req.Request.get_private(request, :req_dpop_nonce)
  end

  defp retry_nonce_challenge({%Req.Request{} = request, %Req.Response{} = response}) do
    config = Req.Request.fetch_option!(request, @option)
    retries = Req.Request.get_private(request, :req_dpop_nonce_retries, 0)

    with true <- config.retry_on_nonce,
         true <- retries < config.max_nonce_retries,
         {:ok, nonce} <- Nonce.challenge_nonce(response) do
      request =
        request
        |> Req.Request.put_private(:req_dpop_nonce, nonce)
        |> Req.Request.put_private(:req_dpop_nonce_retries, retries + 1)

      {request, response_or_exception} =
        request
        |> Map.put(:halted, false)
        |> Map.put(:current_request_steps, [:req_dpop])
        |> Req.Request.run_request()

      Req.Request.halt(request, response_or_exception)
    else
      _ -> {request, response}
    end
  end

  defp build_proof!(request, config, opts) do
    htm =
      opts
      |> required_option!(:htm)
      |> normalize_htm()

    htu = required_option!(opts, :htu)
    access_token = Keyword.get(opts, :access_token)
    nonce = Keyword.get(opts, :nonce)

    claims =
      %{
        "htm" => htm,
        "htu" => htu,
        "iat" => resolve_required(config.clock, request, :clock),
        "jti" => resolve_required(config.jti, request, :jti)
      }
      |> maybe_put("ath", access_token && ath(access_token))
      |> maybe_put("nonce", nonce)

    header = %{
      "alg" => Key.alg_name(config.alg),
      "typ" => "dpop+jwt",
      "jwk" => Key.public_jwk(config.key)
    }

    config.key
    |> Key.jose_jwk()
    |> JOSE.JWT.sign(header, claims)
    |> JOSE.JWS.compact()
    |> elem(1)
  end

  defp required_option!(opts, key) do
    case Keyword.fetch(opts, key) do
      {:ok, value} ->
        value

      :error ->
        raise Error,
          reason: :missing_option,
          message: "missing required option #{inspect(key)}"
    end
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, _key, ""), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp normalize_htm(method) when is_atom(method) do
    method
    |> Atom.to_string()
    |> String.upcase()
  end

  defp normalize_htm(method) when is_binary(method), do: String.upcase(method)

  defp config!(opts) do
    key =
      opts
      |> Keyword.fetch(:key)
      |> case do
        {:ok, key} -> Key.load!(key)
        :error -> raise Error, reason: :missing_key, message: "missing required option :key"
      end

    alg = Keyword.get(opts, :alg, key.alg || @default_alg)

    %{
      key: %{key | alg: alg},
      alg: alg,
      access_token: Keyword.get(opts, :access_token),
      nonce: Keyword.get(opts, :nonce),
      retry_on_nonce: Keyword.get(opts, :retry_on_nonce, true),
      max_nonce_retries: Keyword.get(opts, :max_nonce_retries, @default_max_nonce_retries),
      clock: Keyword.get(opts, :clock, fn -> System.system_time(:second) end),
      jti: Keyword.get(opts, :jti, &default_jti/0)
    }
  end

  defp resolve_required(fun_or_value, request, name) do
    case resolve_optional(fun_or_value, request) do
      nil ->
        raise Error, reason: {:invalid_option, name}, message: "#{inspect(name)} returned nil"

      value ->
        value
    end
  end

  defp resolve_optional(nil, _request), do: nil
  defp resolve_optional(fun, _request) when is_function(fun, 0), do: fun.()
  defp resolve_optional(fun, request) when is_function(fun, 1), do: fun.(request)
  defp resolve_optional(value, _request), do: value

  defp default_jti do
    16
    |> :crypto.strong_rand_bytes()
    |> Base.url_encode64(padding: false)
  end
end
