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

  Every hop of a request gets its own proof. Req re-runs the request pipeline
  for its retry and redirect steps, and the plugin signs a fresh proof for the
  hop's method and URL with a new `jti`. On an untrusted cross-origin redirect
  the plugin follows Req's rule for credentials: Req drops the `Authorization`
  header, and the plugin drops the `DPoP` header, in proof-only mode as well.
  The redirect target receives neither the token nor a proof unless Req's
  `redirect_trusted: true` is set.
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

  @default_max_nonce_retries 1
  @option :req_dpop
  @step :req_dpop

  @doc """
  Attaches DPoP proof generation to a `Req.Request`.

  Calling `attach/2` again on the same request replaces the configuration
  without adding a second set of steps.

  Options:

    * `:key` - required DPoP private key. Accepts `ReqDPoP.Key`, `JOSE.JWK`,
      or a JWK map. P-256 EC keys sign with ES256 and RSA keys of at least
      2048 bits sign with RS256. See `ReqDPoP.Key.load!/1`.
    * `:access_token` - optional token string or function. When present, the
      plugin adds `Authorization: DPoP ...` and computes the proof `ath` claim.
      An empty string is treated as no token. The function runs once per
      request; retries and redirects reuse the token the first hop sent. Do
      not combine with Req's `:auth` option, which also sets `Authorization`.
    * `:nonce` - optional static nonce or function. A nonce received in a
      server challenge takes precedence for the origin that sent it.
    * `:retry_on_nonce` - retries once on DPoP nonce challenges by default.
    * `:max_nonce_retries` - defaults to `1`, counted per origin.
    * `:clock` - injectable Unix-second clock for tests.
    * `:jti` - injectable JTI generator for tests.
    * `:alg` - optional. Must match the key type: `:es256` for P-256 EC keys,
      `:rs256` for RSA keys.
  """
  @spec attach(Req.Request.t(), [attach_option()]) :: Req.Request.t()
  def attach(%Req.Request{} = request, opts) when is_list(opts) do
    config = config!(opts)

    request =
      request
      |> Req.Request.register_options([@option])
      |> Req.Request.merge_options([{@option, config}])

    if Keyword.has_key?(request.request_steps, @step) do
      request
    else
      request
      |> Req.Request.append_request_steps([{@step, &put_dpop_headers/1}])
      |> Req.Request.prepend_response_steps(req_dpop_nonce_retry: &retry_nonce_challenge/1)
      |> Req.Request.prepend_error_steps(req_dpop_rearm: &rearm_after_error/1)
    end
  end

  @doc """
  Builds a compact DPoP proof JWT.

  Required options are `:key`, `:htm`, and `:htu`. `:access_token` adds `ath`;
  `:nonce` adds `nonce`. `:htu` must be an absolute `http` or `https` URI.
  """
  @spec proof([proof_option() | {:htm, binary() | atom()} | {:htu, binary() | URI.t()}]) ::
          {:ok, binary()} | {:error, Error.t()}
  def proof(opts) when is_list(opts) do
    {:ok, build_proof!(nil, config!(opts), opts)}
  rescue
    error in Error -> {:error, error}
  end

  @doc """
  Builds a compact DPoP proof JWT or raises `ReqDPoP.Error`.
  """
  @spec proof!([proof_option() | {:htm, binary() | atom()} | {:htu, binary() | URI.t()}]) ::
          binary()
  def proof!(opts) when is_list(opts) do
    build_proof!(nil, config!(opts), opts)
  end

  @doc false
  def ath(access_token) when is_binary(access_token) do
    :crypto.hash(:sha256, access_token)
    |> Base.url_encode64(padding: false)
  end

  @doc false
  def normalize_htu(htu) when is_binary(htu) do
    htu
    |> URI.parse()
    |> normalize_htu()
  end

  # RFC 9449 section 4.2: `htu` is the target URI without query and fragment.
  # The target URI (RFC 9110 section 7.1) never carries userinfo, so leaving
  # it in would sign URL-embedded credentials into the proof. Scheme and host
  # are case-insensitive and an empty path means `/` (RFC 3986 section 6.2),
  # which is also what goes on the wire, so both are normalized here.
  def normalize_htu(%URI{scheme: scheme, host: host} = uri)
      when is_binary(scheme) and is_binary(host) and host != "" do
    scheme = String.downcase(scheme)

    if scheme in ["http", "https"] do
      %{
        uri
        | scheme: scheme,
          host: String.downcase(host),
          userinfo: nil,
          query: nil,
          fragment: nil,
          path: path_or_root(uri.path)
      }
      |> URI.to_string()
    else
      invalid_htu!()
    end
  end

  def normalize_htu(%URI{}), do: invalid_htu!()

  defp invalid_htu! do
    raise Error,
      reason: {:invalid_option, :htu},
      message: "htu must be an absolute http or https URI with a host"
  end

  defp path_or_root(nil), do: "/"
  defp path_or_root(""), do: "/"
  defp path_or_root(path), do: path

  defp put_dpop_headers(%Req.Request{} = request) do
    config = Req.Request.fetch_option!(request, @option)

    case Req.Request.get_private(request, :req_dpop_token_sent) do
      nil ->
        # First run for this request.
        access_token = resolve_access_token(config.access_token, request)
        check_auth_conflict!(request, access_token)

        request
        |> Req.Request.put_private(:req_dpop_token_sent, is_binary(access_token))
        |> Req.Request.put_private(:req_dpop_origin, origin(request.url))
        |> put_authorization(access_token)
        |> put_proof(config, access_token)

      false ->
        # Proof-only mode, re-run for a retry or redirect. Follow Req's rule
        # for credentials: a cross-origin hop gets nothing unless the caller
        # set `redirect_trusted: true`.
        if same_origin?(request) or request.options[:redirect_trusted] == true do
          put_proof(request, config, nil)
        else
          Req.Request.delete_header(request, "dpop")
        end

      true ->
        # Re-run for a retry or redirect. Req removes the Authorization header
        # when it follows an untrusted cross-origin redirect. The redirect
        # target then gets no proof either: a proof is sender-constraint
        # material for the token that was just withheld.
        case Req.Request.get_header(request, "authorization") do
          ["DPoP " <> access_token] -> put_proof(request, config, access_token)
          _stripped -> Req.Request.delete_header(request, "dpop")
        end
    end
  end

  defp check_auth_conflict!(request, access_token) do
    if is_binary(access_token) and Map.has_key?(request.options, :auth) do
      raise Error,
        reason: {:conflicting_option, :auth},
        message:
          "Req's :auth option and ReqDPoP's :access_token both set the " <>
            "Authorization header; use one of them"
    end
  end

  defp put_authorization(request, nil), do: request

  defp put_authorization(request, access_token) do
    Req.Request.put_header(request, "authorization", "DPoP " <> access_token)
  end

  defp put_proof(request, config, access_token) do
    proof =
      build_proof!(request, config,
        htm: request.method,
        htu: request.url,
        access_token: access_token,
        nonce: stored_nonce(request) || config.nonce
      )

    Req.Request.put_header(request, "dpop", proof)
  end

  defp origin(%URI{scheme: scheme, host: host, port: port}), do: {scheme, host, port}

  defp same_origin?(request) do
    origin(request.url) == Req.Request.get_private(request, :req_dpop_origin)
  end

  defp stored_nonce(request) do
    request
    |> Req.Request.get_private(:req_dpop_nonces, %{})
    |> Map.get(origin(request.url))
  end

  defp retry_nonce_challenge({%Req.Request{} = request, %Req.Response{} = response}) do
    config = Req.Request.fetch_option!(request, @option)
    request = rearm(request)
    origin = origin(request.url)

    retries =
      request
      |> Req.Request.get_private(:req_dpop_nonce_retries, %{})
      |> Map.get(origin, 0)

    proof_only? = Req.Request.get_private(request, :req_dpop_token_sent) == false

    with true <- config.retry_on_nonce,
         # A hop that sent no proof has nothing to retry with a nonce.
         true <- Req.Request.get_header(request, "dpop") != [],
         true <- retries < config.max_nonce_retries,
         {:ok, nonce} <- Nonce.challenge_nonce(request, response, proof_only?) do
      cancel_async(response)

      request =
        request
        |> update_private(:req_dpop_nonces, %{}, &Map.put(&1, origin, nonce))
        |> update_private(:req_dpop_nonce_retries, %{}, &Map.put(&1, origin, retries + 1))

      {request, response_or_exception} = Req.Request.run_request(%{request | halted: false})
      Req.Request.halt(request, response_or_exception)
    else
      _ -> {request, response}
    end
  end

  defp update_private(request, key, default, fun) do
    Req.Request.put_private(request, key, fun.(Req.Request.get_private(request, key, default)))
  end

  # Like Req's redirect step: do not leave the challenge's streaming body
  # running while the retry is in flight.
  defp cancel_async(%Req.Response{body: %Req.Response.Async{}} = response) do
    Req.cancel_async_response(response)
  end

  defp cancel_async(_response), do: :ok

  # Req 0.6 re-runs only the request steps left in `current_request_steps`
  # when its retry and redirect steps call `Req.Request.run_request/1`, and
  # none are left once the adapter has run. Queue the DPoP step again so the
  # next hop gets a fresh proof. Req 0.7 dropped the field and re-runs every
  # request step, so there is nothing to queue.
  defp rearm(request) do
    case Map.get(request, :current_request_steps) do
      steps when is_list(steps) ->
        if @step in steps do
          request
        else
          Map.put(request, :current_request_steps, steps ++ [@step])
        end

      _absent ->
        request
    end
  end

  # Req 0.6 routes adapter exceptions through the error steps only, so the
  # response-step re-arm never runs before Req's retry step re-runs the
  # request after a transport error.
  defp rearm_after_error({%Req.Request{} = request, exception}) do
    {rearm(request), exception}
  end

  defp build_proof!(request, config, opts) do
    htm = opts |> required_option!(:htm) |> normalize_htm()
    htu = opts |> required_option!(:htu) |> normalize_htu()
    access_token = resolve_access_token(Keyword.get(opts, :access_token), request)
    nonce = opts |> Keyword.get(:nonce) |> resolve_optional(request) |> validate_nonce!()
    iat = config.clock |> resolve_required(request, :clock) |> validate_iat!()
    jti = config.jti |> resolve_required(request, :jti) |> validate_jti!()

    claims =
      %{"htm" => htm, "htu" => htu, "iat" => iat, "jti" => jti}
      |> maybe_put("ath", access_token && ath(access_token))
      |> maybe_put("nonce", nonce)

    header = %{
      "alg" => Key.alg_name(config.alg),
      "typ" => "dpop+jwt",
      "jwk" => Key.proof_jwk(config.key)
    }

    config.key
    |> Key.jose_jwk()
    |> JOSE.JWT.sign(header, claims)
    |> JOSE.JWS.compact()
    |> elem(1)
  end

  defp required_option!(opts, key) do
    case Keyword.fetch(opts, key) do
      {:ok, value} when not is_nil(value) ->
        value

      _missing ->
        raise Error,
          reason: :missing_option,
          message: "missing required option #{inspect(key)}"
    end
  end

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp normalize_htm(method) when is_atom(method) and not is_nil(method) do
    method |> Atom.to_string() |> String.upcase()
  end

  defp normalize_htm(method) when is_binary(method) and method != "" do
    String.upcase(method)
  end

  defp normalize_htm(_method) do
    raise Error, reason: {:invalid_option, :htm}, message: "htm must be an HTTP method"
  end

  defp validate_nonce!(nil), do: nil
  defp validate_nonce!(""), do: nil
  defp validate_nonce!(nonce) when is_binary(nonce), do: nonce

  defp validate_nonce!(_nonce) do
    raise Error, reason: {:invalid_option, :nonce}, message: "nonce must be a string"
  end

  defp validate_iat!(iat) when is_integer(iat), do: iat

  defp validate_iat!(_iat) do
    raise Error, reason: {:invalid_option, :clock}, message: ":clock must produce an integer"
  end

  defp validate_jti!(jti) when is_binary(jti) and jti != "", do: jti

  defp validate_jti!(_jti) do
    raise Error,
      reason: {:invalid_option, :jti},
      message: ":jti must produce a non-empty string"
  end

  defp config!(opts) do
    key =
      opts
      |> Keyword.fetch(:key)
      |> case do
        {:ok, key} -> Key.load!(key)
        :error -> raise Error, reason: :missing_key, message: "missing required option :key"
      end

    alg = Keyword.get(opts, :alg, key.alg)
    validate_alg!(key, alg)

    %{
      key: %{key | alg: alg},
      alg: alg,
      access_token: opts |> option!(:access_token, nil, &value_or_fun?/1) |> redact(),
      nonce: option!(opts, :nonce, nil, &value_or_fun?/1),
      retry_on_nonce: option!(opts, :retry_on_nonce, true, &is_boolean/1),
      max_nonce_retries:
        option!(opts, :max_nonce_retries, @default_max_nonce_retries, &non_neg_integer?/1),
      clock: option!(opts, :clock, fn -> System.system_time(:second) end, &integer_or_fun?/1),
      jti: option!(opts, :jti, &default_jti/0, &value_or_fun?/1)
    }
  end

  defp option!(opts, name, default, valid?) do
    value = Keyword.get(opts, name, default)

    if valid?.(value) do
      value
    else
      raise Error,
        reason: {:invalid_option, name},
        message: "invalid value for option #{inspect(name)}"
    end
  end

  defp value_or_fun?(value) do
    is_nil(value) or is_binary(value) or is_function(value, 0) or is_function(value, 1)
  end

  defp integer_or_fun?(value) do
    is_integer(value) or is_function(value, 0) or is_function(value, 1)
  end

  defp non_neg_integer?(value), do: is_integer(value) and value >= 0

  # `Key.load!/1` rejects keys it cannot assign an algorithm to, so `key.alg`
  # is always set here.
  defp validate_alg!(%Key{alg: key_alg}, alg) when alg != key_alg do
    raise Error,
      reason: {:alg_mismatch, alg, key_alg},
      message:
        "signing algorithm #{inspect(alg)} does not match the key, " <>
          "which signs with #{inspect(key_alg)}"
  end

  defp validate_alg!(_key, _alg), do: :ok

  # Req redacts the Authorization header in `inspect/1`. Keep a plain-string
  # token out of the inspected request options too; a closure inspects as
  # `#Function<...>`.
  defp redact(access_token) when is_binary(access_token), do: fn -> access_token end
  defp redact(other), do: other

  defp resolve_access_token(fun_or_value, request) do
    case resolve_optional(fun_or_value, request) do
      nil ->
        nil

      "" ->
        nil

      access_token when is_binary(access_token) ->
        access_token

      _other ->
        raise Error,
          reason: {:invalid_option, :access_token},
          message: ":access_token must be a string or a function returning one"
    end
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
