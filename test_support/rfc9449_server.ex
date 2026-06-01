defmodule ReqDPoP.RFC9449Server do
  @moduledoc false

  @allowed_algs ~w(ES256 RS256)
  @max_jti_length 256

  def adapter(opts) when is_list(opts) do
    fn request ->
      response =
        case verify_request(request, opts) do
          {:ok, claims} ->
            notify(opts, {:accepted, claims})
            %Req.Response{status: 200, body: "ok"}

          {:error, :use_dpop_nonce} ->
            notify(opts, {:challenge, :use_dpop_nonce})

            %Req.Response{status: 401, body: "nonce required"}
            |> Req.Response.put_header("dpop-nonce", Keyword.fetch!(opts, :nonce))
            |> Req.Response.put_header("www-authenticate", ~s(DPoP error="use_dpop_nonce"))

          {:error, reason} ->
            notify(opts, {:rejected, reason})

            %Req.Response{status: 401, body: Atom.to_string(reason)}
            |> Req.Response.put_header("www-authenticate", ~s(DPoP error="invalid_dpop_proof"))
        end

      {request, response}
    end
  end

  def verify_request(%Req.Request{} = request, opts) when is_list(opts) do
    with {:ok, proof} <- one_header(request, "dpop"),
         {:ok, protected} <- protected_header(proof),
         :ok <- verify_protected_header(protected),
         {:ok, claims} <- verify_signature(proof, protected),
         :ok <- verify_htm(claims, request),
         :ok <- verify_htu(claims, request),
         :ok <- verify_iat(claims),
         :ok <- verify_jti(claims),
         :ok <- verify_access_token(claims, request, opts),
         :ok <- verify_nonce(claims, opts) do
      {:ok, claims}
    end
  end

  defp protected_header(proof) do
    protected = JOSE.JWT.peek_protected(proof)

    case protected do
      %JOSE.JWS{alg: alg, fields: fields} when is_map(fields) ->
        {:ok, Map.put(fields, "alg", alg_name(alg))}

      _other ->
        {:error, :invalid_proof}
    end
  rescue
    _error -> {:error, :invalid_proof}
  end

  defp alg_name({:jose_jws_alg_ecdsa, :ES256}), do: "ES256"
  defp alg_name({:jose_jws_alg_rsa_pkcs1_v1_5, :RS256}), do: "RS256"
  defp alg_name(_alg), do: nil

  defp verify_protected_header(%{"typ" => "dpop+jwt", "alg" => alg, "jwk" => jwk})
       when alg in @allowed_algs and is_map(jwk) do
    :ok
  end

  defp verify_protected_header(%{"alg" => alg}) when alg not in @allowed_algs do
    {:error, :invalid_alg}
  end

  defp verify_protected_header(_protected), do: {:error, :invalid_header}

  defp verify_signature(proof, %{"alg" => alg, "jwk" => jwk_map}) do
    jwk = JOSE.JWK.from_map(jwk_map)

    case JOSE.JWT.verify_strict(jwk, [alg], proof) do
      {true, %JOSE.JWT{fields: claims}, _jws} -> {:ok, claims}
      _other -> {:error, :invalid_signature}
    end
  rescue
    _error -> {:error, :invalid_signature}
  end

  defp verify_htm(%{"htm" => htm}, request) do
    method =
      request.method
      |> Atom.to_string()
      |> String.upcase()

    if htm == method do
      :ok
    else
      {:error, :invalid_htm}
    end
  end

  defp verify_htm(_claims, _request), do: {:error, :missing_htm}

  defp verify_htu(%{"htu" => htu}, request) do
    if htu == ReqDPoP.normalize_htu(request.url) do
      :ok
    else
      {:error, :invalid_htu}
    end
  end

  defp verify_htu(_claims, _request), do: {:error, :missing_htu}

  defp verify_iat(%{"iat" => iat}) when is_integer(iat) and iat >= 0, do: :ok
  defp verify_iat(%{"iat" => _iat}), do: {:error, :invalid_iat}
  defp verify_iat(_claims), do: {:error, :missing_iat}

  defp verify_jti(%{"jti" => jti}) when is_binary(jti) do
    if jti != "" and byte_size(jti) <= @max_jti_length do
      :ok
    else
      {:error, :invalid_jti}
    end
  end

  defp verify_jti(%{"jti" => _jti}), do: {:error, :invalid_jti}
  defp verify_jti(_claims), do: {:error, :missing_jti}

  defp verify_access_token(claims, request, opts) do
    case Keyword.fetch(opts, :access_token) do
      {:ok, access_token} ->
        with {:ok, ^access_token} <- dpop_authorization(request),
             true <- claims["ath"] == ReqDPoP.ath(access_token) do
          :ok
        else
          {:ok, _other} -> {:error, :invalid_access_token}
          :error -> {:error, :missing_access_token}
          _other -> {:error, :invalid_ath}
        end

      :error ->
        if Req.Request.get_header(request, "authorization") == [] and is_nil(claims["ath"]) do
          :ok
        else
          {:error, :unexpected_access_token}
        end
    end
  end

  defp verify_nonce(claims, opts) do
    case Keyword.fetch(opts, :nonce) do
      {:ok, nonce} ->
        if claims["nonce"] == nonce, do: :ok, else: {:error, :use_dpop_nonce}

      :error ->
        :ok
    end
  end

  defp dpop_authorization(request) do
    case Req.Request.get_header(request, "authorization") do
      ["DPoP " <> token] -> {:ok, token}
      [] -> :error
      _other -> {:error, :invalid_access_token}
    end
  end

  defp one_header(request, name) do
    case Req.Request.get_header(request, name) do
      [value] -> {:ok, value}
      [] -> {:error, :missing_header}
      _many -> {:error, :duplicate_header}
    end
  end

  defp notify(opts, message) do
    if pid = Keyword.get(opts, :notify) do
      send(pid, message)
    end
  end
end
