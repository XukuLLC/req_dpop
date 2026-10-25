defmodule ReqDPoP.Nonce do
  @moduledoc false

  # Recognizes the two nonce challenges in RFC 9449.
  #
  # Section 8, authorization server: `400` with the RFC 6749 JSON error body
  # `{"error": "use_dpop_nonce"}` and a `DPoP-Nonce` header. Only token
  # endpoint requests, which run in proof-only mode, get this form.
  #
  # Section 9, resource server: `401` with
  # `WWW-Authenticate: DPoP error="use_dpop_nonce"` and a `DPoP-Nonce` header.
  #
  # Some authorization servers send the `WWW-Authenticate` form on `400` as
  # well, so both forms are accepted there.

  @max_nonce_bytes 1024
  @max_body_bytes 64 * 1024

  @doc false
  def challenge_nonce(%Req.Request{} = request, %Req.Response{} = response, proof_only?) do
    with [nonce] <- Req.Response.get_header(response, "dpop-nonce"),
         true <- valid_nonce?(nonce),
         true <- challenge?(request, response, proof_only?) do
      {:ok, nonce}
    else
      _ -> :error
    end
  end

  # RFC 9449 section 8: nonce = 1*NQCHAR, NQCHAR = %x21 / %x23-5B / %x5D-7E.
  # Anything else is not a server nonce and would not survive JSON encoding
  # into the proof.
  defp valid_nonce?(nonce) when is_binary(nonce) do
    byte_size(nonce) <= @max_nonce_bytes and
      Regex.match?(~r/\A[\x21\x23-\x5B\x5D-\x7E]+\z/, nonce)
  end

  defp challenge?(_request, %Req.Response{status: 401} = response, _proof_only?) do
    www_authenticate_challenge?(response)
  end

  defp challenge?(request, %Req.Response{status: 400} = response, proof_only?) do
    www_authenticate_challenge?(response) or
      (proof_only? and json_error_challenge?(request, response))
  end

  defp challenge?(_request, _response, _proof_only?), do: false

  defp www_authenticate_challenge?(response) do
    response
    |> Req.Response.get_header("www-authenticate")
    |> Enum.any?(&dpop_use_nonce_challenge?/1)
  end

  # Finds the `DPoP` challenge in the header value and checks its own `error`
  # auth-param. Params of other schemes and text inside quoted strings do not
  # count.
  defp dpop_use_nonce_challenge?(value) when is_binary(value) do
    case Regex.run(~r/(?:\A|,)\s*DPoP(?:\s+|\z)/i, value, return: :index) do
      [{start, length}] ->
        value
        |> binary_part(start + length, byte_size(value) - start - length)
        |> auth_params([])
        |> Enum.any?(fn {name, param} ->
          String.downcase(name) == "error" and param == "use_dpop_nonce"
        end)

      nil ->
        false
    end
  end

  # Parses `name=token` and `name="quoted"` pairs until something that is not
  # an auth-param, such as the next challenge's scheme.
  defp auth_params(rest, acc) do
    case Regex.run(~r/\A\s*([A-Za-z0-9_.-]+)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|([^",\s]+))\s*,?/, rest) do
      [match, name, quoted] ->
        auth_params(drop(rest, match), [{name, unescape(quoted)} | acc])

      [match, name, "", token] ->
        auth_params(drop(rest, match), [{name, token} | acc])

      nil ->
        acc
    end
  end

  defp drop(rest, match) do
    binary_part(rest, byte_size(match), byte_size(rest) - byte_size(match))
  end

  defp unescape(quoted), do: String.replace(quoted, ~r/\\(.)/, "\\1")

  defp json_error_challenge?(request, response) do
    match?(%{"error" => "use_dpop_nonce"}, decoded_body(request, response))
  end

  # The nonce step runs before Req decompresses and decodes the body, so a copy
  # of the response goes through Req's own body steps here with the caller's
  # options. A compressed body is decompressed only if the caller opted in with
  # `compressed: true`, exactly as Req itself would do a moment later; Req
  # documents the decompression-bomb exposure of that option. Bodies above a
  # modest size are not inspected: an RFC 6749 error object is tiny.
  defp decoded_body(request, %Req.Response{body: body} = response)
       when is_binary(body) and byte_size(body) <= @max_body_bytes do
    {_request, %Req.Response{body: decoded}} =
      {request, response}
      |> Req.Steps.decompress_body()
      |> Req.Steps.decode_body()

    case decoded do
      map when is_map(map) ->
        map

      binary when is_binary(binary) and byte_size(binary) <= @max_body_bytes ->
        decode_json(binary)

      _other ->
        nil
    end
  rescue
    _error -> nil
  end

  defp decoded_body(_request, %Req.Response{body: body}) when is_map(body), do: body
  defp decoded_body(_request, _response), do: nil

  defp decode_json(binary) do
    case JSON.decode(binary) do
      {:ok, map} when is_map(map) -> map
      _other -> nil
    end
  end
end
