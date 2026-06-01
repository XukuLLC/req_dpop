defmodule ReqDPoPTest do
  use ExUnit.Case, async: true

  alias ReqDPoP.Key

  @iat 1_700_000_000

  test "proof includes required DPoP claims" do
    key = Key.generate(:es256)

    {:ok, proof} =
      ReqDPoP.proof(
        key: key,
        htm: :post,
        htu: "https://api.example.com/resource?x=1",
        access_token: "access-token",
        clock: fn -> @iat end,
        jti: fn -> "test-jti" end
      )

    assert claims(proof) == %{
             "ath" => ReqDPoP.ath("access-token"),
             "htm" => "POST",
             "htu" => "https://api.example.com/resource?x=1",
             "iat" => @iat,
             "jti" => "test-jti"
           }
  end

  test "proof header includes public JWK" do
    key = Key.generate(:es256)
    proof = proof!(key: key)
    protected = protected(proof)

    assert protected.alg == {:jose_jws_alg_ecdsa, :ES256}
    assert protected.fields["typ"] == "dpop+jwt"
    assert protected.fields["jwk"] == Key.public_jwk(key)
    refute Map.has_key?(protected.fields["jwk"], "d")
  end

  test "supports RS256 proofs" do
    key = Key.generate(:rs256)
    proof = proof!(key: key, alg: :rs256)
    protected = protected(proof)

    assert protected.alg == {:jose_jws_alg_rsa_pkcs1_v1_5, :RS256}
    assert protected.fields["jwk"] == Key.public_jwk(key)
  end

  test "thumbprint is stable across loaded key material" do
    key = Key.generate(:es256)
    exported = Key.export(key)

    assert Key.thumbprint(key) == Key.thumbprint(exported)
  end

  test "loaded ES256 key material keeps its algorithm" do
    key =
      :es256
      |> Key.generate()
      |> Key.export()
      |> Key.load!()

    proof = proof!(key: key)

    assert protected(proof).alg == {:jose_jws_alg_ecdsa, :ES256}
  end

  test "loaded RS256 key material keeps its algorithm" do
    key =
      :rs256
      |> Key.generate()
      |> Key.export()
      |> Key.load!()

    proof = proof!(key: key)

    assert protected(proof).alg == {:jose_jws_alg_rsa_pkcs1_v1_5, :RS256}
  end

  test "attaches DPoP and Authorization headers" do
    key = Key.generate(:es256)
    parent = self()

    adapter = fn request ->
      send(parent, {:headers, request})
      {request, %Req.Response{status: 200, body: "ok"}}
    end

    response =
      Req.new(base_url: "https://api.example.com", adapter: adapter)
      |> ReqDPoP.attach(
        key: key,
        access_token: "access-token",
        clock: fn -> @iat end,
        jti: fn -> "request-jti" end
      )
      |> Req.get!(url: "/resource", params: [a: "1"])

    assert response.status == 200
    assert_receive {:headers, request}

    [proof] = Req.Request.get_header(request, "dpop")
    assert Req.Request.get_header(request, "authorization") == ["DPoP access-token"]

    assert claims(proof)["htu"] == "https://api.example.com/resource?a=1"
    assert claims(proof)["htm"] == "GET"
    assert claims(proof)["ath"] == ReqDPoP.ath("access-token")
  end

  test "resource request is accepted by an RFC 9449-style server verifier" do
    access_token = "access-token"
    adapter = ReqDPoP.RFC9449Server.adapter(access_token: access_token, notify: self())

    response =
      Req.new(base_url: "https://api.example.com", adapter: adapter)
      |> ReqDPoP.attach(
        key: Key.generate(:es256),
        access_token: access_token,
        clock: fn -> @iat end,
        jti: fn -> "server-verified-jti" end
      )
      |> Req.get!(url: "/resource", params: [a: "1"])

    assert response.status == 200

    assert_receive {:accepted,
                    %{
                      "ath" => _ath,
                      "htm" => "GET",
                      "htu" => "https://api.example.com/resource?a=1",
                      "iat" => @iat,
                      "jti" => "server-verified-jti"
                    }}
  end

  test "proof-only mode omits Authorization and ath" do
    key = Key.generate(:es256)
    parent = self()

    adapter = fn request ->
      send(parent, {:request, request})
      {request, %Req.Response{status: 200}}
    end

    Req.new(adapter: adapter)
    |> ReqDPoP.attach(key: key, clock: fn -> @iat end, jti: fn -> "token-jti" end)
    |> Req.post!(
      url: "https://auth.example.com/oauth/token",
      form: [grant_type: "client_credentials"]
    )

    assert_receive {:request, request}
    [proof] = Req.Request.get_header(request, "dpop")

    assert Req.Request.get_header(request, "authorization") == []
    refute Map.has_key?(claims(proof), "ath")
    assert claims(proof)["htu"] == "https://auth.example.com/oauth/token"
  end

  test "proof-only token request is accepted by an RFC 9449-style server verifier" do
    adapter = ReqDPoP.RFC9449Server.adapter(notify: self())

    response =
      Req.new(adapter: adapter)
      |> ReqDPoP.attach(
        key: Key.generate(:es256),
        clock: fn -> @iat end,
        jti: fn -> "token-server-jti" end
      )
      |> Req.post!(
        url: "https://auth.example.com/oauth/token",
        form: [grant_type: "client_credentials"]
      )

    assert response.status == 200

    assert_receive {:accepted,
                    %{
                      "htm" => "POST",
                      "htu" => "https://auth.example.com/oauth/token",
                      "iat" => @iat,
                      "jti" => "token-server-jti"
                    }}
  end

  test "excludes URL fragments from htu and preserves query string" do
    key = Key.generate(:es256)
    parent = self()

    adapter = fn request ->
      send(parent, Req.Request.get_header(request, "dpop"))
      {request, %Req.Response{status: 200}}
    end

    Req.new(adapter: adapter)
    |> ReqDPoP.attach(key: key, clock: fn -> @iat end, jti: fn -> "fragment-jti" end)
    |> Req.get!(url: "https://api.example.com/resource?x=1&y=two#discard")

    assert_receive [proof]
    assert claims(proof)["htu"] == "https://api.example.com/resource?x=1&y=two"
  end

  test "retries once with nonce on DPoP nonce challenge" do
    key = Key.generate(:es256)
    parent = self()

    {:ok, counter} = Agent.start_link(fn -> 0 end)

    adapter = fn request ->
      count = Agent.get_and_update(counter, &{&1, &1 + 1})
      [proof] = Req.Request.get_header(request, "dpop")
      send(parent, {:attempt, count, claims(proof)})

      response =
        if count == 0 do
          %Req.Response{status: 401}
          |> Req.Response.put_header("dpop-nonce", "server-nonce")
          |> Req.Response.put_header("www-authenticate", ~s(DPoP error="use_dpop_nonce"))
        else
          %Req.Response{status: 200, body: "ok"}
        end

      {request, response}
    end

    response =
      Req.new(adapter: adapter)
      |> ReqDPoP.attach(
        key: key,
        access_token: "access-token",
        clock: fn -> @iat end,
        jti: fn -> "nonce-jti" end
      )
      |> Req.get!(url: "https://api.example.com/resource")

    assert response.status == 200
    assert_receive {:attempt, 0, first_claims}
    assert_receive {:attempt, 1, second_claims}
    refute Map.has_key?(first_claims, "nonce")
    assert second_claims["nonce"] == "server-nonce"
    assert Agent.get(counter, & &1) == 2
  end

  test "nonce retry satisfies an RFC 9449-style server verifier" do
    access_token = "access-token"

    adapter =
      ReqDPoP.RFC9449Server.adapter(
        access_token: access_token,
        nonce: "server-nonce",
        notify: self()
      )

    response =
      Req.new(adapter: adapter)
      |> ReqDPoP.attach(
        key: Key.generate(:es256),
        access_token: access_token,
        clock: fn -> @iat end,
        jti: fn -> "nonce-server-jti" end
      )
      |> Req.get!(url: "https://api.example.com/resource")

    assert response.status == 200
    assert_receive {:challenge, :use_dpop_nonce}
    assert_receive {:accepted, %{"nonce" => "server-nonce", "jti" => "nonce-server-jti"}}
  end

  test "does not retry arbitrary 401 responses with DPoP-Nonce header" do
    key = Key.generate(:es256)
    {:ok, counter} = Agent.start_link(fn -> 0 end)

    adapter = fn request ->
      Agent.update(counter, &(&1 + 1))

      response =
        %Req.Response{status: 401}
        |> Req.Response.put_header("dpop-nonce", "server-nonce")

      {request, response}
    end

    response =
      Req.new(adapter: adapter, http_errors: :return)
      |> ReqDPoP.attach(key: key, clock: fn -> @iat end, jti: fn -> "no-retry-jti" end)
      |> Req.get!(url: "https://api.example.com/resource")

    assert response.status == 401
    assert Agent.get(counter, & &1) == 1
  end

  test "nonce retry occurs at most once" do
    key = Key.generate(:es256)
    {:ok, counter} = Agent.start_link(fn -> 0 end)

    adapter = fn request ->
      Agent.update(counter, &(&1 + 1))

      response =
        %Req.Response{status: 401}
        |> Req.Response.put_header("dpop-nonce", "server-nonce")
        |> Req.Response.put_header("www-authenticate", ~s(DPoP error="use_dpop_nonce"))

      {request, response}
    end

    response =
      Req.new(adapter: adapter, http_errors: :return)
      |> ReqDPoP.attach(
        key: key,
        clock: fn -> @iat end,
        jti: fn -> "once-jti" end,
        max_nonce_retries: 1
      )
      |> Req.get!(url: "https://api.example.com/resource")

    assert response.status == 401
    assert Agent.get(counter, & &1) == 2
  end

  defp proof!(opts) do
    opts
    |> Keyword.merge(
      htm: :get,
      htu: "https://api.example.com/resource",
      clock: fn -> @iat end,
      jti: fn -> "jti" end
    )
    |> ReqDPoP.proof!()
  end

  defp claims(proof) do
    %JOSE.JWT{fields: fields} = JOSE.JWT.peek_payload(proof)
    fields
  end

  defp protected(proof), do: JOSE.JWT.peek_protected(proof)
end
