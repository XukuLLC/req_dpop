defmodule ReqDPoPTest do
  use ExUnit.Case, async: true

  alias Attesto.Test.DPoPVerifier
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
             "htu" => "https://api.example.com/resource",
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

    assert claims(proof)["htu"] == "https://api.example.com/resource"
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
                      "htu" => "https://api.example.com/resource",
                      "iat" => @iat,
                      "jti" => "server-verified-jti"
                    }}
  end

  test "resource request proof is accepted by Attesto's DPoP verifier" do
    access_token = "access-token"
    parent = self()

    adapter = fn request ->
      send(parent, {:request, request})
      {request, %Req.Response{status: 200}}
    end

    Req.new(base_url: "https://api.example.com", adapter: adapter)
    |> ReqDPoP.attach(
      key: Key.generate(:es256),
      access_token: access_token,
      clock: fn -> @iat end,
      jti: fn -> "attesto-resource-jti" end
    )
    |> Req.get!(url: "/resource", params: [a: "1"])

    assert_receive {:request, request}

    assert {:ok, verified} =
             DPoPVerifier.verify_request(
               method: "GET",
               url: "https://api.example.com/resource",
               headers: verifier_headers(request),
               now: @iat
             )

    assert verified.scheme == :dpop
    assert verified.proof.htm == "GET"
    assert verified.proof.htu == "https://api.example.com/resource"
  end

  test "resource request proof is accepted by Auth0's Python DPoP verifier" do
    case auth0_python() do
      {:ok, python} ->
        access_token = "access-token"
        parent = self()
        now = System.system_time(:second)

        adapter = fn request ->
          send(parent, {:request, request})
          {request, %Req.Response{status: 200}}
        end

        Req.new(base_url: "https://api.example.com", adapter: adapter)
        |> ReqDPoP.attach(
          key: Key.generate(:es256),
          access_token: access_token,
          clock: fn -> now end,
          jti: fn -> "auth0-python-resource-jti" end
        )
        |> Req.get!(url: "/resource", params: [a: "1"])

        assert_receive {:request, request}

        assert {:ok, claims} =
                 auth0_verify_dpop(python,
                   access_token: access_token,
                   proof: request |> Req.Request.get_header("dpop") |> List.first(),
                   method: "GET",
                   url: "https://api.example.com/resource?a=1"
                 )

        assert claims["ath"] == ReqDPoP.ath(access_token)
        assert claims["htm"] == "GET"
        assert claims["htu"] == "https://api.example.com/resource"
        assert claims["jti"] == "auth0-python-resource-jti"

      {:skip, reason} ->
        IO.puts("Skipping Auth0 Python DPoP verifier interop: #{reason}")
        assert true
    end
  end

  test "resource request is accepted by Auth0's full Python resource verifier" do
    case auth0_python() do
      {:ok, python} ->
        dpop_key = Key.generate(:es256)
        now = System.system_time(:second)
        access_token = auth0_access_token(dpop_key, now)
        parent = self()

        adapter = fn request ->
          send(parent, {:request, request})
          {request, %Req.Response{status: 200}}
        end

        Req.new(base_url: "https://api.example.com", adapter: adapter)
        |> ReqDPoP.attach(
          key: dpop_key,
          access_token: access_token.token,
          clock: fn -> now end,
          jti: fn -> "auth0-python-full-resource-jti" end
        )
        |> Req.get!(url: "/resource", params: [a: "1"])

        assert_receive {:request, request}

        assert {:ok, claims} =
                 auth0_verify_dpop(python,
                   mode: "verify_request",
                   authorization:
                     request |> Req.Request.get_header("authorization") |> List.first(),
                   proof: request |> Req.Request.get_header("dpop") |> List.first(),
                   method: "GET",
                   url: "https://api.example.com/resource?a=1",
                   issuer: access_token.issuer,
                   audience: access_token.audience,
                   domain: "issuer.example.com",
                   jwks_uri: access_token.jwks_uri,
                   jwk: access_token.public_jwk
                 )

        assert claims["cnf"]["jkt"] == Key.thumbprint(dpop_key)
        assert claims["aud"] == access_token.audience
        assert claims["iss"] == access_token.issuer
        assert claims["sub"] == "client:req-dpop"

      {:skip, reason} ->
        IO.puts("Skipping Auth0 Python resource verifier interop: #{reason}")
        assert true
    end
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

  test "proof-only token request is accepted by Attesto's DPoP verifier" do
    parent = self()

    adapter = fn request ->
      send(parent, {:request, request})
      {request, %Req.Response{status: 200}}
    end

    Req.new(adapter: adapter)
    |> ReqDPoP.attach(
      key: Key.generate(:es256),
      clock: fn -> @iat end,
      jti: fn -> "attesto-token-jti" end
    )
    |> Req.post!(
      url: "https://auth.example.com/oauth/token",
      form: [grant_type: "client_credentials"]
    )

    assert_receive {:request, request}

    assert {:ok, verified} =
             DPoPVerifier.verify_request(
               method: "POST",
               url: "https://auth.example.com/oauth/token",
               headers: verifier_headers(request),
               now: @iat
             )

    assert verified.scheme == :dpop
    assert verified.proof.htm == "POST"
    assert verified.proof.htu == "https://auth.example.com/oauth/token"
  end

  test "server verifier rejects missing iat and jti claims" do
    key = Key.generate(:es256)

    request =
      Req.Request.new(method: :get, url: "https://api.example.com/resource")
      |> Req.Request.put_header(
        "dpop",
        signed_proof(key, %{"htm" => "GET", "htu" => "https://api.example.com/resource"})
      )

    assert {:error, :missing_iat} = ReqDPoP.RFC9449Server.verify_request(request, [])

    request =
      Req.Request.new(method: :get, url: "https://api.example.com/resource")
      |> Req.Request.put_header(
        "dpop",
        signed_proof(key, %{
          "htm" => "GET",
          "htu" => "https://api.example.com/resource",
          "iat" => @iat
        })
      )

    assert {:error, :missing_jti} = ReqDPoP.RFC9449Server.verify_request(request, [])
  end

  test "server verifier rejects invalid iat and jti claims" do
    key = Key.generate(:es256)

    request =
      Req.Request.new(method: :get, url: "https://api.example.com/resource")
      |> Req.Request.put_header(
        "dpop",
        signed_proof(key, %{
          "htm" => "GET",
          "htu" => "https://api.example.com/resource",
          "iat" => "not-an-integer",
          "jti" => "jti"
        })
      )

    assert {:error, :invalid_iat} = ReqDPoP.RFC9449Server.verify_request(request, [])

    request =
      Req.Request.new(method: :get, url: "https://api.example.com/resource")
      |> Req.Request.put_header(
        "dpop",
        signed_proof(key, %{
          "htm" => "GET",
          "htu" => "https://api.example.com/resource",
          "iat" => @iat,
          "jti" => ""
        })
      )

    assert {:error, :invalid_jti} = ReqDPoP.RFC9449Server.verify_request(request, [])
  end

  test "excludes URL query strings and fragments from htu" do
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
    assert claims(proof)["htu"] == "https://api.example.com/resource"
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

  defp signed_proof(key, claims) do
    header = %{
      "alg" => "ES256",
      "typ" => "dpop+jwt",
      "jwk" => Key.public_jwk(key)
    }

    key
    |> Key.jose_jwk()
    |> JOSE.JWT.sign(header, claims)
    |> JOSE.JWS.compact()
    |> elem(1)
  end

  defp claims(proof) do
    %JOSE.JWT{fields: fields} = JOSE.JWT.peek_payload(proof)
    fields
  end

  defp protected(proof), do: JOSE.JWT.peek_protected(proof)

  defp auth0_access_token(dpop_key, now) do
    issuer = "https://issuer.example.com/"
    audience = "https://api.example.com"
    jwks_uri = "https://issuer.example.com/.well-known/jwks.json"
    signing_key = JOSE.JWK.generate_key({:rsa, 2048})

    public_jwk =
      signing_key
      |> JOSE.JWK.to_public()
      |> JOSE.JWK.to_map()
      |> elem(1)
      |> Map.merge(%{"alg" => "RS256", "kid" => "auth0-python-test-key", "use" => "sig"})

    claims = %{
      "aud" => audience,
      "cnf" => %{"jkt" => Key.thumbprint(dpop_key)},
      "exp" => now + 300,
      "iat" => now,
      "iss" => issuer,
      "sub" => "client:req-dpop"
    }

    token =
      signing_key
      |> JOSE.JWT.sign(%{"alg" => "RS256", "kid" => "auth0-python-test-key"}, claims)
      |> JOSE.JWS.compact()
      |> elem(1)

    %{
      audience: audience,
      issuer: issuer,
      jwks_uri: jwks_uri,
      public_jwk: public_jwk,
      token: token
    }
  end

  defp verifier_headers(request) do
    dpop = Req.Request.get_header(request, "dpop")
    authorization = Req.Request.get_header(request, "authorization")

    Enum.map(dpop, &{"dpop", &1}) ++ Enum.map(authorization, &{"authorization", &1})
  end

  defp auth0_python do
    python = System.get_env("REQ_DPOP_PYTHON") || System.find_executable("python3")

    cond do
      is_nil(python) ->
        {:skip, "python3 not found"}

      not File.exists?(auth0_verifier_script()) ->
        {:skip, "Auth0 verifier helper not found"}

      true ->
        case System.cmd(python, ["-c", "import auth0_api_python"], stderr_to_stdout: true) do
          {_output, 0} -> {:ok, python}
          {output, _status} -> {:skip, "auth0-api-python unavailable: #{String.trim(output)}"}
        end
    end
  end

  defp auth0_verify_dpop(python, opts) do
    path =
      Path.join(System.tmp_dir!(), "req_dpop_auth0_#{System.unique_integer([:positive])}.json")

    data =
      opts
      |> Map.new()
      |> JSON.encode!()

    File.write!(path, data)

    try do
      case System.cmd(python, [auth0_verifier_script(), path], stderr_to_stdout: true) do
        {output, 0} ->
          {:ok, output |> last_json_line!() |> JSON.decode!() |> Map.fetch!("claims")}

        {output, _status} ->
          {:error, String.trim(output)}
      end
    after
      File.rm(path)
    end
  end

  defp auth0_verifier_script do
    Path.expand("../test_support/python/auth0_dpop_verify.py", __DIR__)
  end

  defp last_json_line!(output) do
    output
    |> String.split("\n", trim: true)
    |> Enum.reverse()
    |> Enum.find_value(fn line ->
      if String.starts_with?(line, "{"), do: line
    end)
    |> case do
      nil -> raise "Python verifier emitted no JSON: #{output}"
      line -> line
    end
  end
end
