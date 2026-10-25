defmodule ReqDPoPHardeningTest do
  use ExUnit.Case, async: true

  alias ReqDPoP.Key

  @nonce_challenge ~s(DPoP error="use_dpop_nonce")

  describe "nonce challenges" do
    test "retries an RFC 9449 section 8 authorization server challenge" do
      # 400, JSON error body, DPoP-Nonce header, no WWW-Authenticate.
      {:ok, log} = Agent.start_link(fn -> [] end)

      adapter =
        adapter(log, fn
          _request, 1 -> as_challenge("as-nonce")
          _request, _attempt -> Req.Response.new(status: 200, body: "ok")
        end)

      response = token_request(adapter)

      assert response.status == 200
      [first, second] = requests(log)
      refute Map.has_key?(claims(first), "nonce")
      assert claims(second)["nonce"] == "as-nonce"
      assert claims(second)["htu"] == "https://as.example/token"
    end

    test "decodes a compressed section 8 challenge when the caller opted into compression" do
      {:ok, log} = Agent.start_link(fn -> [] end)

      adapter =
        adapter(log, fn
          _request, 1 -> as_challenge("as-nonce", compressed: true)
          _request, _attempt -> Req.Response.new(status: 200, body: "ok")
        end)

      response = token_request(adapter, compressed: true)

      assert response.status == 200
      [_first, second] = requests(log)
      assert claims(second)["nonce"] == "as-nonce"
    end

    test "does not decompress a 400 body the caller did not ask to have compressed" do
      # Req documents decompression as opt-in because of decompression bombs;
      # challenge detection follows the same rule.
      {:ok, log} = Agent.start_link(fn -> [] end)

      adapter =
        adapter(log, fn _request, _attempt -> as_challenge("as-nonce", compressed: true) end)

      response = token_request(adapter)

      assert response.status == 400
      assert length(requests(log)) == 1
    end

    test "does not retry a 400 whose JSON error is something else" do
      {:ok, log} = Agent.start_link(fn -> [] end)

      adapter =
        adapter(log, fn _request, _attempt ->
          as_challenge("fresh-nonce", body: ~s({"error":"invalid_grant"}))
        end)

      response = token_request(adapter)

      assert response.status == 400
      assert length(requests(log)) == 1
    end

    test "does not retry a 400 with a body that is not JSON" do
      {:ok, log} = Agent.start_link(fn -> [] end)

      adapter =
        adapter(log, fn _request, _attempt ->
          Req.Response.new(
            status: 400,
            headers: %{"dpop-nonce" => ["fresh-nonce"], "content-type" => ["text/html"]},
            body: "<html>use_dpop_nonce</html>"
          )
        end)

      response = token_request(adapter)

      assert response.status == 400
      assert length(requests(log)) == 1
    end

    test "ignores the section 8 JSON form on resource requests that carry a token" do
      {:ok, log} = Agent.start_link(fn -> [] end)
      adapter = adapter(log, fn _request, _attempt -> as_challenge("as-nonce") end)

      response =
        Req.new(adapter: adapter, retry: false)
        |> ReqDPoP.attach(key: Key.generate(:es256), access_token: "tok")
        |> Req.get!(url: "https://rs.example/resource")

      assert response.status == 400
      assert length(requests(log)) == 1
    end

    test "rejects server nonces that are not RFC 9449 NQCHAR strings" do
      for bad <- [
            <<255, 254>>,
            "has space",
            ~s(quo"te),
            "back\\slash",
            String.duplicate("n", 1025)
          ] do
        {:ok, log} = Agent.start_link(fn -> [] end)
        adapter = adapter(log, fn _request, _attempt -> rs_challenge(bad) end)

        {:ok, response} =
          Req.new(adapter: adapter, retry: false)
          |> ReqDPoP.attach(key: Key.generate(:es256), access_token: "tok")
          |> Req.get(url: "https://rs.example/resource")

        assert response.status == 401
        assert length(requests(log)) == 1
      end
    end

    test "ignores a challenge with more than one DPoP-Nonce header" do
      {:ok, log} = Agent.start_link(fn -> [] end)

      adapter =
        adapter(log, fn _request, _attempt ->
          Req.Response.new(
            status: 401,
            headers: %{"dpop-nonce" => ["one", "two"], "www-authenticate" => [@nonce_challenge]}
          )
        end)

      response =
        Req.new(adapter: adapter, retry: false)
        |> ReqDPoP.attach(key: Key.generate(:es256), access_token: "tok")
        |> Req.get!(url: "https://rs.example/resource")

      assert response.status == 401
      assert length(requests(log)) == 1
    end

    test "reads error=use_dpop_nonce only from the DPoP challenge itself" do
      retried = [
        @nonce_challenge,
        ~s(DPoP error=use_dpop_nonce),
        ~s(Bearer realm="api", DPoP error="use_dpop_nonce", error_description="x"),
        ~s(dpop algs="ES256", error="use_dpop_nonce")
      ]

      ignored = [
        ~s(Bearer realm="dpop", error="use_dpop_nonce"),
        ~s(DPoP error="invalid_dpop_proof", error_description="error=use_dpop_nonce"),
        ~s(DPoP error="use_dpop_nonce_later"),
        ~s(DPoP realm="use_dpop_nonce")
      ]

      for value <- retried do
        assert attempts_for_www_authenticate(value) == 2, "expected a retry for #{value}"
      end

      for value <- ignored do
        assert attempts_for_www_authenticate(value) == 1, "expected no retry for #{value}"
      end
    end

    test "scopes server nonces and the retry budget to the origin that issued them" do
      # A challenges, A redirects (trusted) to B, B challenges with its own nonce.
      {:ok, log} = Agent.start_link(fn -> [] end)

      adapter =
        adapter(log, fn
          %{url: %{host: "a.example"}} = request, _attempt ->
            case claims(request)["nonce"] do
              nil ->
                rs_challenge("nonce-a")

              "nonce-a" ->
                Req.Response.new(status: 302, headers: %{"location" => ["https://b.example/r"]})
            end

          %{url: %{host: "b.example"}} = request, _attempt ->
            case claims(request)["nonce"] do
              nil -> rs_challenge("nonce-b")
              "nonce-b" -> Req.Response.new(status: 200, body: "ok")
            end
        end)

      response =
        Req.new(adapter: adapter, retry: false, redirect_log_level: false, redirect_trusted: true)
        |> ReqDPoP.attach(key: Key.generate(:es256), access_token: "tok")
        |> Req.get!(url: "https://a.example/r")

      assert response.status == 200
      [a1, a2, b1, b2] = requests(log)
      refute Map.has_key?(claims(a1), "nonce")
      assert claims(a2)["nonce"] == "nonce-a"
      refute Map.has_key?(claims(b1), "nonce")
      assert claims(b2)["nonce"] == "nonce-b"
    end

    test "does not answer a nonce challenge from a hop that received no proof" do
      {:ok, log} = Agent.start_link(fn -> [] end)

      adapter =
        adapter(log, fn
          %{url: %{host: "api.example.com"}}, _attempt ->
            Req.Response.new(status: 302, headers: %{"location" => ["https://other.example/x"]})

          _request, _attempt ->
            rs_challenge("other-nonce")
        end)

      response =
        Req.new(adapter: adapter, retry: false, redirect_log_level: false)
        |> ReqDPoP.attach(key: Key.generate(:es256), access_token: "tok")
        |> Req.get!(url: "https://api.example.com/resource")

      assert response.status == 401
      [_first, second] = requests(log)
      assert Req.Request.get_header(second, "dpop") == []
    end
  end

  describe "redirects and retries" do
    test "re-signs the proof on a same-origin redirect" do
      {:ok, log} = Agent.start_link(fn -> [] end)

      adapter =
        adapter(log, fn
          %{url: %{path: "/resource"}}, _attempt ->
            Req.Response.new(status: 301, headers: %{"location" => ["/resource/"]})

          _request, _attempt ->
            Req.Response.new(status: 200, body: "ok")
        end)

      Req.new(adapter: adapter, retry: false, redirect_log_level: false)
      |> ReqDPoP.attach(key: Key.generate(:es256), access_token: "tok")
      |> Req.get!(url: "https://api.example.com/resource")

      [first, second] = requests(log)
      assert Req.Request.get_header(second, "authorization") == ["DPoP tok"]
      assert claims(first)["htu"] == "https://api.example.com/resource"
      assert claims(second)["htu"] == "https://api.example.com/resource/"
      assert claims(second)["ath"] == ReqDPoP.ath("tok")
      assert claims(first)["jti"] != claims(second)["jti"]
    end

    test "signs the changed method after a 303 redirect" do
      {:ok, log} = Agent.start_link(fn -> [] end)

      adapter =
        adapter(log, fn
          %{method: :post}, _attempt ->
            Req.Response.new(status: 303, headers: %{"location" => ["/result"]})

          _request, _attempt ->
            Req.Response.new(status: 200, body: "ok")
        end)

      Req.new(adapter: adapter, retry: false, redirect_log_level: false)
      |> ReqDPoP.attach(key: Key.generate(:es256), access_token: "tok")
      |> Req.post!(url: "https://api.example.com/submit", form: [a: "1"])

      [first, second] = requests(log)
      assert claims(first)["htm"] == "POST"
      assert second.method == :get
      assert claims(second)["htm"] == "GET"
      assert claims(second)["htu"] == "https://api.example.com/result"
    end

    test "sends neither the token nor a proof to an untrusted cross-origin redirect" do
      {:ok, log} = Agent.start_link(fn -> [] end)

      adapter =
        adapter(log, fn
          %{url: %{host: "api.example.com"}}, _attempt ->
            Req.Response.new(status: 302, headers: %{"location" => ["https://other.example/x"]})

          _request, _attempt ->
            Req.Response.new(status: 200, body: "ok")
        end)

      Req.new(adapter: adapter, retry: false, redirect_log_level: false)
      |> ReqDPoP.attach(key: Key.generate(:es256), access_token: "tok")
      |> Req.get!(url: "https://api.example.com/resource")

      [first, second] = requests(log)
      assert Req.Request.get_header(first, "authorization") == ["DPoP tok"]
      assert second.url.host == "other.example"
      assert Req.Request.get_header(second, "authorization") == []
      assert Req.Request.get_header(second, "dpop") == []
    end

    test "re-signs with the token on a trusted cross-origin redirect" do
      {:ok, log} = Agent.start_link(fn -> [] end)

      adapter =
        adapter(log, fn
          %{url: %{host: "api.example.com"}}, _attempt ->
            Req.Response.new(status: 302, headers: %{"location" => ["https://other.example/x"]})

          _request, _attempt ->
            Req.Response.new(status: 200, body: "ok")
        end)

      Req.new(adapter: adapter, retry: false, redirect_log_level: false, redirect_trusted: true)
      |> ReqDPoP.attach(key: Key.generate(:es256), access_token: "tok")
      |> Req.get!(url: "https://api.example.com/resource")

      [first, second] = requests(log)
      assert Req.Request.get_header(second, "authorization") == ["DPoP tok"]
      assert claims(second)["htu"] == "https://other.example/x"
      assert claims(second)["ath"] == ReqDPoP.ath("tok")
      assert claims(first)["jti"] != claims(second)["jti"]
    end

    test "proof-only requests send no proof to an untrusted cross-origin redirect" do
      {:ok, log} = Agent.start_link(fn -> [] end)

      adapter =
        adapter(log, fn
          %{url: %{host: "as.example"}}, _attempt ->
            Req.Response.new(status: 307, headers: %{"location" => ["https://as2.example/token"]})

          _request, _attempt ->
            Req.Response.new(status: 200, body: "ok")
        end)

      Req.new(adapter: adapter, retry: false, redirect_log_level: false)
      |> ReqDPoP.attach(key: Key.generate(:es256))
      |> Req.post!(url: "https://as.example/token", form: [grant_type: "client_credentials"])

      [first, second] = requests(log)
      assert Req.Request.get_header(first, "dpop") != []
      assert second.url.host == "as2.example"
      assert Req.Request.get_header(second, "dpop") == []
    end

    test "proof-only requests get a fresh proof on same-origin and trusted redirects" do
      {:ok, log} = Agent.start_link(fn -> [] end)

      adapter =
        adapter(log, fn
          %{url: %{host: "as.example"}}, _attempt ->
            Req.Response.new(status: 307, headers: %{"location" => ["https://as2.example/token"]})

          _request, _attempt ->
            Req.Response.new(status: 200, body: "ok")
        end)

      Req.new(adapter: adapter, retry: false, redirect_log_level: false, redirect_trusted: true)
      |> ReqDPoP.attach(key: Key.generate(:es256))
      |> Req.post!(url: "https://as.example/token", form: [grant_type: "client_credentials"])

      [first, second] = requests(log)
      assert Req.Request.get_header(second, "authorization") == []
      assert claims(second)["htu"] == "https://as2.example/token"
      assert claims(second)["htm"] == "POST"
      refute Map.has_key?(claims(second), "ath")
      assert claims(first)["jti"] != claims(second)["jti"]
    end

    test "Req's retry step sends a fresh proof instead of replaying the last one" do
      {:ok, log} = Agent.start_link(fn -> [] end)

      adapter =
        adapter(log, fn
          _request, 1 -> Req.Response.new(status: 503)
          _request, _attempt -> Req.Response.new(status: 200, body: "ok")
        end)

      response =
        Req.new(adapter: adapter, retry_delay: 0, max_retries: 1, retry_log_level: false)
        |> ReqDPoP.attach(key: Key.generate(:es256), access_token: "tok")
        |> Req.get!(url: "https://api.example.com/resource")

      assert response.status == 200
      [first, second] = requests(log)
      assert Req.Request.get_header(second, "authorization") == ["DPoP tok"]
      assert claims(first)["jti"] != claims(second)["jti"]
      assert claims(second)["htu"] == "https://api.example.com/resource"
    end

    test "a retry after a transport error also gets a fresh proof" do
      {:ok, log} = Agent.start_link(fn -> [] end)

      adapter = fn request ->
        attempt = Agent.get_and_update(log, fn seen -> {length(seen) + 1, [request | seen]} end)

        if attempt == 1 do
          {request, %Req.TransportError{reason: :timeout}}
        else
          {request, Req.Response.new(status: 200, body: "ok")}
        end
      end

      response =
        Req.new(adapter: adapter, retry_delay: 0, max_retries: 1, retry_log_level: false)
        |> ReqDPoP.attach(key: Key.generate(:es256), access_token: "tok")
        |> Req.get!(url: "https://api.example.com/resource")

      assert response.status == 200
      [first, second] = requests(log)
      assert claims(first)["jti"] != claims(second)["jti"]
    end
  end

  describe "configuration" do
    test "attaching twice replaces the configuration without duplicating steps" do
      request =
        Req.new()
        |> ReqDPoP.attach(key: Key.generate(:es256))
        |> ReqDPoP.attach(key: Key.generate(:es256), access_token: "second")

      assert Keyword.keys(request.request_steps) |> Enum.count(&(&1 == :req_dpop)) == 1

      assert Keyword.keys(request.response_steps) |> Enum.count(&(&1 == :req_dpop_nonce_retry)) ==
               1

      assert Keyword.keys(request.error_steps) |> Enum.count(&(&1 == :req_dpop_rearm)) == 1

      {:ok, log} = Agent.start_link(fn -> [] end)
      adapter = adapter(log, fn _request, _attempt -> Req.Response.new(status: 200) end)
      Req.get!(%{request | adapter: adapter}, url: "https://api.example.com/r")
      [sent] = requests(log)
      assert Req.Request.get_header(sent, "authorization") == ["DPoP second"]
      assert length(Req.Request.get_header(sent, "dpop")) == 1
    end

    test "rejects option values that would misbehave" do
      key = Key.generate(:es256)

      for {opts, name} <- [
            {[max_nonce_retries: nil], :max_nonce_retries},
            {[max_nonce_retries: -1], :max_nonce_retries},
            {[max_nonce_retries: :infinity], :max_nonce_retries},
            {[retry_on_nonce: "yes"], :retry_on_nonce},
            {[access_token: 123], :access_token},
            {[nonce: %{}], :nonce},
            {[clock: "now"], :clock},
            {[jti: 1], :jti}
          ] do
        error =
          assert_raise ReqDPoP.Error, fn -> ReqDPoP.attach(Req.new(), [key: key] ++ opts) end

        assert error.reason == {:invalid_option, name}
      end

      assert {:error, %ReqDPoP.Error{reason: {:invalid_option, :jti}}} =
               ReqDPoP.proof(key: key, htm: :get, htu: "https://x.example/", jti: fn -> "" end)

      assert {:error, %ReqDPoP.Error{reason: {:invalid_option, :clock}}} =
               ReqDPoP.proof(
                 key: key,
                 htm: :get,
                 htu: "https://x.example/",
                 clock: fn -> "now" end
               )

      assert {:error, %ReqDPoP.Error{reason: :missing_option}} =
               ReqDPoP.proof(key: key, htm: nil, htu: "https://x.example/")

      assert {:error, %ReqDPoP.Error{reason: {:invalid_option, :htm}}} =
               ReqDPoP.proof(key: key, htm: "", htu: "https://x.example/")
    end

    test "refuses to combine Req's :auth with an access token" do
      request =
        Req.new(adapter: fn request -> {request, Req.Response.new(status: 200)} end)
        |> ReqDPoP.attach(key: Key.generate(:es256), access_token: "tok")

      error =
        assert_raise ReqDPoP.Error, fn ->
          Req.get!(request, url: "https://api.example.com/r", auth: {:bearer, "other"})
        end

      assert error.reason == {:conflicting_option, :auth}
    end

    test "allows Req's :auth alongside proof-only mode" do
      {:ok, log} = Agent.start_link(fn -> [] end)
      adapter = adapter(log, fn _request, _attempt -> Req.Response.new(status: 200) end)

      Req.new(adapter: adapter)
      |> ReqDPoP.attach(key: Key.generate(:es256))
      |> Req.post!(url: "https://as.example/token", auth: {:basic, "id:secret"}, form: [a: "b"])

      [sent] = requests(log)
      assert ["Basic " <> _] = Req.Request.get_header(sent, "authorization")
      refute Map.has_key?(claims(sent), "ath")
    end
  end

  describe "htu" do
    test "signs the wire form of the target URI" do
      {:ok, log} = Agent.start_link(fn -> [] end)
      adapter = adapter(log, fn _request, _attempt -> Req.Response.new(status: 200) end)

      Req.new(adapter: adapter, base_url: "HTTPS://API.Example.com")
      |> ReqDPoP.attach(key: Key.generate(:es256))
      |> Req.get!()

      [sent] = requests(log)
      assert claims(sent)["htu"] == "https://api.example.com/"
    end

    test "excludes userinfo, query, and fragment" do
      assert ReqDPoP.normalize_htu("https://user:secret@api.example.com/r?x=1#f") ==
               "https://api.example.com/r"
    end

    test "drops the default port and keeps a non-default one" do
      assert ReqDPoP.normalize_htu("https://api.example.com:443/r") == "https://api.example.com/r"

      assert ReqDPoP.normalize_htu("https://api.example.com:8443/r") ==
               "https://api.example.com:8443/r"
    end

    test "rejects relative and non-HTTP URIs" do
      key = Key.generate(:es256)

      for htu <- ["/relative", "api.example.com/r", "ftp://api.example.com/r", "https:///r"] do
        assert {:error, %ReqDPoP.Error{reason: {:invalid_option, :htu}}} =
                 ReqDPoP.proof(key: key, htm: :get, htu: htu),
               "expected #{htu} to be rejected"
      end
    end
  end

  describe "key and header hygiene" do
    test "EC proof jwk header carries only RFC 7638 members" do
      key = Key.generate(:es256)

      map =
        key
        |> Key.export()
        |> Map.merge(%{"kid" => "k1", "use" => "sig", "alg" => "ES256", "ext" => "stays home"})

      proof = ReqDPoP.proof!(key: map, htm: :get, htu: "https://api.example.com/r")
      jwk = JOSE.JWT.peek_protected(proof).fields["jwk"]

      assert Map.keys(jwk) == ["crv", "kty", "x", "y"]
      assert Key.thumbprint(map) == Key.thumbprint(key)
      assert Key.public_jwk(Key.load!(map))["kid"] == "k1"
    end

    test "RSA proof jwk header carries only RFC 7638 members" do
      proof =
        ReqDPoP.proof!(key: Key.generate(:rs256), htm: :get, htu: "https://api.example.com/r")

      assert Map.keys(JOSE.JWT.peek_protected(proof).fields["jwk"]) == ["e", "kty", "n"]
    end

    test "thumbprint accepts a public JWK" do
      key = Key.generate(:es256)
      assert Key.thumbprint(Key.public_jwk(key)) == Key.thumbprint(key)
    end

    test "an empty access token means proof-only mode" do
      {:ok, log} = Agent.start_link(fn -> [] end)
      adapter = adapter(log, fn _request, _attempt -> Req.Response.new(status: 200) end)

      Req.new(adapter: adapter)
      |> ReqDPoP.attach(key: Key.generate(:es256), access_token: "")
      |> Req.get!(url: "https://api.example.com/resource")

      [request] = requests(log)
      assert Req.Request.get_header(request, "authorization") == []
      refute Map.has_key?(claims(request), "ath")
    end

    test "rejects key types other than P-256 EC and RSA" do
      for jwk <- [JOSE.JWK.generate_key({:oct, 32}), JOSE.JWK.generate_key({:ec, "P-384"})] do
        assert {:error, %ReqDPoP.Error{reason: :unsupported_key}} =
                 ReqDPoP.proof(key: jwk, htm: :get, htu: "https://api.example.com/r")
      end
    end

    test "rejects RSA keys shorter than 2048 bits" do
      error =
        assert_raise ReqDPoP.Error, fn -> Key.load!(JOSE.JWK.generate_key({:rsa, 1024})) end

      assert error.reason == :unsupported_key
    end

    test "rejects public-only and incomplete keys at load time, without echoing them" do
      key = Key.generate(:es256)
      private = Key.export(key)
      secret = private["d"]

      incomplete = [
        Key.public_jwk(key),
        Map.drop(private, ["x", "y"]),
        Map.merge(private, %{"x" => "AAAA", "y" => "BBBB"}),
        Map.put(private, "d", "AAAA"),
        %{"kty" => "EC", "d" => secret},
        Key.generate(:rs256) |> Key.public_jwk(),
        Key.generate(:rs256) |> Key.export() |> Map.delete("n")
      ]

      for map <- incomplete do
        error = assert_raise ReqDPoP.Error, fn -> Key.load!(map) end
        assert error.reason in [:invalid_key, :unsupported_key]
        refute inspect(error) =~ secret
        refute inspect(error) =~ "AAAA"
      end
    end

    test "re-validates a hand-built key struct" do
      struct = %Key{jwk: JOSE.JWK.generate_key({:oct, 32}), alg: :es256}

      assert {:error, %ReqDPoP.Error{reason: :unsupported_key}} =
               ReqDPoP.proof(key: struct, htm: :get, htu: "https://api.example.com/r")
    end

    test "rejects an :alg that does not match the key" do
      key = Key.generate(:es256)

      assert {:error, %ReqDPoP.Error{reason: {:alg_mismatch, :rs256, :es256}}} =
               ReqDPoP.proof(key: key, alg: :rs256, htm: :get, htu: "https://api.example.com/r")

      assert {:error, %ReqDPoP.Error{reason: {:alg_mismatch, :hs256, :es256}}} =
               ReqDPoP.proof(key: key, alg: :hs256, htm: :get, htu: "https://api.example.com/r")
    end

    test "invalid key errors do not echo the rejected value" do
      pem = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEsecretsecret\n-----END EC PRIVATE KEY-----"
      error = assert_raise ReqDPoP.Error, fn -> Key.load!(pem) end
      assert error.reason == :invalid_key
      refute inspect(error) =~ "secretsecret"
    end

    test "inspecting a key shows the algorithm only" do
      map = Key.generate(:es256) |> Key.export() |> Map.put("custom_secret", "my-secret-value")
      key = Key.load!(map)
      rendered = inspect(key, limit: :infinity)

      assert rendered =~ "es256"
      refute rendered =~ "my-secret-value"
      refute rendered =~ map["d"]
    end

    test "inspecting the request does not reveal a string access token" do
      request =
        Req.new() |> ReqDPoP.attach(key: Key.generate(:es256), access_token: "super-secret-token")

      refute inspect(request, limit: :infinity) =~ "super-secret-token"
    end
  end

  defp adapter(log, respond) do
    fn request ->
      attempt = Agent.get_and_update(log, fn seen -> {length(seen) + 1, [request | seen]} end)
      {request, respond.(request, attempt)}
    end
  end

  defp requests(log), do: log |> Agent.get(& &1) |> Enum.reverse()

  defp claims(%Req.Request{} = request) do
    [proof] = Req.Request.get_header(request, "dpop")
    claims(proof)
  end

  defp claims(proof) when is_binary(proof) do
    %JOSE.JWT{fields: fields} = JOSE.JWT.peek_payload(proof)
    fields
  end

  defp token_request(adapter, opts \\ []) do
    Req.new([adapter: adapter, retry: false] ++ opts)
    |> ReqDPoP.attach(key: Key.generate(:es256))
    |> Req.post!(url: "https://as.example/token", form: [grant_type: "client_credentials"])
  end

  defp as_challenge(nonce, opts \\ []) do
    body =
      Keyword.get(
        opts,
        :body,
        ~s({"error":"use_dpop_nonce","error_description":"nonce required"})
      )

    headers = %{"dpop-nonce" => [nonce], "content-type" => ["application/json"]}

    if Keyword.get(opts, :compressed, false) do
      Req.Response.new(
        status: 400,
        headers: Map.put(headers, "content-encoding", ["gzip"]),
        body: :zlib.gzip(body)
      )
    else
      Req.Response.new(status: 400, headers: headers, body: body)
    end
  end

  defp rs_challenge(nonce) do
    Req.Response.new(
      status: 401,
      headers: %{"dpop-nonce" => [nonce], "www-authenticate" => [@nonce_challenge]}
    )
  end

  defp attempts_for_www_authenticate(value) do
    {:ok, log} = Agent.start_link(fn -> [] end)

    adapter =
      adapter(log, fn
        _request, 1 ->
          Req.Response.new(
            status: 401,
            headers: %{"dpop-nonce" => ["n"], "www-authenticate" => [value]}
          )

        _request, _attempt ->
          Req.Response.new(status: 200)
      end)

    Req.new(adapter: adapter, retry: false)
    |> ReqDPoP.attach(key: Key.generate(:es256), access_token: "tok")
    |> Req.get!(url: "https://rs.example/resource")

    length(requests(log))
  end
end
