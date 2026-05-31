defmodule ReqDPoP.Nonce do
  @moduledoc false

  @doc false
  def challenge_nonce(%Req.Response{} = response) do
    nonce = first_header(response, "dpop-nonce")

    if dpop_nonce_challenge?(response) and is_binary(nonce) and nonce != "" do
      {:ok, nonce}
    else
      :error
    end
  end

  defp dpop_nonce_challenge?(%Req.Response{status: status} = response)
       when status in [400, 401] do
    response
    |> Req.Response.get_header("www-authenticate")
    |> Enum.any?(&dpop_use_nonce?/1)
  end

  defp dpop_nonce_challenge?(_response), do: false

  defp dpop_use_nonce?(value) when is_binary(value) do
    value = String.downcase(value)
    String.contains?(value, "dpop") and String.contains?(value, "use_dpop_nonce")
  end

  defp first_header(response, name) do
    response
    |> Req.Response.get_header(name)
    |> List.first()
  end
end
