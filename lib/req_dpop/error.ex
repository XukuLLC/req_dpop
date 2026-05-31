defmodule ReqDPoP.Error do
  @moduledoc """
  Error raised for invalid DPoP plugin configuration or proof generation.
  """

  @type t :: %__MODULE__{message: binary(), reason: term()}

  defexception [:message, :reason]
end
