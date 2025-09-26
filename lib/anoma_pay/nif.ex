defmodule AnomaPay.NIF do
  @moduledoc """
  I define a few functions work with the counter application.
  """

  use Rustler,
    otp_app: :anoma_pay,
    crate: :anomapay_nif

  def test, do: :erlang.nif_error(:nif_not_loaded)

  @doc """
  Returns the logic ref for the counter binary.
  """
  # @spec verifying_key :: binary()
  # def verifying_key do
  #   verifying_key()
  #   |> :binary.list_to_bin()
  # end

  # @doc """
  # Prove a counter logic witness and return a logic proof.
  # """
  # @spec prove_counter_logic(CounterLogic.t()) :: LogicVerifier.t()
  # def prove_counter_logic(_), do: :erlang.nif_error(:nif_not_loaded)

  # # ----------------------------------------------------------------------------#
  # #                                Helpers                                     #
  # # ----------------------------------------------------------------------------#

  # NIF implementation.
  # Wrapped by counter_logic_ref/0 to return a binary rather than a list of bytes.
  # @spec verifying_key_nif :: [byte()]
  # defp verifying_key_nif, do: :erlang.nif_error(:nif_not_loaded)
end
