defmodule EctoBase64 do
  @moduledoc """
  An ecto type that defines a base64 string. Validates that the string is valid
  base64 data.
  """
  use Ecto.Type

  def type, do: :string

  def cast(data) when is_binary(data) do
    case Base.decode64(data) do
      {:ok, data} -> {:ok, data}
      :error -> {:error, message: "invalid base64 string"}
    end
  end

  def cast(_), do: {:error, message: "invalid base64 string"}

  def load(data) when is_binary(data) do
    Base.decode64(data)
  end

  def dump(data) when is_binary(data) do
    {:ok, Base.encode64(data)}
  end

  def dump(_), do: :error
end
