defmodule AnomaPayWeb.Api.APIJSON do
  @doc """
  Renders a list of transfer.
  """
  def create(%{create: create}) do
    %{signature: Base.encode64(create.signature), commitment: Base.encode64(create.commitment)}
  end

  @doc """
  Renders a list of transfer.
  """
  def index(%{transfer: transfer}) do
    %{data: for(api <- transfer, do: data(api))}
  end

  @doc """
  Renders a single api.
  """
  def show(%{api: api}) do
    %{data: data(api)}
  end

  defp data(%{} = api) do
    %{
      id: api.id,
      signature: api.signature,
      merkle_path: api.merkle_path
    }
  end
end
