defmodule AnomaPayWeb.Schemas.Create do
  @moduledoc false
  require OpenApiSpex
  alias AnomaPayWeb.Schemas.Commitment
  alias AnomaPayWeb.Schemas.MerklePath
  alias AnomaPayWeb.Schemas.Resource
  alias AnomaPayWeb.Schemas.Signature

  OpenApiSpex.schema(%{
    description: "A create request",
    type: :object,
    properties: %{
      commitment: Commitment.schema(),
      signature: Signature.schema(),
      merkle_path: MerklePath.schema(),
      resource: Resource.schema()
    },
    required: [:commitment, :signature, :merkle_path, :resource],
    example: %{
      commitment: Commitment.schema().example,
      signature: Signature.schema().example,
      merkle_path: MerklePath.schema().example,
      resource: Resource.schema().example
    }
  })
end
