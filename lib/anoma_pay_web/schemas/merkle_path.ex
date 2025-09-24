defmodule AnomaPayWeb.Schemas.MerklePath do
  @moduledoc false
  require OpenApiSpex
  alias AnomaPayWeb.Schemas.MerklePathNode

  OpenApiSpex.schema(%{
    description: "A merkle path",
    type: :array,
    items: MerklePathNode,
    example: List.duplicate(MerklePathNode.schema().example, 2)
  })
end
