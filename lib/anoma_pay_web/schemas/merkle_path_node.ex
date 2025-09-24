defmodule AnomaPayWeb.Schemas.MerklePathNode do
  @moduledoc false
  require OpenApiSpex
  alias OpenApiSpex.Schema

  OpenApiSpex.schema(%{
    description: "A node in a merkle path",
    type: :object,
    properties: %{
      node: %Schema{type: :string, format: :byte},
      left: %Schema{type: :boolean}
    },
    example: %{
      node: "0x00",
      left: true
    }
  })
end
