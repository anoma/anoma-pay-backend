defmodule AnomaPayWeb.Schemas.Nullifier do
  @moduledoc false
  require OpenApiSpex

  OpenApiSpex.schema(%{
    description: "A nullifier value",
    type: :string,
    format: :byte,
    example: "0x00"
  })
end
