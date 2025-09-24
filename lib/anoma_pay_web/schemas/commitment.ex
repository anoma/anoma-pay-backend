defmodule AnomaPayWeb.Schemas.Commitment do
  @moduledoc false
  require OpenApiSpex

  OpenApiSpex.schema(%{
    description: "A commitment value",
    type: :string,
    format: :byte,
    example: "0x00"
  })
end
