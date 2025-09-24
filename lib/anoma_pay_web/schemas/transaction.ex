defmodule AnomaPayWeb.Schemas.Transaction do
  @moduledoc false
  require OpenApiSpex
  alias OpenApiSpex.Schema

  OpenApiSpex.schema(%{
    description: "A transaction object",
    type: :object,
    properties: %{
      expected_balance: %Schema{type: :string, format: :byte}
    },
    example: %{
      expected_balance: "0x00"
    }
  })
end
