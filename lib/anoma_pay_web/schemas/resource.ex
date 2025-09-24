defmodule AnomaPayWeb.Schemas.Resource do
  @moduledoc false
  require OpenApiSpex
  alias OpenApiSpex.Schema

  OpenApiSpex.schema(%{
    description: "A resource",
    type: :object,
    properties: %{
      logic_ref: %Schema{type: :string, format: :byte},
      label_ref: %Schema{type: :string, format: :byte},
      quantity: %Schema{type: :integer},
      value_ref: %Schema{type: :string, format: :byte},
      is_ephemeral: %Schema{type: :boolean},
      nonce: %Schema{type: :string, format: :byte},
      nk_commitment: %Schema{type: :string, format: :byte},
      rand_seed: %Schema{type: :string, format: :byte}
    },
    required: [:logic_ref, :label_ref, :quantity, :value_ref, :is_ephemeral],
    example: %{
      logic_ref: "0x00",
      label_ref: "0x00",
      quantity: 124,
      value_ref: "0x00",
      is_ephemeral: true,
      nonce: "0x00",
      nk_commitment: "0x00",
      rand_seed: "0x00"
    }
  })
end
