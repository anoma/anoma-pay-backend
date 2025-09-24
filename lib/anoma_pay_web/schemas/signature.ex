defmodule AnomaPayWeb.Schemas.Signature do
  @moduledoc false
  require OpenApiSpex

  OpenApiSpex.schema(%{
    # The title is optional. It defaults to the last section of the module name.
    # So the derived title for MyApp.User is "User".
    title: "Signature",
    description: "A signature",
    type: :string,
    format: :byte,
    example: "0x00"
  })
end
