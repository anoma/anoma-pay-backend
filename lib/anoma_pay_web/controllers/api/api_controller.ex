defmodule AnomaPayWeb.Api.APIController do
  use AnomaPayWeb, :controller
  use OpenApiSpex.ControllerSpecs

  alias AnomaPayWeb.Schemas.Create

  plug OpenApiSpex.Plug.CastAndValidate, json_render_error_v2: true

  action_fallback AnomaPayWeb.FallbackController

  operation(:create,
    summary: "Update user",
    request_body: {"User params", "application/json", Create}
  )

  def create(conn, _params) do
    params = conn.body_params
    text(conn, "ok")
  end

  # def show(conn, %{"id" => id}) do
  #   api = Transfer.get_api!(id)
  #   render(conn, :show, api: api)
  # end

  # def update(conn, %{"id" => id, "api" => api_params}) do
  #   api = Transfer.get_api!(id)

  #   with {:ok, %API{} = api} <- Transfer.update_api(api, api_params) do
  #     render(conn, :show, api: api)
  #   end
  # end

  # def delete(conn, %{"id" => id}) do
  #   api = Transfer.get_api!(id)

  #   with {:ok, %API{}} <- Transfer.delete_api(api) do
  #     send_resp(conn, :no_content, "")
  #   end
  # end
end
