defmodule AnomaPayWeb.Router do
  use AnomaPayWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {AnomaPayWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug OpenApiSpex.Plug.PutApiSpec, module: AnomaPayWeb.ApiSpec
  end

  pipeline :api do
    plug :accepts, ["json"]
    plug OpenApiSpex.Plug.PutApiSpec, module: AnomaPayWeb.ApiSpec
  end

  scope "/" do
    pipe_through :browser

    scope "/openapi" do
      # serve the spec
      get "/", OpenApiSpex.Plug.RenderSpec, []
      # allow openapi to be rendered in the browser
      get "/swaggerui", OpenApiSpex.Plug.SwaggerUI, path: "/openapi"
    end
  end

  scope "/api", AnomaPayWeb do
    pipe_through :api

    post "/create", Api.APIController, :create
  end

  # Other scopes may use custom stacks.
  # scope "/api", AnomaPayWeb do
  #   pipe_through :api
  # end

  # Enable LiveDashboard in development
  if Application.compile_env(:anoma_pay, :dev_routes) do
    # If you want to use the LiveDashboard in production, you should put
    # it behind authentication and allow only admins to access it.
    # If your application does not have an admins-only section yet,
    # you can use Plug.BasicAuth to set up some basic authentication
    # as long as you are also using SSL (which you should anyway).
    import Phoenix.LiveDashboard.Router

    scope "/dev" do
      pipe_through :browser

      live_dashboard "/dashboard", metrics: AnomaPayWeb.Telemetry
    end
  end
end
