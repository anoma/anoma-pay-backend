defmodule AnomaPay.Repo do
  use Ecto.Repo,
    otp_app: :anoma_pay,
    adapter: Ecto.Adapters.Postgres
end
