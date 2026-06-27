{
  title: "Orion Advisor",

  connection: {
    fields: [
      {
        name: "environment",
        label: "Environment",
        control_type: "select",
        pick_list: [%w[Production production], %w[Staging staging]],
        default: "production",
        optional: false,
        hint: "Production = api.orionadvisor.com, Staging = stagingapi.orionadvisor.com"
      },
      { name: "client_id", label: "Client ID", optional: false,
        hint: "Partner client_id provided by Orion" },
      { name: "client_secret", label: "Client secret", control_type: "password",
        optional: false, hint: "Partner client_secret provided by Orion" }
    ],

    base_uri: lambda do |connection|
      connection["environment"] == "staging" ? "https://stagingapi.orionadvisor.com" : "https://api.orionadvisor.com"
    end,

    authorization: {
      type: "oauth2",
      client_id: lambda { |connection| connection["client_id"] },
      client_secret: lambda { |connection| connection["client_secret"] },

      authorization_url: lambda do |connection|
        base = connection["environment"] == "staging" ? "https://stagingapi.orionadvisor.com" : "https://api.orionadvisor.com"
        "#{base}/api/oauth/?response_type=code"
      end,

      acquire: lambda do |connection, auth_code, redirect_uri|
        base = connection["environment"] == "staging" ? "https://stagingapi.orionadvisor.com" : "https://api.orionadvisor.com"
        response = post("#{base}/api/v1/Security/Token")
                   .params(grant_type: "authorization_code", code: auth_code,
                           client_id: connection["client_id"], client_secret: connection["client_secret"],
                           redirect_uri: redirect_uri, response_type: "code")
        [{ access_token: response["access_token"], refresh_token: response["refresh_token"] }, nil, nil]
      end,

      refresh: lambda do |connection, refresh_token|
        base = connection["environment"] == "staging" ? "https://stagingapi.orionadvisor.com" : "https://api.orionadvisor.com"
        response = post("#{base}/api/v1/Security/Token")
                   .headers("Authorization" => "Bearer #{refresh_token}", "Accept" => "application/json",
                            "client_id" => connection["client_id"], "client_secret" => connection["client_secret"])
        { access_token: response["access_token"],
          refresh_token: response["refresh_token"].presence || refresh_token }
      end,

      refresh_on: [401, 403],
      detect_on: [/"errorCode"/, /Unauthorized/],
      apply: lambda { |_connection, access_token| headers("Authorization" => "Session #{access_token}") }
    }
  },

  test: lambda { |_connection| get("/api/v1/Authorization/User") }
}