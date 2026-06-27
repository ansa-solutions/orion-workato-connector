# Orion Advisor — Workato custom connector
#
# Auth: OAuth 2.0 authorization code (https://developers.orionadvisor.com/guides/oauth/)
#   1. Authorize: browser -> {base}/api/oauth/?response_type=code&... (NO version segment)
#   2. Token exchange: POST {base}/api/v1/Security/Token (params as query string),
#      returns access_token (~10h JWT) + refresh_token (375 days, ROTATED on each use).
#   3. All API calls send: Authorization: Session <access_token>.
#
# Impersonation (https://developers.orionadvisor.com/guides/impersonation/) is a token
# exchange: GET {base}/api/v1/security/token with Authorization: Impersonate <service
# token> + Entity / EntityId / LoginName headers, returning a Session token for that
# rep/client. Driven dynamically per action via the "Get impersonation token" action.
# See the apply block for how the Impersonate vs Session scheme is selected.

{
  title: "Orion Advisor",

  # ──────────────────────────────────────────────────────────────────────────
  # Connection
  # ──────────────────────────────────────────────────────────────────────────
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
      {
        name: "client_id",
        label: "Client ID",
        optional: false,
        hint: "Partner client_id provided by Orion (must be whitelisted for the redirect URI below)"
      },
      {
        name: "client_secret",
        label: "Client secret",
        control_type: "password",
        optional: false,
        hint: "Partner client_secret provided by Orion"
      }
    ],

    base_uri: lambda do |connection|
      call(:base_url, connection)
    end,

    # OAuth 2.0 authorization-code flow. No user id / password is stored — an
    # Orion user logs in once via the browser, and Workato keeps the tokens.
    # Whitelist this redirect URI with Orion: https://www.workato.com/oauth/callback
    authorization: {
      type: "oauth2",

      client_id: lambda do |connection|
        connection["client_id"]
      end,

      client_secret: lambda do |connection|
        connection["client_secret"]
      end,

      # NOTE: path must be /api/oauth/ WITHOUT a version — Orion shows its native
      # login dialog instead if /api/v1/oauth is used. Workato appends client_id,
      # redirect_uri, response_type and state automatically.
      authorization_url: lambda do |connection|
        base = connection["environment"] == "staging" ? "https://stagingapi.orionadvisor.com" : "https://api.orionadvisor.com"
        "#{base}/api/oauth/?response_type=code"
      end,

      # Token exchange: Orion expects the values as QUERY parameters.
      acquire: lambda do |connection, auth_code, redirect_uri|
        response = post("#{call(:base_url, connection)}/api/v1/Security/Token")
                   .params(
                     grant_type: "authorization_code",
                     code: auth_code,
                     client_id: connection["client_id"],
                     client_secret: connection["client_secret"],
                     redirect_uri: redirect_uri,
                     response_type: "code"
                   )

        [
          {
            access_token: response["access_token"],
            refresh_token: response["refresh_token"]
          },
          nil,
          nil
        ]
      end,

      # Orion ROTATES refresh tokens — the old one is voided once used, so we must
      # persist the new refresh_token returned here (fall back to the old one if
      # the response omits it).
      refresh: lambda do |connection, refresh_token|
        response = post("#{call(:base_url, connection)}/api/v1/Security/Token")
                   .headers(
                     "Authorization" => "Bearer #{refresh_token}",
                     "Accept" => "application/json",
                     "client_id" => connection["client_id"],
                     "client_secret" => connection["client_secret"]
                   )

        {
          access_token: response["access_token"],
          refresh_token: response["refresh_token"].presence || refresh_token
        }
      end,

      # Orion returns 401 once the ~10h access token expires; refresh transparently.
      refresh_on: [401, 403],

      detect_on: [/"errorCode"/, /Unauthorized/],

      # The service access token lives only inside `apply` (OAuth2 manages it), so
      # impersonation is driven from here via flags an action sets on `connection`:
      #   _imp_exchange = true  -> minting an impersonation token: send the SERVICE
      #                            token with the "Impersonate" scheme (Orion's rule).
      #   _imp_token    = "..." -> acting AS an impersonated user: send that token
      #                            with the normal "Session" scheme.
      #   neither               -> normal service-level call.
      # This is deterministic regardless of header precedence between apply/execute.
      apply: lambda do |connection, access_token|
        if connection["_imp_exchange"]
          headers("Authorization" => "Impersonate #{access_token}")
        elsif connection["_imp_token"].present?
          headers("Authorization" => "Session #{connection['_imp_token']}")
        else
          headers("Authorization" => "Session #{access_token}")
        end
      end
    }
  },

  test: lambda do |_connection|
    # Returns the currently authenticated user — cheapest authenticated call.
    get("/api/v1/Authorization/User")
  end,

  # ──────────────────────────────────────────────────────────────────────────
  # Reusable methods
  # ──────────────────────────────────────────────────────────────────────────
  methods: {
    base_url: lambda do |connection|
      if connection["environment"] == "staging"
        "https://stagingapi.orionadvisor.com"
      else
        "https://api.orionadvisor.com"
      end
    end,

    entity_pick_list: lambda do
      [["Representative", 4], ["Client", 5]]
    end,

    # Exchange the service token for an impersonation token scoped to a rep/client.
    # Sets _imp_exchange so `apply` sends the service token with the "Impersonate"
    # scheme, then always clears it.
    mint_impersonation_token: lambda do |connection, entity, entity_id, login_name|
      h = {
        "client_id" => connection["client_id"],
        "client_secret" => connection["client_secret"],
        "Entity" => entity.to_s,
        "EntityId" => entity_id.to_s
      }
      h["LoginName"] = login_name if login_name.present?

      connection["_imp_exchange"] = true
      result = get("#{call(:base_url, connection)}/api/v1/security/token").headers(h)
      connection["_imp_exchange"] = false
      result
    end,

    # Shared output schema for a Portfolio "Client".
    client_schema: lambda do
      [
        { name: "id", type: "integer" },
        { name: "name" },
        { name: "firstName" },
        { name: "lastName" },
        { name: "isActive", type: "boolean" },
        { name: "clientType" },
        { name: "repId", type: "integer", label: "Rep ID" },
        { name: "repName", label: "Rep name" },
        { name: "householdId", type: "integer" },
        { name: "custodian" },
        { name: "startDate", type: "date_time" },
        { name: "marketValue", type: "number" }
      ]
    end,

    # Shared output schema for a Portfolio "Account".
    account_schema: lambda do
      [
        { name: "id", type: "integer" },
        { name: "accountNumber" },
        { name: "name" },
        { name: "isActive", type: "boolean" },
        { name: "accountType" },
        { name: "clientId", type: "integer" },
        { name: "clientName" },
        { name: "registrationId", type: "integer" },
        { name: "custodian" },
        { name: "managementStyle" },
        { name: "modelName" },
        { name: "value", type: "number", label: "Market value" },
        { name: "cashBalance", type: "number" },
        { name: "startDate", type: "date_time" }
      ]
    end
  },

  object_definitions: {
    client: { fields: lambda do |_connection, _config| call(:client_schema) end },
    account: { fields: lambda do |_connection, _config| call(:account_schema) end }
  },

  pick_lists: {
    entities: lambda do |_connection|
      call(:entity_pick_list)
    end
  },

  # ──────────────────────────────────────────────────────────────────────────
  # Actions
  # ──────────────────────────────────────────────────────────────────────────
  actions: {

    get_impersonation_token: {
      title: "Get impersonation token",
      subtitle: "Mint a token scoped to a representative or client",
      description: "Get an <span class='provider'>impersonation token</span> in <span class='provider'>Orion Advisor</span>",
      help: "Returns an access token scoped to the chosen rep/client. Pass the returned " \
            "<b>Impersonation token</b> into the optional field on other actions to run " \
            "those calls as that user. Token lifetime is ~10 hours.",

      input_fields: lambda do |_object_definitions|
        [
          { name: "entity", label: "Impersonate as", control_type: "select",
            pick_list: "entities", optional: false,
            hint: "Representative (Entity 4) or Client (Entity 5)" },
          { name: "entity_id", label: "Entity ID", type: "integer", optional: false,
            hint: "The Rep ID or Client ID to impersonate" },
          { name: "login_name", label: "Login name", sticky: true,
            hint: "Optional — required only for non-default representative logins" }
        ]
      end,

      execute: lambda do |connection, input|
        response = call(:mint_impersonation_token, connection,
                        input["entity"], input["entity_id"], input["login_name"])
        {
          access_token: response["access_token"],
          expires_in: response["expires_in"],
          entity: input["entity"],
          entity_id: input["entity_id"]
        }
      end,

      output_fields: lambda do |_object_definitions|
        [
          { name: "access_token", label: "Impersonation token" },
          { name: "expires_in", type: "number", hint: "Seconds until the token expires" },
          { name: "entity", type: "integer" },
          { name: "entity_id", type: "integer" }
        ]
      end
    },

    get_clients: {
      title: "Search clients",
      subtitle: "Get a list of Portfolio clients from Orion",
      description: "Get <span class='provider'>clients</span> in <span class='provider'>Orion Advisor</span>",

      input_fields: lambda do |_object_definitions|
        [
          { name: "search", label: "Search term", sticky: true,
            hint: "Filters clients by name (Orion 'search' query parameter)" },
          { name: "top", label: "Max records", type: "integer", sticky: true,
            hint: "Limits the number of records returned" },
          { name: "impersonation_token", label: "Impersonation token", sticky: true,
            hint: "Token from the 'Get impersonation token' action. If set, this call runs as that rep/client." }
        ]
      end,

      execute: lambda do |connection, input|
        connection["_imp_token"] = input["impersonation_token"]
        params = {}
        params["search"] = input["search"] if input["search"].present?
        params["top"]    = input["top"]    if input["top"].present?

        { clients: get("/api/v1/Portfolio/Clients", params) }
      end,

      output_fields: lambda do |object_definitions|
        [{ name: "clients", type: "array", of: "object",
           properties: object_definitions["client"] }]
      end,

      sample_output: lambda do |_connection, _input|
        { clients: [get("/api/v1/Portfolio/Clients", { "top" => 1 })].flatten.first(1) }
      end
    },

    get_client: {
      title: "Get client by ID",
      description: "Get a <span class='provider'>client</span> by ID in <span class='provider'>Orion Advisor</span>",

      input_fields: lambda do |_object_definitions|
        [
          { name: "id", label: "Client ID", type: "integer", optional: false },
          { name: "impersonation_token", label: "Impersonation token", sticky: true,
            hint: "Token from the 'Get impersonation token' action. If set, this call runs as that rep/client." }
        ]
      end,

      execute: lambda do |connection, input|
        connection["_imp_token"] = input["impersonation_token"]
        get("/api/v1/Portfolio/Clients/#{input['id']}")
      end,

      output_fields: lambda do |object_definitions|
        object_definitions["client"]
      end
    },

    get_accounts: {
      title: "Search accounts",
      subtitle: "Get a list of Portfolio accounts from Orion",
      description: "Get <span class='provider'>accounts</span> in <span class='provider'>Orion Advisor</span>",

      input_fields: lambda do |_object_definitions|
        [
          { name: "clientId", label: "Client ID", type: "integer", sticky: true,
            hint: "Restrict to accounts for a single client" },
          { name: "search", label: "Search term", sticky: true },
          { name: "top", label: "Max records", type: "integer", sticky: true },
          { name: "impersonation_token", label: "Impersonation token", sticky: true,
            hint: "Token from the 'Get impersonation token' action. If set, this call runs as that rep/client." }
        ]
      end,

      execute: lambda do |connection, input|
        connection["_imp_token"] = input["impersonation_token"]
        params = {}
        params["clientId"] = input["clientId"] if input["clientId"].present?
        params["search"]   = input["search"]   if input["search"].present?
        params["top"]      = input["top"]       if input["top"].present?

        { accounts: get("/api/v1/Portfolio/Accounts", params) }
      end,

      output_fields: lambda do |object_definitions|
        [{ name: "accounts", type: "array", of: "object",
           properties: object_definitions["account"] }]
      end
    },

    get_account: {
      title: "Get account by ID",
      description: "Get an <span class='provider'>account</span> by ID in <span class='provider'>Orion Advisor</span>",

      input_fields: lambda do |_object_definitions|
        [
          { name: "id", label: "Account ID", type: "integer", optional: false },
          { name: "impersonation_token", label: "Impersonation token", sticky: true,
            hint: "Token from the 'Get impersonation token' action. If set, this call runs as that rep/client." }
        ]
      end,

      execute: lambda do |connection, input|
        connection["_imp_token"] = input["impersonation_token"]
        get("/api/v1/Portfolio/Accounts/#{input['id']}")
      end,

      output_fields: lambda do |object_definitions|
        object_definitions["account"]
      end
    },

    # Escape hatch: call any Orion endpoint not modelled above.
    custom_request: {
      title: "Send custom request",
      subtitle: "Call any Orion Advisor API endpoint",
      description: "Send a <span class='provider'>custom request</span> to <span class='provider'>Orion Advisor</span>",
      help: "Use the path relative to the host, e.g. <b>/api/v1/Portfolio/Households</b>. " \
            "The Authorization header is added automatically.",

      input_fields: lambda do |_object_definitions|
        [
          { name: "method", control_type: "select", optional: false,
            pick_list: [%w[GET get], %w[POST post], %w[PUT put],
                        %w[PATCH patch], %w[DELETE delete]],
            default: "get" },
          { name: "path", optional: false,
            hint: "Relative path, e.g. /api/v1/Portfolio/Households" },
          { name: "query_params", type: "object",
            control_type: "key_value", label: "Query parameters",
            hint: "Appended to the URL as ?key=value" },
          { name: "body", type: "object", control_type: "key_value",
            hint: "Request body for POST/PUT/PATCH" },
          { name: "impersonation_token", label: "Impersonation token", sticky: true,
            hint: "Token from the 'Get impersonation token' action. If set, this call runs as that rep/client." }
        ]
      end,

      execute: lambda do |connection, input|
        connection["_imp_token"] = input["impersonation_token"]
        verb   = (input["method"] || "get").downcase
        params = input["query_params"] || {}
        body   = input["body"] || {}

        response =
          case verb
          when "get"    then get(input["path"], params)
          when "delete" then delete(input["path"], params)
          when "post"   then post(input["path"], body).params(params)
          when "put"    then put(input["path"], body).params(params)
          when "patch"  then patch(input["path"], body).params(params)
          else error("Unsupported method: #{verb}")
          end

        { response: response }
      end,

      output_fields: lambda do |_object_definitions|
        [{ name: "response" }]
      end
    }
  },

  # ──────────────────────────────────────────────────────────────────────────
  # Triggers  (polling — Orion's REST API has no webhooks)
  # ──────────────────────────────────────────────────────────────────────────
  triggers: {

    new_client: {
      title: "New client",
      subtitle: "Triggers when a new client is added in Orion",
      description: "New <span class='provider'>client</span> in <span class='provider'>Orion Advisor</span>",
      help: "Polls the Portfolio Clients list and emits clients whose ID is higher " \
            "than any seen before. Orion IDs are monotonically increasing.",

      input_fields: lambda do |_object_definitions|
        [{ name: "search", label: "Search filter", sticky: true,
           hint: "Optional name filter passed to Orion" }]
      end,

      poll: lambda do |_connection, input, last_id|
        params = { "orderBy" => "id desc" }
        params["search"] = input["search"] if input["search"].present?

        records = get("/api/v1/Portfolio/Clients", params)
        records = records.select { |r| r["id"].to_i > last_id.to_i } if last_id.present?

        next_id = records.map { |r| r["id"].to_i }.max || last_id

        {
          events: records,
          next_poll: next_id,
          can_poll_more: false
        }
      end,

      dedup: lambda do |record|
        record["id"]
      end,

      output_fields: lambda do |object_definitions|
        object_definitions["client"]
      end
    },

    new_account: {
      title: "New account",
      subtitle: "Triggers when a new account is added in Orion",
      description: "New <span class='provider'>account</span> in <span class='provider'>Orion Advisor</span>",
      help: "Polls the Portfolio Accounts list and emits accounts whose ID is higher " \
            "than any seen before.",

      input_fields: lambda do |_object_definitions|
        [{ name: "clientId", label: "Client ID", type: "integer", sticky: true,
           hint: "Optionally restrict to a single client" }]
      end,

      poll: lambda do |_connection, input, last_id|
        params = { "orderBy" => "id desc" }
        params["clientId"] = input["clientId"] if input["clientId"].present?

        records = get("/api/v1/Portfolio/Accounts", params)
        records = records.select { |r| r["id"].to_i > last_id.to_i } if last_id.present?

        next_id = records.map { |r| r["id"].to_i }.max || last_id

        {
          events: records,
          next_poll: next_id,
          can_poll_more: false
        }
      end,

      dedup: lambda do |record|
        record["id"]
      end,

      output_fields: lambda do |object_definitions|
        object_definitions["account"]
      end
    }
  }
}
