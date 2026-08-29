{
  title: 'Orion Advisor Solutions',
  description: 'Orion API. OAuth 2.0 only.',
  connection: {
    fields: [
      {
        name: 'environment',
        label: 'Environment',
        control_type: 'select',
        pick_list: [
          ['Staging', 'https://stagingapi.orionadvisor.com'],
          ['Production', 'https://api.orionadvisor.com']
        ],
        default: 'https://stagingapi.orionadvisor.com',
        optional: false,
        hint: 'Must match the environment the OAuth application was registered in.'
      },
      {
        name: 'client_id',
        label: 'Client ID',
        optional: false,
        hint: 'Issued by Orion when the OAuth application is registered.'
      },
      {
        name: 'client_secret',
        label: 'Client Secret',
        control_type: 'password',
        optional: false
      },
      {
        name: 'client_auth_method',
        label: 'Client authentication',
        control_type: 'select',
        pick_list: [
          ['Request body (form fields) - DEFAULT, matches the original working connector', 'body'],
          ['HTTP Basic header', 'basic'],
          ['Both body and Basic (NOT RFC compliant - last resort only)', 'both']
        ],
        default: 'body',
        optional: false,
        hint: 'Leave on "Request body". Try "Basic" only if sign in fails. "Both" breaks RFC 6749 and most servers reject it outright - diagnostic only.'
      },
      {
        name: 'token_app_header',
        label: 'Send App header on token requests',
        control_type: 'checkbox',
        type: :boolean,
        default: false,
        optional: true,
        hint: 'Data endpoints always send it; the token endpoint did not need it. Enable only if Orion support says otherwise.'
      },
      {
        name: 'refresh_style',
        label: 'Refresh request style',
        control_type: 'select',
        pick_list: [
          ['Auto - standard form body, fall back to legacy headers', 'auto'],
          ['Form body only (RFC 6749)', 'form_body'],
          ['Legacy headers only', 'legacy_headers']
        ],
        default: 'auto',
        optional: false,
        hint: 'Auto tries the standard form body, then the header style the previous connector used. Only the ~10h token expiry exercises this, so a wrong choice surfaces overnight.'
      },
      {
        name: 'redirect_uri',
        label: 'Redirect URI',
        default: 'https://www.workato.com/oauth/callback',
        optional: false,
        hint: 'Must match the value registered with Orion.'
      },
      {
        name: 'scope',
        label: 'Scope',
        optional: true,
        hint: 'Space delimited. Leave blank if Orion does not require scopes.'
      },
      {
        name: 'token_prefix',
        label: 'Token header prefix',
        control_type: 'select',
        pick_list: [['Session', 'Session'], ['Bearer', 'Bearer']],
        default: 'Session',
        optional: false,
        hint: 'Orion data endpoints natively use Session. Bearer is kept only as a fallback - ' \
              'if sign in succeeds but every data call 401s, you are on the wrong prefix.'
      },
      {
        name: 'identity_path',
        label: 'Identity endpoint path',
        default: '/api/v1/Authorization/User',
        optional: false,
        hint: 'Called at sign in AND on every Get Signed In User call. Change here if Orion publishes a different path.'
      },
      {
        name: 'mask_account_numbers',
        label: 'Mask account numbers everywhere',
        control_type: 'checkbox',
        type: :boolean,
        default: true,
        optional: true,
        hint: 'Leaves only the last 4 on every account number. Turn off only for a controlled reconciliation run.'
      },
      {
        name: 'refuse_tenant_wide',
        label: 'Refuse tenant wide results',
        control_type: 'checkbox',
        type: :boolean,
        default: false,
        optional: true,
        hint: 'Orion does not enforce advisor scope here - omitting a Representative ID returns the whole tenant. When on, unscoped list calls raise instead.'
      }
    ],
    authorization: {
      type: 'oauth2',
      client_id: lambda do |connection|
        connection['client_id']
      end,
      client_secret: lambda do |connection|
        connection['client_secret']
      end,
      authorization_url: lambda do |connection|
        params = {
          'response_type' => 'code',
          'client_id' => connection['client_id'],
          'redirect_uri' => connection['redirect_uri']
        }
        params['scope'] = connection['scope'] if connection['scope'].present?
        "#{connection['environment']}/api/oauth?#{params.to_param}"
      end,
      token_url: lambda do |connection|
        "#{connection['environment']}/api/v1/Security/Token"
      end,
      acquire: lambda do |connection, auth_code, redirect_uri|
        res = call('token_request', connection, 'authorization_code',
                   'grant_type' => 'authorization_code',
                   'code' => auth_code,
                   'redirect_uri' => redirect_uri)
        identity = call('fetch_identity', connection, res['access_token'])
        [
          {
            'access_token' => res['access_token'],
            'refresh_token' => res['refresh_token'],
            'expires_in' => res['expires_in'],
            'token_type' => res['token_type']
          },
          identity['email'],
          {
            'user_email' => identity['email'],
            'user_id' => identity['user_id'],
            'rep_id' => identity['rep_id']
          }
        ]
      end,
      refresh: lambda do |connection, refresh_token|
        style = (connection['refresh_style'].presence || 'auto').to_s.downcase
        res =
          if style == 'legacy_headers'
            call('legacy_refresh_request', connection, refresh_token)
          elsif style == 'form_body'
            call('token_request', connection, 'refresh_token',
                 'grant_type' => 'refresh_token',
                 'refresh_token' => refresh_token)
          else
            begin
              call('token_request', connection, 'refresh_token',
                   'grant_type' => 'refresh_token',
                   'refresh_token' => refresh_token)
            rescue StandardError => standard_error
              begin
                call('legacy_refresh_request', connection, refresh_token)
              rescue StandardError => legacy_error
                error('Orion token refresh failed in BOTH request styles, so the connection ' \
                      'cannot renew itself and must be re-authorized. ' \
                      "Standard form body attempt: #{standard_error.message} " \
                      "Legacy header attempt: #{legacy_error.message} " \
                      'If one of these looks like the right shape, pin it on the connection with ' \
                      '"Refresh request style" so the failing attempt is not made at all.')
              end
            end
          end
        {
          'access_token' => res['access_token'],
          'refresh_token' => res['refresh_token'] || refresh_token,
          'expires_in' => res['expires_in']
        }
      end,
      refresh_on: [401, 403],
      detect_on: [/"error"\s*:\s*"invalid_token"/],
      apply: lambda do |connection, access_token|
        headers('Authorization' => "#{connection['token_prefix'].presence || 'Session'} #{access_token}")
      end
    },
    base_uri: lambda do |connection|
      connection['environment']
    end
  },
  methods: {
    orion_headers: lambda do |apppath|
      {
        'App' => 'OrionConnect',
        'Apppath' => apppath,
        'Content-Type' => 'application/json'
      }
    end,
    orion_correlation_id: lambda do |response_headers|
      response_headers.find { |k, _| k.to_s.downcase == 'x-oas-correlationid' }&.last ||
        response_headers.find { |k, _| k.to_s.downcase == 'correlation-id' }&.last
    end,
    to_bool: lambda do |value, default|
      return default if value.nil? || value.to_s.strip.empty?
      %w[true t yes y 1].include?(value.to_s.strip.downcase)
    end,
    identity_path: lambda do |connection|
      path = connection['identity_path'].presence || '/api/v1/Authorization/User'
      if path.start_with?('//') || !path.match?(%r{\A/[A-Za-z0-9._~%!$&'()*+,;=:@/-]*\z})
        error("Identity endpoint path must be a plain path starting with a single '/'. " \
              "Got: #{path}. A value carrying a host, a scheme, or a leading '//' would send " \
              'the Orion access token to a different server.')
      end
      path
    end,
    token_request: lambda do |connection, grant_label, payload|
      if connection['client_id'].blank? || connection['client_secret'].blank?
        error('Orion connection is missing a Client ID or Client Secret. ' \
              'Nothing was sent to Orion. This is a Workato connection problem, not an Orion problem - ' \
              'if you also saw "Unknown/invalid shared account with id =", the connection record ' \
              'could not be resolved, so the credential fields came through empty. ' \
              'Re-link or re-authorize the Orion connection.')
      end
      base  = connection['environment']
      style = (connection['client_auth_method'].presence || 'body').to_s.downcase
      body = payload.dup
      if %w[body both].include?(style)
        body['client_id']     = connection['client_id']
        body['client_secret'] = connection['client_secret']
      end
      req_headers = {}
      req_headers['App'] = 'OrionConnect' if call('to_bool', connection['token_app_header'], false)
      if %w[basic both].include?(style)
        req_headers['Authorization'] =
          "Basic #{"#{connection['client_id']}:#{connection['client_secret']}".encode_base64.gsub("\n", '')}"
      end
      post("#{base}/api/v1/Security/Token")
        .payload(body)
        .headers(req_headers)
        .request_format_www_form_urlencoded
        .after_error_response(/.*/) do |code, resp_body, resp_headers, message|
          shown = resp_body.to_s.strip
          shown = '(empty - server sent no error payload)' if shown.blank?
          diag =
            if code == 401 && resp_body.to_s.strip.blank? && style == 'both'
              'You are on client auth style "both", which sends the credentials in the Basic header ' \
              'AND the form body. RFC 6749 section 2.3.1 forbids that, and a bare 401 with no body is ' \
              'the usual rejection - the credentials themselves are probably fine. ' \
              'SET "Client authentication" TO "Request body (form fields)" AND RETRY. ' \
              'That is what the original connector sent and what staging accepts.'
            elsif code == 401 && resp_body.to_s.strip.blank?
              'An empty body on a 401 is a CLIENT AUTHENTICATION failure, not a bad user or code. ' \
              "Checks in order: (1) are client_id/client_secret populated on this connection; " \
              "(2) set 'Client authentication' to 'Request body (form fields)' first, then try 'Basic'; " \
              "(3) does the Environment match where the OAuth app is registered (currently #{base}); " \
              '(4) if you also saw "Unknown/invalid shared account with id =", the Workato connection ' \
              'record is unresolved and the credentials arrived blank - relink the connection.'
            elsif code == 400
              'A 400 usually means the authorization code expired or was already used. Re-run the sign in.'
            else
              'Route reached Orion and Orion rejected it. Read the body above.'
            end
          error("Orion token #{grant_label} failed (#{code}): #{message}. " \
                "Body: #{shown}. Client auth style tried: #{style}. Environment: #{base}. #{diag} " \
                "Correlation ID: #{call('orion_correlation_id', resp_headers)}")
        end
    end,
    legacy_refresh_request: lambda do |connection, refresh_token|
      # The shape the previously working connector used: refresh token as a Bearer header,
      # credentials as HTTP headers, no request body at all. Kept as a fallback because the
      # ~10 hour expiry is the only thing that exercises the refresh path.
      post("#{connection['environment']}/api/v1/Security/Token")
        .headers(
          'Authorization' => "Bearer #{refresh_token}",
          'Accept' => 'application/json',
          'client_id' => connection['client_id'],
          'client_secret' => connection['client_secret']
        )
        .after_error_response(/.*/) do |code, resp_body, resp_headers, message|
          error("legacy header style refresh failed (#{code}): #{message}. " \
                "Body: #{resp_body.to_s.strip.presence || '(empty)'}. " \
                "Correlation ID: #{call('orion_correlation_id', resp_headers)}")
        end
    end,
    guard_scope: lambda do |connection, scoped, action_label|
      if !scoped && call('to_bool', connection['refuse_tenant_wide'], false)
        error("#{action_label} was called with no representative or client filter, which returns " \
              'the ENTIRE TENANT. "Refuse tenant wide results" is on for this connection, so the ' \
              'call was stopped rather than handing back cross advisor data. Supply a ' \
              'Representative ID from the entitlement table, or a Client ID.')
      end
      scoped
    end,
    fetch_identity: lambda do |connection, access_token|
      prefix = connection['token_prefix'].presence || 'Session'
      path   = call('identity_path', connection)
      res = get("#{connection['environment']}#{path}")
        .headers('Authorization' => "#{prefix} #{access_token}", 'App' => 'OrionConnect')
        .after_error_response(/.*/) do |code, body, _headers, message|
          error("Signed in user lookup failed (#{code}) at #{path}: #{message}. " \
                "Body: #{call('safe_body', connection, body, 500)}. " \
                'Auth succeeded, so this is a wrong path or a missing scope, not a credential problem.')
        end
      email = res['email'] || res['emailAddress'] || res['userName'] || res['loginUserId']
      error('Orion returned no email on the identity endpoint. Advisor scoping cannot be enforced.') if email.blank?
      {
        'email' => email.to_s.downcase,
        'user_id' => res['id'] || res['userId'],
        'rep_id' => res['repId'] || res['representativeId']
      }
    end,
    unwrap_array: lambda do |res|
      return [] if res.nil?
      return res.flatten(1) if res.is_a?(Array)
      if res.is_a?(Hash)
        # Some Orion routes wrap the collection in an envelope. Returning [res] for those
        # produces one nonsense row and a count of 1, which reads as a real (tiny) result.
        %w[data items results rows records value].each do |k|
          return res[k].flatten(1) if res[k].is_a?(Array)
        end
        return [res]
      end
      arr = begin
        res.to_a
      rescue StandardError
        nil
      end
      arr.is_a?(Array) ? arr.flatten(1) : [res].compact
    end,
    unwrap_hash: lambda do |res|
      return res if res.is_a?(Hash)
      return {} if res.nil? || res.is_a?(Array)
      h = begin
        res.to_h
      rescue StandardError
        nil
      end
      h.is_a?(Hash) ? h : {}
    end,
    parse_id_list: lambda do |raw|
      raw.to_s.split(',').map { |s| s.to_s.strip }.reject(&:blank?)
    end,
    row_account_keys: lambda do |row|
      # Deliberately excludes row['id']: on the rep level books that is the beneficiary /
      # systematic / RMD record's own id, not an account id, and matching on it returns
      # rows belonging to a different client.
      [row['accountId'], row['acctCode'], row['accountNumber'], row['number']]
        .compact.map { |v| v.to_s.strip.downcase }.reject(&:blank?).uniq
    end,
    filter_by_account_ids: lambda do |rows, raw_ids|
      wanted = call('parse_id_list', raw_ids).map(&:downcase)
      next [rows, false, []] if wanted.blank?
      matched_ids = []
      filtered = rows.select do |r|
        keys = call('row_account_keys', r)
        hit = wanted.select { |w| keys.include?(w) }
        matched_ids.concat(hit)
        hit.present?
      end
      [filtered, true, (wanted - matched_ids.uniq)]
    end,
    mask_account_number: lambda do |value|
      s = value.to_s.strip
      next s if s.blank?
      alnum = s.gsub(/[^0-9A-Za-z]/, '')
      alnum.length > 4 ? "*#{alnum[-4, 4]}" : s
    end,
    mask_account_id: lambda do |value|
      s = value.to_s.strip
      next s if s.blank?
      # A real Orion accountId is a plain integer and must stay usable as a join key.
      # Anything else is a custodian account code (e.g. "636-148526") and is an account
      # number by another name, so it gets masked.
      next s if s.match?(/\A\d+\z/)
      call('mask_account_number', s)
    end,
    mask_any: lambda do |connection, obj|
      next obj unless call('to_bool', connection['mask_account_numbers'], true)
      number_keys = %w[number accountNumber acctCode]
      if obj.is_a?(Hash)
        obj.map do |k, v|
          if number_keys.any? { |n| n.casecmp?(k.to_s) }
            [k, call('mask_account_number', v)]
          elsif k.to_s.casecmp?('accountId')
            [k, call('mask_account_id', v)]
          else
            [k, call('mask_any', connection, v)]
          end
        end.to_h
      elsif obj.is_a?(Array)
        obj.map { |v| call('mask_any', connection, v) }
      else
        obj
      end
    end,
    mask_rows: lambda do |connection, rows|
      call('mask_any', connection, rows)
    end,
    scrub_pii: lambda do |obj|
      banned = %w[ssN_TaxID ssn taxId ccNum ccType ccToken ccIsValid]
      if obj.is_a?(Hash)
        obj.reject { |k, _| banned.any? { |b| b.casecmp?(k.to_s) } }
           .map { |k, v| [k, call('scrub_pii', v)] }.to_h
      elsif obj.is_a?(Array)
        obj.map { |v| call('scrub_pii', v) }
      else
        obj
      end
    end,
    sanitize_any: lambda do |connection, obj|
      call('mask_any', connection, call('scrub_pii', obj))
    end,
    sanitize_rows: lambda do |connection, rows|
      call('sanitize_any', connection, rows)
    end,
    safe_body: lambda do |connection, body, limit|
      # Error bodies from the portfolio and billing routes carry client names, emails,
      # addresses and account numbers straight into permanent job history. Scrub and mask
      # them the same way a successful response would be.
      cap = limit || 500
      parsed = begin
        workato.parse_json(body.to_s)
      rescue StandardError
        nil
      end
      next call('sanitize_any', connection, parsed).to_json[0, cap] if parsed.present?
      body.to_s.gsub(/\d{6,}/) { |d| "*#{d[-4, 4]}" }[0, cap]
    end
  },
  object_definitions: {
    # Single source of truth for the row shapes that more than one action returns. These were
    # declared inline per action and had already drifted - the plain Clients list was missing
    # homePhone and isDataSharingEntity, and the Simple account search was missing everything
    # the Grid view returns. Orion passes extra fields through and returns absent ones blank,
    # so a union is safe.
    client_row: {
      fields: lambda do |_connection, _config_fields|
        [
          { name: 'id', type: :integer },
          { name: 'name', type: :string,
            hint: 'May be joint, duplicated, or surname only. Do not match on this alone.' },
          { name: 'firstName', type: :string,
            hint: 'Joint clients contain both names joined with "&".' },
          { name: 'lastName', type: :string },
          { name: 'email', type: :string },
          { name: 'homePhone', type: :string },
          { name: 'isActive', type: :boolean },
          { name: 'isDataSharingEntity', type: :boolean },
          { name: 'aum', type: :number },
          { name: 'representativeId', type: :integer },
          { name: 'representativeName', type: :string }
        ]
      end
    },
    account_row: {
      fields: lambda do |_connection, _config_fields|
        [
          { name: 'id', type: :integer },
          { name: 'number', type: :string,
            hint: 'Masked to last 4 unless masking is disabled on the connection.' },
          { name: 'name', type: :string },
          { name: 'lastName', type: :string },
          { name: 'isActive', type: :boolean },
          { name: 'isManaged', type: :boolean },
          { name: 'isDiscretionary', type: :boolean },
          { name: 'currentValue', type: :number },
          { name: 'cashBalance', type: :number,
            hint: '0 on every staging record. Not a Cash in Brokerage source.' },
          { name: 'accountType', type: :string,
            hint: '"Invalid Type" appears - surface as a data quality flag.' },
          { name: 'accountStatus', type: :string },
          { name: 'accountStatusDescription', type: :string },
          { name: 'custodian', type: :string },
          { name: 'fundFamily', type: :string },
          { name: 'household', type: :string,
            hint: 'Populated. No DOBs - cross reference Wealthbox.' },
          { name: 'representative', type: :string },
          { name: 'representativeId', type: :integer },
          { name: 'representativeNumber', type: :string },
          { name: 'clientId', type: :integer, hint: 'Join key to the client list.' },
          { name: 'registration', type: :string, hint: 'Returned by the Simple search, not by the Grid view.' },
          { name: 'registrationId', type: :integer },
          { name: 'feeSchedule', type: :string, hint: 'Uniform across staging. Not a Fee source.' },
          { name: 'billFrequency', type: :string },
          { name: 'masterPayoutSchedule', type: :string }
        ]
      end
    }
  },
  test: lambda do |connection|
    get('/api/v1/Portfolio/Clients/Grid').params('top' => 1)
      .headers(call('orion_headers', '/portfolio/clients'))
  end,
  actions: {
           get_signed_in_user: {
      title: 'Get Signed In User',
      subtitle: 'Live Orion identity, plus optional verified user claims from the recipe',
      description: 'Advisor identity, read from Orion on every call',
      input_fields: lambda do
        [
          { name: 'jwt_claims', type: :string, label: 'JWT claims (diagnostic)', optional: true,
            hint: 'Map the JWT claims datapill here in formula mode - the connector cannot read it otherwise.' },
          { name: 'verified_user_email', type: :string, label: 'Verified user email', optional: true,
            hint: 'RECIPE SIDE ONLY. Formula mode, the JWT claims datapill with ["email"] appended.' },
          { name: 'echo_claims', type: :boolean, label: 'Echo raw JWT claims', default: false,
            hint: 'Diagnostic. Returns the full claim set in jwtClaimsRaw. Leave off in production.' }
        ]
      end,
      execute: lambda do |connection, input|
        path = call('identity_path', connection)
        res = get(path)
          .headers('App' => 'OrionConnect')
          .after_error_response(/.*/) do |code, body, headers, message|
            error("Orion live identity lookup failed (#{code}) at #{path}: #{message}. " \
                  "Body: #{call('safe_body', connection, body, 300)}. " \
                  'This action reads identity from Orion at call time, so a failure here means the ' \
                  'connection resolved for this caller is not usable. ' \
                  "Correlation ID: #{call('orion_correlation_id', headers)}")
          end
        live = call('unwrap_hash', res)
        live_email = (live['email'] || live['emailAddress'] || live['userName'] || live['loginUserId']).to_s.downcase
        live_rep   = live['repId'] || live['representativeId']
        found = live_email.present?

        claims_raw = input['jwt_claims'].to_s
        verified   = input['verified_user_email'].to_s.strip.downcase
        parsed = if claims_raw.present?
                   begin
                     workato.parse_json(claims_raw)
                   rescue StandardError
                     nil
                   end
                 end
        if verified.blank? && parsed.is_a?(Hash)
          verified = (parsed['email'] || parsed['upn'] || parsed['preferred_username']).to_s.strip.downcase
        end

        {
          'email' => found ? live_email : 'not_found',
          'userId' => live['id'] || live['userId'],
          'rep_id' => live_rep,
          'repIdSource' => live_rep.present? ? 'orion_identity_endpoint_live' : 'null_use_entitlement_table',
          'identityMatchesConnection' =>
            (found && connection['user_email'].present?) ? (live_email == connection['user_email'].to_s.downcase) : nil,
          'identitySource' => found ? 'live' : 'not_found',
          'verifiedUserEmail' => verified.presence || 'not_supplied',
          'jwtClaimsRaw' => call('to_bool', input['echo_claims'], false) ?
            (claims_raw.presence || 'not_supplied') : 'not_echoed',
          'jwtClaimsParsed' => claims_raw.present? ? parsed.is_a?(Hash) : nil,
          'verifiedMatchesOrion' => (verified.present? && found) ? (verified == live_email) : nil
        }
      end,
      output_fields: lambda do
        [
          { name: 'email', type: :string,
            hint: 'Lowercased, read LIVE from Orion on every call. Reads "not_found" when Orion returned ' \
                  'no email. Never falls back to a stored value.' },
          { name: 'userId', type: :integer, hint: 'Live from Orion. Null if Orion did not return one.' },
          { name: 'rep_id', type: :integer,
            hint: 'Live from Orion, OFTEN NULL. Does not fall back to the connection. The entitlement ' \
                  'table is the authority - never feed this straight into a scoping filter.' },
          { name: 'repIdSource', type: :string,
            hint: 'Reads null_use_entitlement_table when Orion gave no rep id.' },
          { name: 'identityMatchesConnection', type: :boolean,
            hint: 'Live Orion identity vs the value stored at authorization. Diagnostic only.' },
          { name: 'identitySource', type: :string, hint: '"live" or "not_found".' },
          { name: 'verifiedUserEmail', type: :string,
            hint: 'The Workato verified user from the JWT claims. Trustworthy when populated - platform resolved, not caller supplied.' },
          { name: 'jwtClaimsRaw', type: :string,
            hint: 'Reads "not_echoed" unless Echo raw JWT claims is switched on. Diagnostic only - ' \
                  'the claim set is identity data.' },
          { name: 'jwtClaimsParsed', type: :boolean,
            hint: 'FALSE means claims were mapped but did not parse, so a blank verifiedUserEmail is a mapping bug, not a missing input.' },
          { name: 'verifiedMatchesOrion', type: :boolean,
            hint: 'TRUE means the Workato verified user and the Orion connection are the same person. ' \
                  'FALSE is the ria1 vs ria2 split you have been seeing. Null when either is blank.' }
        ]
      end
    },
    list_clients: {
      title: 'List Clients',
      subtitle: 'Portfolio Clients endpoint, no Grid suffix',
      description: 'Clients from the plain route. Use the Grid view if this 404s',
      input_fields: lambda do
        [
          { name: 'representativeId', type: :integer, label: 'Representative ID', optional: true,
            hint: 'Omit to return the tenant. Supply it to scope to one rep.' },
          { name: 'clientId', type: :integer, label: 'Client ID', optional: true },
          { name: 'isActive', type: :boolean, label: 'Is Active Only', default: true },
          { name: 'top', type: :integer, label: 'Top / Record Limit', default: 200 },
          { name: 'skip', type: :integer, label: 'Skip (paging offset)', optional: true,
            hint: 'Unconfirmed on this endpoint. If Orion ignores it you get the same page back - check pageFirstId changed before looping.' },
          { name: 'diagnostic', type: :boolean, label: 'Diagnostic mode', default: false, hint: 'Returns the raw response instead of the mapped output.' }
        ]
      end,
      execute: lambda do |connection, input|
        limit  = input['top'].nil? ? 200 : input['top'].to_i
        scoped = input['representativeId'].present? || input['clientId'].present?
        call('guard_scope', connection, scoped, 'List Clients')
        params = {
          'representativeId' => input['representativeId'],
          'clientId' => input['clientId'],
          'isActive' => input['isActive'].nil? ? 'true' : input['isActive'].to_s,
          'top' => limit,
          'skip' => input['skip']
        }.reject { |_, v| v.nil? }
        res = get('/api/v1/Portfolio/Clients')
          .params(params)
          .headers(call('orion_headers', '/portfolio/clients'))
          .after_error_response(/.*/) do |code, body, headers, message|
            hint = if code == 404 && body.to_s.include?('<html')
                     'Styled HTML 404 = route not registered on this host. Use List Clients (Grid View).'
                   elsif code == 404
                     'JSON 404 = route exists but returned no resource.'
                   else
                     'Route exists. Auth or parameter problem, not routing.'
                   end
            error("Orion Clients Error (#{code}): #{message}. #{hint} " \
                  "Body: #{call('safe_body', connection, body, 500)}. " \
                  "Correlation ID: #{call('orion_correlation_id', headers)}")
          end
        if call('to_bool', input['diagnostic'], false)
          detected = res.is_a?(Array) ? 'array' : (res.is_a?(Hash) ? 'hash' : 'scalar')
          next {
            'raw' => { 'response' => call('sanitize_any', connection, res) },
            'detectedType' => detected,
            'advisorEmail' => connection['user_email']
          }
        end
        clients = call('sanitize_rows', connection, call('unwrap_array', res))
        {
          'clients' => clients,
          'clientCount' => clients.length,
          'advisorEmail' => connection['user_email'],
          'repScoped' => scoped,
          'truncated' => clients.length >= limit,
          'pagingUnverified' => input['skip'].to_i.positive?,
          'pageFirstId' => clients.first.is_a?(Hash) ? clients.first['id'] : nil,
          'pageLastId' => clients.last.is_a?(Hash) ? clients.last['id'] : nil
        }
      end,
      output_fields: lambda do |object_definitions|
        [
          { name: 'clients', type: :array, of: :object, properties: object_definitions['client_row'] },
          { name: 'clientCount', type: :integer },
          { name: 'advisorEmail', type: :string },
          { name: 'repScoped', type: :boolean,
            hint: 'FALSE means no Representative ID or Client ID was supplied, so this is the whole tenant. Assert on it, or switch on "Refuse tenant wide results".' },
          { name: 'truncated', type: :boolean,
            hint: 'TRUE means the result hit the record limit and more rows exist that you did not ' \
                  'receive. Never summarize or count a truncated set for an advisor.' },
          { name: 'pagingUnverified', type: :boolean,
            hint: 'TRUE whenever Skip was set. Confirm pageFirstId changed before trusting a Skip loop.' },
          { name: 'pageFirstId', type: :integer, hint: 'First row id in this page. Use it to prove Skip moved.' },
          { name: 'pageLastId', type: :integer, hint: 'Last row id in this page.' },
          { name: 'raw', type: :object, hint: 'Diagnostic mode only. Masked and scrubbed like any other output.' },
          { name: 'detectedType', type: :string, hint: 'Diagnostic mode only.' }
        ]
      end
    },
    list_clients_grid: {
      title: 'List Clients (Grid View)',
      subtitle: 'The reliable client list',
      description: 'Client list. The reliable one - start here',
      input_fields: lambda do
        [
          { name: 'householdFilter', type: :string, label: 'Household Filter', optional: true, hint: 'Silent no-op server side. Filter the returned array instead.' },
          { name: 'rep_id', type: :integer, label: 'Representative ID', optional: true,
            hint: 'Works. Value 0 returns empty. OMITTING IT RETURNS THE WHOLE TENANT - ' \
                  'feed this from the entitlement table, never from a field that can be null.' },
          { name: 'accountId', type: :integer, label: 'Account ID', optional: true },
          { name: 'registrationId', type: :integer, label: 'Registration ID', optional: true },
          { name: 'isActive', type: :boolean, label: 'Is Active Only', default: true },
          { name: 'refreshCache', type: :boolean, label: 'Refresh Cache', default: false },
          { name: 'top', type: :integer, label: 'Top / Record Limit', default: 200, hint: 'Tenant holds roughly 56,000 households. Raise deliberately.' },
          { name: 'skip', type: :integer, label: 'Skip (paging offset)', optional: true,
            hint: 'Unconfirmed on this endpoint. If Orion ignores it you get the same page back - check pageFirstId changed before looping.' }
        ]
      end,
      execute: lambda do |connection, input|
        limit  = input['top'].nil? ? 200 : input['top'].to_i
        scoped = input['rep_id'].present? || input['accountId'].present? ||
                 input['registrationId'].present?
        call('guard_scope', connection, scoped, 'List Clients (Grid View)')
        params = {
          'householdFilter' => input['householdFilter'].presence,
          'representativeId' => input['rep_id'],
          'accountId' => input['accountId'],
          'registrationId' => input['registrationId'],
          'isActive' => input['isActive'].nil? ? 'true' : input['isActive'].to_s,
          'refreshCache' => input['refreshCache'].nil? ? 'false' : input['refreshCache'].to_s,
          'top' => limit,
          'skip' => input['skip']
        }.reject { |_, v| v.nil? }
        res = get('/api/v1/Portfolio/Clients/Grid')
          .params(params)
          .headers(call('orion_headers', '/portfolio/clients'))
          .after_error_response(/.*/) do |code, _body, headers, message|
            error("Orion Clients Grid Error (#{code}): #{message}. Correlation ID: #{call('orion_correlation_id', headers)}")
          end
        clients = call('sanitize_rows', connection, call('unwrap_array', res))
        reps = clients.map { |c| c['representativeId'] }.compact.uniq
        {
          'clients' => clients,
          'clientCount' => clients.length,
          'advisorEmail' => connection['user_email'],
          'repScoped' => scoped,
          'distinctRepIds' => reps.join(','),
          'truncated' => clients.length >= limit,
          'pagingUnverified' => input['skip'].to_i.positive?,
          'pageFirstId' => clients.first.is_a?(Hash) ? clients.first['id'] : nil,
          'pageLastId' => clients.last.is_a?(Hash) ? clients.last['id'] : nil
        }
      end,
      output_fields: lambda do |object_definitions|
        [
          { name: 'clients', type: :array, of: :object, properties: object_definitions['client_row'] },
          { name: 'clientCount', type: :integer },
          { name: 'advisorEmail', type: :string },
          { name: 'repScoped', type: :boolean,
            hint: 'FALSE means tenant wide. Stop the recipe rather than showing cross rep data, ' \
                  'or switch on "Refuse tenant wide results" on the connection.' },
          { name: 'distinctRepIds', type: :string,
            hint: 'Cheap assertion: if this holds more than the one rep you scoped to, scoping did not take effect.' },
          { name: 'truncated', type: :boolean,
            hint: 'TRUE means the result hit the record limit and more rows exist that you did not ' \
                  'receive. Never summarize or count a truncated set for an advisor.' },
          { name: 'pagingUnverified', type: :boolean,
            hint: 'TRUE whenever Skip was set. Confirm pageFirstId changed before trusting a Skip loop.' },
          { name: 'pageFirstId', type: :integer, hint: 'First row id in this page. Use it to prove Skip moved.' },
          { name: 'pageLastId', type: :integer, hint: 'Last row id in this page.' }
        ]
      end
    },
    list_accounts_grid: {
      title: 'List Accounts (Grid View)',
      subtitle: 'Account list with household and client join keys',
      description: 'Accounts with client and household join keys',
      input_fields: lambda do
        [
          { name: 'accountFilter', type: :string, label: 'Account Filter', optional: true, hint: 'Silent no-op server side. Filter the returned array instead.' },
          { name: 'representativeId', type: :integer, label: 'Representative ID', optional: true },
          { name: 'clientId', type: :integer, label: 'Client ID', optional: true },
          { name: 'registrationId', type: :integer, label: 'Registration ID', optional: true },
          { name: 'isActive', type: :boolean, label: 'Is Active Only', default: true },
          { name: 'refreshCache', type: :boolean, label: 'Refresh Cache', default: false },
          { name: 'returnStyle', type: :string, label: 'Return Style', default: 'Standard' },
          { name: 'top', type: :integer, label: 'Top / Record Limit', default: 50 },
          { name: 'skip', type: :integer, label: 'Skip (paging offset)', optional: true,
            hint: 'Unconfirmed on this endpoint. If Orion ignores it you get the same page back - check pageFirstId changed before looping.' }
        ]
      end,
      execute: lambda do |connection, input|
        limit  = input['top'].nil? ? 50 : input['top'].to_i
        scoped = input['representativeId'].present? || input['clientId'].present? ||
                 input['registrationId'].present?
        call('guard_scope', connection, scoped, 'List Accounts (Grid View)')
        params = {
          'accountFilter' => input['accountFilter'].presence,
          'representativeId' => input['representativeId'],
          'clientId' => input['clientId'],
          'registrationId' => input['registrationId'],
          'isActive' => input['isActive'].nil? ? 'true' : input['isActive'].to_s,
          'refreshCache' => input['refreshCache'].nil? ? 'false' : input['refreshCache'].to_s,
          'returnStyle' => input['returnStyle'].presence || 'Standard',
          'top' => limit,
          'skip' => input['skip']
        }.reject { |_, v| v.nil? }
        res = get('/api/v1/Portfolio/Accounts/Grid')
          .params(params)
          .headers(call('orion_headers', '/portfolio/accounts'))
          .after_error_response(/.*/) do |code, _body, headers, message|
            error("Orion Accounts Grid Error (#{code}): #{message}. Correlation ID: #{call('orion_correlation_id', headers)}")
          end
        raw = call('unwrap_array', res).select { |a| a.is_a?(Hash) }
        total = raw.inject(0.0) { |sum, a| sum + (a['currentValue'] || 0).to_f }
        accounts = call('sanitize_rows', connection, raw)
        {
          'accounts' => accounts,
          'accountCount' => accounts.length,
          'totalValue' => total.round(2),
          'repScoped' => scoped,
          'truncated' => accounts.length >= limit,
          'pagingUnverified' => input['skip'].to_i.positive?,
          'pageFirstId' => accounts.first.is_a?(Hash) ? accounts.first['id'] : nil,
          'pageLastId' => accounts.last.is_a?(Hash) ? accounts.last['id'] : nil
        }
      end,
      output_fields: lambda do |object_definitions|
        [
          { name: 'accounts', type: :array, of: :object, properties: object_definitions['account_row'] },
          { name: 'accountCount', type: :integer, hint: 'Fills "N TOTAL ACCTS" when called with a clientId.' },
          { name: 'totalValue', type: :number,
            hint: 'Sum of currentValue across the rows returned. If truncated is TRUE this is a ' \
                  'partial sum, not the account total.' },
          { name: 'repScoped', type: :boolean,
            hint: 'FALSE means tenant wide. Switch on "Refuse tenant wide results" on the connection ' \
                  'to make that raise instead of returning data.' },
          { name: 'truncated', type: :boolean,
            hint: 'TRUE means the result hit the record limit and more rows exist that you did not ' \
                  'receive. totalValue and accountCount are both understated when this is TRUE.' },
          { name: 'pagingUnverified', type: :boolean,
            hint: 'TRUE whenever Skip was set. Confirm pageFirstId changed before trusting a Skip loop.' },
          { name: 'pageFirstId', type: :integer, hint: 'First row id in this page. Use it to prove Skip moved.' },
          { name: 'pageLastId', type: :integer, hint: 'Last row id in this page.' }
        ]
      end
    },
    get_client_registrations: {
      title: 'Get Client Registrations',
      subtitle: 'Registration id, name, and active status',
      description: 'Registrations for one client',
      input_fields: lambda do
        [
          { name: 'clientId', type: :integer, label: 'Client ID', optional: false }
        ]
      end,
      execute: lambda do |connection, input|
        res = get("/api/v1/Portfolio/Clients/#{input['clientId'].to_i}/Registrations/Simple")
          .headers(call('orion_headers', '/portfolio/registrations'))
          .after_error_response(/.*/) do |code, _body, headers, message|
            error("Orion Client Registrations Error (#{code}): #{message}. Correlation ID: #{call('orion_correlation_id', headers)}")
          end
        regs = call('sanitize_rows', connection, call('unwrap_array', res))
        {
          'registrations' => regs,
          'totalRegistrationCount' => regs.length
        }
      end,
      output_fields: lambda do
        [
          {
            name: 'registrations',
            type: :array,
            of: :object,
            properties: [
              { name: 'id', type: :integer },
              { name: 'name', type: :string, hint: 'Joint registrations contain both owner names.' },
              { name: 'clientId', type: :integer, hint: 'Observed as 0. Use the queried clientId instead.' },
              { name: 'isActive', type: :boolean }
            ]
          },
          { name: 'totalRegistrationCount', type: :integer }
        ]
      end
    },
    list_portfolio_assets: {
      title: 'List Portfolio Assets',
      subtitle: 'Asset holdings for cash classification',
      description: 'Holdings for a set of account IDs',
      input_fields: lambda do
        [
          { name: 'includeCostBasis', type: :boolean, label: 'Include Cost Basis', default: false },
          { name: 'ids', type: :string, label: 'Account IDs', default: '0', hint: 'Comma separated, e.g. 123, 456' }
        ]
      end,
      execute: lambda do |connection, input|
        raw_ids = call('parse_id_list', input['ids']).map(&:to_i)
        id_array = raw_ids.empty? ? [0] : raw_ids
        res = post('/api/v1/Portfolio/Assets/List')
          .params('includeCostBasis' => input['includeCostBasis'].nil? ? 'false' : input['includeCostBasis'].to_s)
          .request_body(id_array.to_json)
          .headers(call('orion_headers', '/portfolio/assets'))
          .after_error_response(/.*/) do |code, _body, headers, message|
            error("Orion Portfolio Assets Error (#{code}): #{message}. Correlation ID: #{call('orion_correlation_id', headers)}")
          end
        { 'assets' => call('sanitize_rows', connection, call('unwrap_array', res)) }
      end,
      output_fields: lambda do
        [
          {
            name: 'assets',
            type: :array,
            of: :object,
            properties: [
              { name: 'id', type: :integer },
              { name: 'accountId', type: :integer },
              { name: 'accountNumber', type: :string, hint: 'Masked to last 4.' },
              { name: 'ticker', type: :string },
              { name: 'name', type: :string },
              { name: 'currentShares', type: :number },
              { name: 'currentValue', type: :number },
              { name: 'currentPrice', type: :number },
              { name: 'costBasis', type: :number },
              { name: 'assetClass', type: :string, hint: 'Candidate field for cash classification.' },
              { name: 'custodian', type: :string },
              { name: 'householdName', type: :string },
              { name: 'isActive', type: :boolean }
            ]
          }
        ]
      end
    },
    get_household_portfolio_cards: {
      title: 'Get Household Portfolio Cards',
      subtitle: 'Relationship cards and performance',
      description: 'Household performance cards. Response shape unverified',
      input_fields: lambda do
        [
          { name: 'householdId', type: :integer, label: 'Household ID', optional: false },
          { name: 'startDate', type: :date, label: 'Start Date', optional: true },
          { name: 'endDate', type: :date, label: 'End Date', optional: true }
        ]
      end,
      execute: lambda do |connection, input|
        payload = {
          'householdId' => input['householdId'].to_i,
          'startDate' => input['startDate'].presence && input['startDate'].to_date.strftime('%m/%d/%Y'),
          'endDate' => input['endDate'].presence && input['endDate'].to_date.strftime('%m/%d/%Y')
        }.reject { |_, v| v.nil? }
        res = post('/api/v1/Reporting/Performance/HouseholdCards')
          .payload(payload)
          .headers(call('orion_headers', '/portfolio/reporting'))
          .after_error_response(/.*/) do |code, _body, headers, message|
            error("Orion Portfolio Cards Error (#{code}): #{message}. Correlation ID: #{call('orion_correlation_id', headers)}")
          end
        call('scrub_pii', call('unwrap_hash', res))
      end,
      output_fields: lambda do
        [
          { name: 'householdId', type: :integer },
          { name: 'householdName', type: :string },
          { name: 'totalMarketValue', type: :number },
          { name: 'ytdReturn', type: :number },
          { name: 'oneYearReturn', type: :number },
          {
            name: 'cards',
            type: :array,
            of: :object,
            properties: [
              { name: 'cardType', type: :string },
              { name: 'title', type: :string },
              { name: 'value', type: :string },
              { name: 'status', type: :string }
            ]
          }
        ]
      end
    },
    get_performance_allocation_summary: {
      title: 'Get Performance & Allocation Summary',
      subtitle: 'Composite metrics for At Risk scoring and Outreach',
      description: 'Household performance and allocation. Response shape unverified',
      input_fields: lambda do
        [
          { name: 'householdId', type: :integer, label: 'Household ID', optional: false },
          { name: 'startDate', type: :date, label: 'Start Date', optional: true },
          { name: 'endDate', type: :date, label: 'End Date', optional: true }
        ]
      end,
      execute: lambda do |connection, input|
        payload = {
          'householdId' => input['householdId'].to_i,
          'startDate' => input['startDate'].presence && input['startDate'].to_date.strftime('%m/%d/%Y'),
          'endDate' => input['endDate'].presence && input['endDate'].to_date.strftime('%m/%d/%Y')
        }.reject { |_, v| v.nil? }
        res = post('/api/v1/Reporting/Summary/Composite')
          .payload(payload)
          .headers(call('orion_headers', '/portfolio/reporting'))
          .after_error_response(/.*/) do |code, _body, headers, message|
            error("Orion Reporting Summary Error (#{code}): #{message}. Correlation ID: #{call('orion_correlation_id', headers)}")
          end
        call('scrub_pii', call('unwrap_hash', res))
      end,
      output_fields: lambda do
        [
          { name: 'householdId', type: :integer },
          { name: 'beginningValue', type: :number },
          { name: 'endingValue', type: :number },
          { name: 'netContributions', type: :number },
          { name: 'totalReturn', type: :number },
          {
            name: 'allocations',
            type: :array,
            of: :object,
            properties: [
              { name: 'category', type: :string },
              { name: 'targetPercent', type: :number },
              { name: 'actualPercent', type: :number }
            ]
          }
        ]
      end
    },
    get_benchmark_risk_profile: {
      title: 'Get Benchmark & Risk Profile',
      subtitle: 'Risk score, stress test, benchmark comparison',
      description: 'Household risk and benchmark figures. Response shape unverified',
      input_fields: lambda do
        [
          { name: 'householdId', type: :integer, label: 'Household ID', optional: false }
        ]
      end,
      execute: lambda do |connection, input|
        res = get("/api/v1/Risk/Household/#{input['householdId'].to_i}/Profile")
          .headers(call('orion_headers', '/portfolio/risk'))
          .after_error_response(/.*/) do |code, _body, headers, message|
            error("Orion Risk Profile Error (#{code}): #{message}. Correlation ID: #{call('orion_correlation_id', headers)}")
          end
        call('scrub_pii', call('unwrap_hash', res))
      end,
      output_fields: lambda do
        [
          { name: 'householdId', type: :integer },
          { name: 'riskScore', type: :integer },
          { name: 'targetRiskScore', type: :integer },
          { name: 'stressTestScenario', type: :string },
          { name: 'estimatedDrawdown', type: :number },
          { name: 'primaryBenchmarkName', type: :string },
          { name: 'benchmarkReturnYTD', type: :number }
        ]
      end
    },
    get_client_detail: {
      title: 'Get Client Detail',
      subtitle: 'Single client record, standard or verbose',
      description: 'One client record. Verbose adds portfolio and household members',
      input_fields: lambda do
        [
          { name: 'clientId', type: :integer, label: 'Client ID', optional: false },
          { name: 'verbose', type: :boolean, label: 'Verbose', default: false,
            hint: 'Calls Clients/Verbose/{key}. Verbose precedes the key, it is not a suffix.' },
          { name: 'expand', type: :string, label: 'Expand sections', optional: true,
            hint: 'Verbose only. Comma separated, e.g. Portfolio,HouseholdMembers. Sections not listed return null. Requesting any section turns off the ones you did not ask for.' }
        ]
      end,
      execute: lambda do |connection, input|
        verbose = call('to_bool', input['verbose'], false)
        path = if verbose
                 "/api/v1/Portfolio/Clients/Verbose/#{input['clientId'].to_i}"
               else
                 "/api/v1/Portfolio/Clients/#{input['clientId'].to_i}"
               end
        params = {}
        if verbose && input['expand'].present?
          params['expand'] = input['expand'].to_s.gsub(' ', '')
        end
        res = get(path)
          .params(params)
          .headers(call('orion_headers', '/portfolio/clients'))
          .after_error_response(/.*/) do |code, body, headers, message|
            if code == 404 && !body.to_s.include?('<html')
              error("Orion Client Detail: client #{input['clientId']} not found or not accessible. " \
                    "Correlation ID: #{call('orion_correlation_id', headers)}")
            else
              error("Orion Client Detail Error (#{code}) at #{path}: #{message}. " \
                    "Body: #{call('safe_body', connection, body, 500)}. " \
                    "Correlation ID: #{call('orion_correlation_id', headers)}")
            end
          end
        call('sanitize_any', connection, call('unwrap_hash', res))
      end,
      output_fields: lambda do
        [
          { name: 'id', type: :integer },
          { name: 'name', type: :string, hint: 'e.g. "Lawrence E Sibal".' },
          { name: 'firstName', type: :string },
          { name: 'lastName', type: :string },
          { name: 'salutation', type: :string },
          { name: 'company', type: :string },
          { name: 'jobTitle', type: :string },
          { name: 'reportName', type: :string },
          { name: 'isActive', type: :boolean },
          { name: 'isDataSharingEntity', type: :boolean },
          { name: 'globalId', type: :string, hint: 'Stable GUID. Safer join key than any name field.' },
          { name: 'personalId', type: :integer },
          { name: 'aum', type: :number },
          { name: 'cashBalance', type: :number },
          { name: 'additionalAccounts', type: :integer },
          { name: 'missingInformation', type: :string, hint: 'e.g. "DOB, Email". Empty string means the record is complete.' },
          { name: 'dob', type: :string, hint: 'Populated on complete records, e.g. "1968-09-23". On joint households this is a single date and cannot be attributed to a specific person.' },
          { name: 'gender', type: :string },
          { name: 'email', type: :string },
          { name: 'webAddress', type: :string },
          { name: 'homePhone', type: :string },
          { name: 'homePhoneExt', type: :string },
          { name: 'mobilePhone', type: :string },
          { name: 'businessPhone', type: :string },
          { name: 'businessPhoneExt', type: :string },
          { name: 'otherPhone', type: :string },
          { name: 'otherPhoneExt', type: :string },
          { name: 'fax', type: :string },
          { name: 'faxExt', type: :string },
          { name: 'pager', type: :string },
          { name: 'pagerExt', type: :string },
          { name: 'address1', type: :string },
          { name: 'address2', type: :string },
          { name: 'address3', type: :string },
          { name: 'city', type: :string },
          { name: 'state', type: :string },
          { name: 'zip', type: :string, hint: 'Unformatted 9 digit in staging, e.g. "693411592".' },
          { name: 'country', type: :string },
          { name: 'representativeId', type: :integer, hint: 'Ownership gate key. Compare to the signed in advisor rep id.' },
          { name: 'representativeName', type: :string },
          { name: 'representativeNumber', type: :string },
          { name: 'brokerDealerName', type: :string },
          { name: 'categoryId', type: :integer },
          { name: 'category', type: :string, hint: 'e.g. "Household".' },
          { name: 'advClientCategoryId', type: :integer },
          { name: 'advClientCategory', type: :string },
          { name: 'statementDeliveryMethodId', type: :integer },
          { name: 'statementDeliveryMethod', type: :string },
          { name: 'videoStatementDeliveryMethod', type: :string },
          { name: 'lastStatementSent', type: :string },
          { name: 'lastStatementSentTo', type: :string },
          { name: 'riskScore', type: :number },
          { name: 'currentRiskScore', type: :number },
          { name: 'targetRiskScore', type: :number },
          { name: 'portfolioRiskScore', type: :number },
          { name: 'riskScoreAsOfDate', type: :string },
          { name: 'riskScoreProvider', type: :string },
          { name: 'probabilityOfSuccess', type: :number },
          { name: 'isRTQLocked', type: :boolean },
          { name: 'startDate', type: :string },
          { name: 'importKey', type: :string },
          { name: 'createdBy', type: :string },
          { name: 'createdDate', type: :string },
          { name: 'editedBy', type: :string },
          { name: 'editedDate', type: :string },
          { name: 'udf5WEALTHBOX', type: :string, hint: 'Intended Wealthbox join key. Null in staging' },
          { name: 'udf5CRMID', type: :string },
          { name: 'udf5EMONEYCLI', type: :string },
          {
            name: 'portfolio',
            type: :object,
            hint: 'Verbose only. Requires expand to include Portfolio. Null otherwise.',
            properties: [
              { name: 'name', type: :string },
              { name: 'firstName', type: :string, hint: 'Joint households carry both names split across firstName and lastName, e.g. "Terry A Montgomery &" and "Rhonda E Montgomery".' },
              { name: 'lastName', type: :string },
              { name: 'salutation', type: :string },
              { name: 'prefix', type: :string },
              { name: 'suffix', type: :string },
              { name: 'dob', type: :string, hint: 'One date per household. On a joint record it cannot be attributed to either named person.' },
              { name: 'gender', type: :string },
              { name: 'email', type: :string },
              { name: 'webAddress', type: :string },
              { name: 'homePhone', type: :string },
              { name: 'homePhoneExt', type: :string },
              { name: 'mobilePhone', type: :string },
              { name: 'businessPhone', type: :string },
              { name: 'businessPhoneExt', type: :string },
              { name: 'workPhone', type: :string },
              { name: 'workPhoneExt', type: :string },
              { name: 'otherPhone', type: :string },
              { name: 'otherPhoneExt', type: :string },
              { name: 'fax', type: :string },
              { name: 'faxExt', type: :string },
              { name: 'pager', type: :string },
              { name: 'pagerExt', type: :string },
              { name: 'address1', type: :string },
              { name: 'address2', type: :string },
              { name: 'address3', type: :string },
              { name: 'city', type: :string },
              { name: 'state', type: :string },
              { name: 'zip', type: :string },
              { name: 'country', type: :string },
              { name: 'isUsResident', type: :boolean },
              { name: 'isQualifiedInvestor', type: :boolean },
              { name: 'isActive', type: :boolean },
              { name: 'representativeId', type: :integer },
              { name: 'categoryId', type: :integer },
              { name: 'advClientCategoryId', type: :integer },
              { name: 'statementDeliveryMethodId', type: :integer },
              { name: 'videoStatementDeliveryMethod', type: :string },
              { name: 'lastStatementSent', type: :string },
              { name: 'lastStatementSentTo', type: :string },
              { name: 'reportName', type: :string },
              { name: 'company', type: :string },
              { name: 'jobTitle', type: :string },
              { name: 'startDate', type: :string },
              { name: 'importKey', type: :string },
              { name: 'createdBy', type: :string },
              { name: 'createdDate', type: :string },
              { name: 'editedBy', type: :string },
              { name: 'editedDate', type: :string }
            ]
          },
          {
            name: 'householdMembers',
            type: :array,
            of: :object,
            hint: 'Verbose only, requires expand=HouseholdMembers. Empty on this tenant - the fields below come from Swagger, not real data.',
            properties: [
              { name: 'id', type: :integer },
              { name: 'type', type: :string, hint: 'Ties to the HouseholdMemberTypes reference list, e.g. Spouse, Child. This is the dependents and children source.' },
              { name: 'globalId', type: :string },
              { name: 'salutation', type: :string },
              { name: 'firstName', type: :string },
              { name: 'lastName', type: :string },
              { name: 'fullName', type: :string },
              { name: 'dob', type: :string, hint: 'Per member birth date, unlike the single household level dob.' },
              { name: 'gender', type: :string },
              { name: 'email', type: :string },
              { name: 'webAddress', type: :string },
              { name: 'homePhone', type: :string },
              { name: 'homePhoneExt', type: :string },
              { name: 'mobilePhone', type: :string },
              { name: 'businessPhone', type: :string },
              { name: 'businessPhoneExt', type: :string },
              { name: 'otherPhone', type: :string },
              { name: 'otherPhoneExt', type: :string },
              { name: 'fax', type: :string },
              { name: 'faxExt', type: :string },
              { name: 'pager', type: :string },
              { name: 'pagerExt', type: :string }
            ]
          }
        ]
      end
    },
    search_accounts_simple: {
      title: 'Search Accounts (Simple)',
      subtitle: 'Account inventory by search term',
      description: 'Find accounts by name, number, or client ID',
      input_fields: lambda do
        [
          { name: 'search', type: :string, label: 'Search term', optional: false,
            hint: 'Client id, account number, or name fragment.' },
          { name: 'clientId', type: :integer, label: 'Filter to Client ID', optional: true,
            hint: 'Applied after the response returns.' },
          { name: 'maskAccountNumbers', type: :boolean, label: 'Mask account numbers', default: true,
            hint: 'Leaves only the last 4. The connection level setting also applies.' }
        ]
      end,
      execute: lambda do |connection, input|
        term = input['search'].to_s.strip
        error('Search term cannot be blank.') if term.blank?
        # This value is interpolated into the request PATH. Escaping only spaces lets a term
        # containing / ? # or % rewrite the route being called.
        if term.match?(%r{[/?\#%]})
          error("Search term contains a character that would rewrite the request path: #{term}. " \
                'Remove / ? # and % and retry.')
        end
        term = term.gsub(' ', '%20')
        res = get("/api/v1/Portfolio/Accounts/Simple/Search/#{term}")
          .headers(call('orion_headers', '/portfolio/accounts'))
          .after_error_response(/.*/) do |code, body, headers, message|
            hint = if code == 404 && body.to_s.include?('<html')
                     'Styled HTML 404 = route not registered. Fall back to List Accounts (Grid View).'
                   else
                     ''
                   end
            error("Orion Account Search Error (#{code}): #{message}. #{hint} " \
                  "Correlation ID: #{call('orion_correlation_id', headers)}")
          end
        accounts = call('unwrap_array', res).select { |a| a.is_a?(Hash) }
        if input['clientId'].present?
          target = input['clientId'].to_s.strip
          accounts = accounts.select { |a| a['clientId'].to_s.strip == target }
        end
        id_list = accounts.map { |a| a['id'] }.compact.join(',')
        # Either switch asks for masking, masking happens. Only turning BOTH off returns
        # account numbers in full.
        mask = call('to_bool', input['maskAccountNumbers'], true) ||
               call('to_bool', connection['mask_account_numbers'], true)
        accounts = call('sanitize_any', connection.merge('mask_account_numbers' => mask), accounts)
        {
          'accounts' => accounts,
          'accountCount' => accounts.length,
          'accountIdList' => id_list
        }
      end,
      output_fields: lambda do |object_definitions|
        [
          { name: 'accounts', type: :array, of: :object, properties: object_definitions['account_row'] },
          { name: 'accountCount', type: :integer, hint: 'Fills the "N TOTAL ACCTS" template line.' },
          { name: 'accountIdList', type: :string, hint: 'Comma separated, UNMASKED ids. Feed into the rep level actions.' }
        ]
      end
    },
    get_account_value: {
      title: 'Get Account Value',
      subtitle: 'Current or as of date account value',
      description: 'Market value for one account, current or as of a date',
      input_fields: lambda do
        [
          { name: 'accountId', type: :integer, label: 'Account ID', optional: false },
          { name: 'asOfDate', type: :date, label: 'As Of Date', optional: true, hint: 'Omit for current value.' }
        ]
      end,
      execute: lambda do |connection, input|
        path = "/api/v1/Portfolio/Accounts/#{input['accountId'].to_i}/Value"
        path = path + "/#{input['asOfDate'].to_date.strftime('%Y-%m-%d')}" if input['asOfDate'].present?
        res = get(path)
          .headers(call('orion_headers', '/portfolio/accounts'))
          .after_error_response(/.*/) do |code, _body, headers, message|
            error("Orion Account Value Error (#{code}): #{message}. " \
                  "Correlation ID: #{call('orion_correlation_id', headers)}")
          end
        body = call('unwrap_hash', res)
        out =
          if body.present?
            body.merge('accountId' => input['accountId'].to_i)
          else
            scalar = call('unwrap_array', res).first
            { 'accountId' => input['accountId'].to_i, 'value' => scalar.to_f }
          end
        echoed = out['id']
        if echoed.present? && echoed.to_s.strip != input['accountId'].to_s.strip
          error("Orion Account Value mismatch: asked for account #{input['accountId']}, " \
                "Orion returned account #{echoed}. Refusing to return a value for a different account. " \
                'Check that the account id came from Orion (Search Accounts / List Accounts) and is not ' \
                'a custodian account number or a client id.')
        end
        call('mask_rows', connection, [call('scrub_pii', out)]).first
      end,
      output_fields: lambda do
        [
          { name: 'accountId', type: :integer },
          { name: 'id', type: :integer, hint: 'Orion account id. Asserted to equal accountId - a mismatch raises.' },
          { name: 'value', type: :number },
          { name: 'number', type: :string, hint: 'Masked to last 4.' },
          { name: 'name', type: :string, hint: 'Registration name, leading whitespace in staging.' },
          { name: 'custodian', type: :string },
          { name: 'clientId', type: :integer, hint: 'Join key back to the client.' },
          { name: 'registrationId', type: :integer },
          { name: 'isActive', type: :boolean },
          { name: 'managementStyle', type: :string, hint: '"Invalid" appears in staging, surface as a data quality flag.' }
        ]
      end
    },
    get_account_asset_values: {
      title: 'Get Account Asset Values',
      subtitle: 'Holdings with cash rollup',
      description: 'Holdings for one account, with a cash subtotal',
      input_fields: lambda do
        [
          { name: 'accountId', type: :integer, label: 'Account ID', optional: false },
          { name: 'hasValue', type: :boolean, label: 'Only assets that have value', optional: true,
            hint: 'Documented query param. TRUE returns only positions with a value, FALSE only those ' \
                  'without. Leave blank for everything.' },
          { name: 'asOfDate', type: :date, label: 'As Of Date', optional: true,
            hint: 'NOT IN THE PUBLISHED CONTRACT. Swagger documents this route as /Assets/Value with no ' \
                  'date segment, so a date is likely to 404 or be ignored. Verify before trusting a ' \
                  'historical figure - check pathCalled in the output.' },
          { name: 'cashKeywords', type: :string, label: 'Cash match keywords', default: 'cash,money market,sweep,mmkt',
            hint: 'Comma separated, matched case insensitively against the asset class and name fields. ' \
                  'isCustodialCash is checked first and wins outright when present.' }
        ]
      end,
      execute: lambda do |connection, input|
        path = "/api/v1/Portfolio/Accounts/#{input['accountId'].to_i}/Assets/Value"
        path = path + "/#{input['asOfDate'].to_date.strftime('%Y-%m-%d')}" if input['asOfDate'].present?
        params = {}
        params['hasValue'] = input['hasValue'].to_s unless input['hasValue'].nil?
        res = get(path)
          .params(params)
          .headers(call('orion_headers', '/portfolio/accounts'))
          .after_error_response(/.*/) do |code, _body, headers, message|
            error("Orion Account Assets Value Error (#{code}): #{message}. " \
                  "Correlation ID: #{call('orion_correlation_id', headers)}")
          end
        assets = call('unwrap_array', res).select { |a| a.is_a?(Hash) }
        assets = assets.map { |a| a.merge('currentValue' => (a['currentValue'] || a['value']).to_f) }
        keywords = call('parse_id_list', input['cashKeywords']).map(&:downcase)
        keywords = ['cash', 'money market', 'sweep', 'mmkt'] if keywords.blank?
        cash_assets = assets.select do |a|
          next true if a['isCustodialCash'] == true
          haystack = [a['assetClass'], a['productCategory'], a['assetClassName'], a['name']]
                     .compact.join(' ').downcase
          keywords.any? { |k| haystack.include?(k) }
        end
        total = assets.inject(0.0) { |sum, a| sum + (a['currentValue'] || a['value'] || 0).to_f }
        cash  = cash_assets.inject(0.0) { |sum, a| sum + (a['currentValue'] || a['value'] || 0).to_f }
        # Staging returns positions with shares/price/value all zero. Without this flag a
        # recipe cannot tell "this account holds no cash" from "this tenant carries no
        # valuations", and both render as $0.00 to an advisor.
        valued = assets.any? { |a| (a['currentValue'] || a['value'] || 0).to_f != 0 }
        {
          'accountId' => input['accountId'].to_i,
          'pathCalled' => path,
          'assets' => call('sanitize_rows', connection, assets),
          'assetCount' => assets.length,
          'valuesPopulated' => valued,
          'totalValue' => total.round(2),
          'cashValue' => cash.round(2),
          'cashPercent' => valued ? ((cash / total) * 100).round(2) : nil,
          'cashAssetCount' => cash_assets.length,
          'cashClassificationFields' => 'isCustodialCash (authoritative), then assetClass, productCategory, assetClassName, name',
          'costBasisPopulated' => assets.any? { |a| a.key?('costBasis') } ?
            assets.any? { |a| (a['costBasis'] || 0).to_f > 0 } : nil
        }
      end,
      output_fields: lambda do
        [
          { name: 'accountId', type: :integer },
          {
            name: 'assets',
            type: :array,
            of: :object,
            properties: [
              { name: 'id', type: :integer },
              { name: 'productId', type: :integer },
              { name: 'ticker', type: :string, hint: 'e.g. "CASH:CASH".' },
              { name: 'name', type: :string, hint: 'e.g. "Cash Asset".' },
              { name: 'assetClass', type: :string, hint: 'e.g. "SW MM Funds Taxable". Note this does not contain the word cash even on cash positions.' },
              { name: 'accountNumber', type: :string, hint: 'Empty string on this tenant. Masked when present.' },
              { name: 'isCustodialCash', type: :boolean, hint: 'Authoritative cash signal, checked before keyword matching.' },
              { name: 'isTradeExcluded', type: :boolean },
              { name: 'shares', type: :number, hint: 'The declared currentShares does not exist.' },
              { name: 'price', type: :number, hint: 'The declared currentPrice does not exist.' },
              { name: 'value', type: :number, hint: 'Per position dollar amount.' },
              { name: 'currentValue', type: :number, hint: 'Added by the connector, normalized from value.' }
            ]
          },
          { name: 'pathCalled', type: :string,
            hint: 'The URL actually requested. Check this when using As Of Date - a date segment is not ' \
                  'in the published contract for this route.' },
          { name: 'assetCount', type: :integer },
          { name: 'valuesPopulated', type: :boolean,
            hint: 'FALSE means every position came back with value 0, so totalValue, cashValue and ' \
                  'cashPercent are all meaningless. Do not report $0 or 0% cash to an advisor when this ' \
                  'is FALSE - it means the valuations are missing, not that the account is empty.' },
          { name: 'totalValue', type: :number, hint: 'Zero and meaningless when valuesPopulated is FALSE.' },
          { name: 'cashValue', type: :number, hint: 'Dollar half of the template line. Trust only when valuesPopulated is TRUE.' },
          { name: 'cashPercent', type: :number,
            hint: 'Percent half of the template line. NULL when there is nothing to take a percentage of.' },
          { name: 'cashAssetCount', type: :integer,
            hint: 'How many positions were classified as cash. Non-zero with a $0 cashValue means the ' \
                  'cash position exists but carries no valuation.' },
          { name: 'cashClassificationFields', type: :string, hint: 'Which fields the match ran against.' },
          { name: 'costBasisPopulated', type: :boolean,
            hint: 'Always NULL here - this route does not return costBasis at all. Use List Portfolio ' \
                  'Assets with Include Cost Basis for that.' }
        ]
      end
    },
    get_account_transactions: {
      title: 'Get Account Transactions',
      subtitle: 'Date ranged transactions with withdrawal rollup',
      description: 'Transactions in a date range, with a withdrawal subtotal',
      input_fields: lambda do
        [
          { name: 'accountId', type: :integer, label: 'Account ID', optional: false },
          { name: 'startDate', type: :date, label: 'Start Date', optional: true, hint: 'Defaults to Jan 1 of the current year.' },
          { name: 'endDate', type: :date, label: 'End Date', optional: true, hint: 'Defaults to today.' },
          { name: 'withdrawalTypeIds', type: :string, label: 'Withdrawal transaction type IDs', optional: true,
            hint: 'Comma separated. From List Transaction Types. STRONGLY RECOMMENDED - without it the ' \
                  'connector falls back to keyword matching, which under reports.' }
        ]
      end,
      execute: lambda do |connection, input|
        start_date = input['startDate'].present? ? input['startDate'].to_date : "#{now.year}-01-01".to_date
        end_date   = input['endDate'].present? ? input['endDate'].to_date : now.to_date
        res = get("/api/v1/Portfolio/Accounts/#{input['accountId'].to_i}/Transactions")
          .params(
            'startDate' => start_date.strftime('%Y-%m-%d'),
            'endDate' => end_date.strftime('%Y-%m-%d')
          )
          .headers(call('orion_headers', '/portfolio/accounts'))
          .after_error_response(/.*/) do |code, _body, headers, message|
            error("Orion Account Transactions Error (#{code}): #{message}. " \
                  "Correlation ID: #{call('orion_correlation_id', headers)}")
          end
        txns = call('unwrap_array', res).select { |t| t.is_a?(Hash) }
        type_ids = call('parse_id_list', input['withdrawalTypeIds'])
        withdrawals = if type_ids.present?
                        txns.select do |t|
                          tid = (t['transactionTypeId'] || t['typeId'] || t['transTypeId']).to_s.strip
                          type_ids.include?(tid)
                        end
                      else
                        txns.select do |t|
                          desc = [t['transactionType'], t['type'], t['description'], t['transactionDescription']]
                                 .compact.join(' ').downcase
                          desc.include?('withdraw') || desc.include?('distribution')
                        end
                      end
        amounts = withdrawals.map { |t| (t['amount'] || t['transAmount'] || 0).to_f }
        # Sum signed, then take the magnitude. Taking .abs per row silently adds a positive
        # contribution that matched "distribution" in the keyword path.
        signed = amounts.inject(0.0) { |sum, a| sum + a }
        total  = signed.abs
        {
          'accountId' => input['accountId'].to_i,
          'transactions' => call('sanitize_rows', connection, txns),
          'transactionCount' => txns.length,
          'withdrawalTotal' => total.round(2),
          'withdrawalNetSigned' => signed.round(2),
          'withdrawalCount' => withdrawals.length,
          'mixedSigns' => amounts.reject(&:zero?).map(&:negative?).uniq.length > 1,
          'startDate' => start_date.strftime('%Y-%m-%d'),
          'endDate' => end_date.strftime('%Y-%m-%d'),
          'matchedBy' => type_ids.present? ? 'typeId' : 'description keyword fallback',
          'zeroIsUnverified' => (total.zero? && txns.present?)
        }
      end,
      output_fields: lambda do
        [
          { name: 'accountId', type: :integer },
          {
            name: 'transactions',
            type: :array,
            of: :object,
            properties: [
              { name: 'id', type: :integer },
              { name: 'tradeDate', type: :string },
              { name: 'settleDate', type: :string },
              { name: 'transactionTypeId', type: :integer },
              { name: 'transactionType', type: :string },
              { name: 'description', type: :string },
              { name: 'ticker', type: :string },
              { name: 'amount', type: :number },
              { name: 'shares', type: :number }
            ]
          },
          { name: 'transactionCount', type: :integer },
          { name: 'withdrawalTotal', type: :number,
            hint: 'Feeds the "YTD WD $" template field. Magnitude of the signed net, not a sum of ' \
                  'absolute values.' },
          { name: 'withdrawalNetSigned', type: :number,
            hint: 'The signed net before taking magnitude. If this and withdrawalTotal disagree in ' \
                  'sign, the matched set is not purely withdrawals.' },
          { name: 'withdrawalCount', type: :integer },
          { name: 'mixedSigns', type: :boolean,
            hint: 'TRUE means the matched rows contain both debits and credits, so the match rule is ' \
                  'catching contributions as well as withdrawals. Investigate before reporting.' },
          { name: 'startDate', type: :string },
          { name: 'endDate', type: :string },
          { name: 'matchedBy', type: :string, hint: 'Warn in the recipe if this reads "description keyword fallback".' },
          { name: 'zeroIsUnverified', type: :boolean,
            hint: 'TRUE means the account had transactions but none matched the withdrawal rule, so $0 is a match failure, not a real zero. Never report $0 when this is TRUE.' }
        ]
      end
    },
    get_beneficiaries_by_rep: {
      title: 'Get Beneficiaries (by Rep)',
      subtitle: 'Rep level beneficiary book, filtered to account IDs',
      description: 'Beneficiaries for a rep, filtered to account IDs',
      input_fields: lambda do
        [
          { name: 'repId', type: :integer, label: 'Representative ID', optional: false,
            hint: 'From the entitlement table. Get Signed In User often returns null.' },
          { name: 'accountIds', type: :string, label: 'Filter to Account IDs', optional: true,
            hint: 'Comma separated. Omitting returns the whole book.' }
        ]
      end,
      execute: lambda do |connection, input|
        res = get("/api/v1/Portfolio/Accounts/AccountInformation/Beneficiaries/#{input['repId'].to_i}")
          .headers(call('orion_headers', '/portfolio/accounts'))
          .after_error_response(/.*/) do |code, _body, headers, message|
            error("Orion Beneficiaries Error (#{code}): #{message}. " \
                  "Correlation ID: #{call('orion_correlation_id', headers)}")
          end
        rows = call('unwrap_array', res).select { |r| r.is_a?(Hash) }
        total_before = rows.length
        rows, applied, unmatched = call('filter_by_account_ids', rows, input['accountIds'])
        primary    = rows.select { |r| r['beneficiaryType'].to_s.downcase.include?('primary') }
        contingent = rows.select { |r| r['beneficiaryType'].to_s.downcase.include?('conting') }
        {
          'beneficiaries' => call('sanitize_rows', connection, rows),
          'beneficiaryCount' => rows.length,
          'primarySummary' => primary.map { |r| r['beneficiaryName'] || r['name'] }.compact.uniq.join(', '),
          'contingentSummary' => contingent.map { |r| r['beneficiaryName'] || r['name'] }.compact.uniq.join(', '),
          'filtered' => applied,
          'rowsBeforeFilter' => total_before,
          'unmatchedAccountIds' => unmatched.join(','),
          'idFormatWarning' => (applied && rows.empty? && total_before.positive?) ?
            'The rep book returned rows but NONE matched the supplied account ids. This feed may key ' \
            'accounts by custodian acct code (e.g. "636-148526") rather than Orion accountId. ' \
            'An empty result here means "no match", NOT "no beneficiaries on file" - do not report ' \
            '"none on file" to an advisor from this.' : nil
        }
      end,
      output_fields: lambda do
        [
          {
            name: 'beneficiaries',
            type: :array,
            of: :object,
            properties: [
              { name: 'accountId', type: :string },
              { name: 'accountNumber', type: :string, hint: 'Masked to last 4.' },
              { name: 'beneficiaryName', type: :string },
              { name: 'beneficiaryType', type: :string, hint: 'Primary or Contingent.' },
              { name: 'relationship', type: :string },
              { name: 'percentage', type: :number }
            ]
          },
          { name: 'beneficiaryCount', type: :integer },
          { name: 'primarySummary', type: :string, hint: 'Household roll up for template Text14.' },
          { name: 'contingentSummary', type: :string, hint: 'Household roll up for template Text20.' },
          { name: 'filtered', type: :boolean, hint: 'False means the whole rep book came through. Warn in the recipe.' },
          { name: 'rowsBeforeFilter', type: :integer, hint: 'Size of the rep book before the account filter.' },
          { name: 'unmatchedAccountIds', type: :string, hint: 'Ids you asked for that matched nothing. Non empty = investigate.' },
          { name: 'idFormatWarning', type: :string,
            hint: 'Populated when the filter matched nothing but the book was non empty. Distinguishes ' \
                  '"none on file" from "id space mismatch".' }
        ]
      end
    },
    get_systematics_by_rep: {
      title: 'Get Systematics (by Rep)',
      subtitle: 'Systematic distribution plans, filtered to account IDs',
      description: 'Systematic distributions for a rep, filtered to account IDs',
      input_fields: lambda do
        [
          { name: 'repId', type: :integer, label: 'Representative ID', optional: false },
          { name: 'accountIds', type: :string, label: 'Filter to Account IDs', optional: true,
            hint: 'Comma separated. Omitting returns the whole book.' }
        ]
      end,
      execute: lambda do |connection, input|
        res = get("/api/v1/Portfolio/Accounts/AccountInformation/Systematics/#{input['repId'].to_i}")
          .headers(call('orion_headers', '/portfolio/accounts'))
          .after_error_response(/.*/) do |code, _body, headers, message|
            error("Orion Systematics Error (#{code}): #{message}. " \
                  "Correlation ID: #{call('orion_correlation_id', headers)}")
          end
        rows = call('unwrap_array', res).select { |r| r.is_a?(Hash) }
        total_before = rows.length
        rows, applied, unmatched = call('filter_by_account_ids', rows, input['accountIds'])
        monthly = rows.select { |r| r['frequency'].to_s.downcase.include?('month') }
        monthly_total = monthly.inject(0.0) { |sum, r| sum + (r['amount'] || 0).to_f }
        distributions = rows.reject { |r| r['distributionType'].to_s.downcase.include?('contrib') }
        contributions = rows.select { |r| r['distributionType'].to_s.downcase.include?('contrib') }
        {
          'systematics' => call('sanitize_rows', connection, rows),
          'systematicCount' => rows.length,
          'distributionCount' => distributions.length,
          'contributionCount' => contributions.length,
          'monthlyTotal' => monthly_total.round(2),
          'filtered' => applied,
          'rowsBeforeFilter' => total_before,
          'unmatchedAccountIds' => unmatched.join(','),
          'idFormatWarning' => (applied && rows.empty? && total_before.positive?) ?
            'Rep book non empty but no account id matched. Treat as "no match", not "none on file".' : nil
        }
      end,
      output_fields: lambda do
        [
          {
            name: 'systematics',
            type: :array,
            of: :object,
            properties: [
              { name: 'accountId', type: :string },
              { name: 'accountNumber', type: :string, hint: 'Masked to last 4.' },
              { name: 'amount', type: :number },
              { name: 'frequency', type: :string },
              { name: 'distributionType', type: :string },
              { name: 'nextDate', type: :string },
              { name: 'isActive', type: :boolean }
            ]
          },
          { name: 'systematicCount', type: :integer },
          { name: 'distributionCount', type: :integer, hint: 'Excludes contribution plans.' },
          { name: 'contributionCount', type: :integer,
            hint: 'Report these separately. A contribution reported as a distribution is a test failure.' },
          { name: 'monthlyTotal', type: :number },
          { name: 'filtered', type: :boolean },
          { name: 'rowsBeforeFilter', type: :integer },
          { name: 'unmatchedAccountIds', type: :string },
          { name: 'idFormatWarning', type: :string }
        ]
      end
    },
    get_rmd_by_rep: {
      title: 'Get RMD (by Rep)',
      subtitle: 'RMD information, filtered to account IDs',
      description: 'RMD figures for a rep, filtered to account IDs',
      input_fields: lambda do
        [
          { name: 'repId', type: :integer, label: 'Representative ID', optional: false },
          { name: 'accountIds', type: :string, label: 'Filter to Account IDs', optional: true,
            hint: 'Comma separated. Omitting returns the whole rep book.' }
        ]
      end,
      execute: lambda do |connection, input|
        res = get("/api/v1/Portfolio/Accounts/AccountInformation/Rmd/#{input['repId'].to_i}")
          .headers(call('orion_headers', '/portfolio/accounts'))
          .after_error_response(/.*/) do |code, _body, headers, message|
            error("Orion RMD Error (#{code}): #{message}. " \
                  "Correlation ID: #{call('orion_correlation_id', headers)}")
          end
        raw_rows = call('unwrap_array', res).select { |r| r.is_a?(Hash) }
        total_before = raw_rows.length
        filtered_rows, applied, unmatched = call('filter_by_account_ids', raw_rows, input['accountIds'])
        rows = filtered_rows.map do |r|
          {
            'accountId' => r['accountId'] || r['acctCode'],
            'accountNumber' => r['accountNumber'] || r['acctCode'],
            'registrationName' => r['registrationName'],
            'registrationType' => r['registrationType'],
            'priorEoyValue' => (r['priorEoyValue'] || 0).to_f,
            'ytdDistribution' => (r['ytdDistribution'] || 0).to_f,
            'requiredAmount' => (r['requiredAmount'] || r['rmdAmount'] || 0).to_f,
            'distributedAmount' => (r['distributedAmount'] || r['ytdDistribution'] || 0).to_f,
            'remainingAmount' => (r['remainingAmount'] || r['rmdRemaining'] || 0).to_f,
            'dueDate' => r['dueDate'],
            'year' => r['year']
          }
        end
        required  = rows.inject(0.0) { |sum, r| sum + (r['requiredAmount'] || 0).to_f }
        remaining = rows.inject(0.0) { |sum, r| sum + (r['remainingAmount'] || 0).to_f }
        warning =
          if applied && rows.empty? && total_before.positive?
            'The rep RMD book returned rows but NONE matched the supplied account ids. This feed keys ' \
            'accounts by custodian acct code (e.g. "636-148526"), not the Orion accountId used by ' \
            'Get Account Value. An empty result here means "no id match", NOT "no RMD applies" - ' \
            'do not tell an advisor there is no RMD on the strength of this.'
          elsif !applied && total_before.positive?
            'NO ACCOUNT FILTER APPLIED. These rows are the entire rep book, not one client. ' \
            'Supply Filter to Account IDs before showing this to anyone.'
          end
        {
          'rmds' => call('sanitize_rows', connection, rows),
          'rmdCount' => rows.length,
          'rmdApplicable' => applied ? rows.present? : nil,
          'totalRequiredAmount' => required.round(2),
          'totalRemainingAmount' => remaining.round(2),
          'filtered' => applied,
          'rowsBeforeFilter' => total_before,
          'unmatchedAccountIds' => unmatched.join(','),
          'idFormatWarning' => warning
        }
      end,
      output_fields: lambda do
        [
          {
            name: 'rmds',
            type: :array,
            of: :object,
            properties: [
              { name: 'accountId', type: :string, hint: 'May be a custodian acct code such as "636-148526". Never coerce this to an integer.' },
              { name: 'accountNumber', type: :string, hint: 'Masked to last 4.' },
              { name: 'registrationName', type: :string, hint: 'Real Orion field. Registration owner name.' },
              { name: 'registrationType', type: :string, hint: 'Real Orion field, e.g. IRA, SEP IRA.' },
              { name: 'priorEoyValue', type: :number, hint: 'Real Orion field. Prior end-of-year account value used in the RMD calc.' },
              { name: 'ytdDistribution', type: :number, hint: 'Real Orion field. Amount already distributed this year.' },
              { name: 'requiredAmount', type: :number },
              { name: 'distributedAmount', type: :number },
              { name: 'remainingAmount', type: :number },
              { name: 'dueDate', type: :string, hint: 'Not present in this tenant response. Expect nil.' },
              { name: 'year', type: :integer, hint: 'Not present in this tenant response. Expect nil.' }
            ]
          },
          { name: 'rmdCount', type: :integer },
          { name: 'rmdApplicable', type: :boolean,
            hint: 'NULL when no account filter was applied - the rep book tells you nothing about ' \
                  'one client. Only trust true/false when filtered is true.' },
          { name: 'totalRequiredAmount', type: :number },
          { name: 'totalRemainingAmount', type: :number, hint: 'Falls back to rmdRemaining.' },
          { name: 'filtered', type: :boolean, hint: 'Now reports the truth. Previously said true while filtering nothing.' },
          { name: 'rowsBeforeFilter', type: :integer, hint: 'Rep book size. If this is large and rmdCount equals it, the filter did not bite.' },
          { name: 'unmatchedAccountIds', type: :string },
          { name: 'idFormatWarning', type: :string, hint: 'Read this before reporting "no RMD".' }
        ]
      end
    },
    list_registrations: {
      title: 'List Registrations',
      subtitle: 'Registration reference list',
      description: 'Registration reference list. Fetch once at build time',
      input_fields: lambda do
        [
          { name: 'isActive', type: :boolean, label: 'Is Active Only', default: true },
          { name: 'top', type: :integer, label: 'Top / Record Limit', default: 500 }
        ]
      end,
      execute: lambda do |connection, input|
        limit = input['top'].nil? ? 500 : input['top'].to_i
        res = get('/api/v1/Portfolio/Registrations')
          .params(
            'isActive' => input['isActive'].nil? ? 'true' : input['isActive'].to_s,
            'top' => limit
          )
          .headers(call('orion_headers', '/portfolio/registrations'))
          .after_error_response(/.*/) do |code, _body, headers, message|
            error("Orion Registrations Error (#{code}): #{message}. " \
                  "Correlation ID: #{call('orion_correlation_id', headers)}")
          end
        regs = call('sanitize_rows', connection, call('unwrap_array', res))
        { 'registrations' => regs, 'registrationCount' => regs.length,
          'truncated' => regs.length >= limit }
      end,
      output_fields: lambda do
        [
          {
            name: 'registrations',
            type: :array,
            of: :object,
            properties: [
              { name: 'id', type: :integer },
              { name: 'name', type: :string, hint: 'Joint registrations name both owners.' },
              { name: 'registrationType', type: :string },
              { name: 'clientId', type: :integer },
              { name: 'isActive', type: :boolean }
            ]
          },
          { name: 'registrationCount', type: :integer },
          { name: 'truncated', type: :boolean,
            hint: 'TRUE means the result hit the record limit and more rows exist that you did not receive.' }
        ]
      end
    },
    list_transaction_types: {
      title: 'List Transaction Types',
      subtitle: 'Transaction type legend',
      description: 'Transaction type IDs. Fetch once, then hard code the withdrawal IDs',
      input_fields: lambda do
        [
          { name: 'withdrawalOnly', type: :boolean, label: 'Withdrawal and distribution types only', default: false,
            hint: 'Convenience filter on name and description. Check the result by eye before hard coding it.' }
        ]
      end,
      execute: lambda do |_connection, input|
        res = get('/api/v1/Trading/TransactionTypes')
          .headers(call('orion_headers', '/trading/transactiontypes'))
          .after_error_response(/.*/) do |code, _body, headers, message|
            error("Orion Transaction Types Error (#{code}): #{message}. " \
                  "Correlation ID: #{call('orion_correlation_id', headers)}")
          end
        types = call('unwrap_array', res).select { |t| t.is_a?(Hash) }
        if input['withdrawalOnly']
          types = types.select do |t|
            label = [t['name'], t['description']].compact.join(' ').downcase
            label.include?('withdraw') || label.include?('distribution')
          end
        end
        {
          'transactionTypes' => types,
          'typeCount' => types.length,
          'idList' => types.map { |t| t['id'] }.compact.join(',')
        }
      end,
      output_fields: lambda do
        [
          {
            name: 'transactionTypes',
            type: :array,
            of: :object,
            properties: [
              { name: 'id', type: :integer },
              { name: 'name', type: :string },
              { name: 'description', type: :string },
              { name: 'category', type: :string }
            ]
          },
          { name: 'typeCount', type: :integer },
          { name: 'idList', type: :string, hint: 'Comma separated. Paste into the Get Account Transactions constant.' }
        ]
      end
    },
    list_billing_clients: {
      title: 'List Billing Clients',
      subtitle: 'Fee schedule and billing status per client',
      description: 'Client level fee schedule and billing status',
      input_fields: lambda do
        [
          { name: 'clientId', type: :integer, label: 'Filter to Client ID', optional: true,
            hint: 'Applied client side. Not a confirmed query param on this endpoint.' },
          { name: 'representativeNumber', type: :string, label: 'Filter to Representative Number', optional: true,
            hint: 'Applied client side against the representativeNumber field.' },
          { name: 'isActive', type: :boolean, label: 'Is Active Only', default: true },
          { name: 'status', type: :string, label: 'Status', optional: true,
            hint: 'Confirmed query param. Blank in the confirmed working call. Accepted values unconfirmed.' },
          { name: 'top', type: :integer, label: 'Top / Record Limit', default: 1000,
            hint: 'Was 50000. Every row is scrubbed and masked in memory, so a tenant sized pull ' \
                  'risks a job timeout. Raise deliberately and watch the truncated flag.' },
          { name: 'skip', type: :integer, label: 'Skip (paging offset)', optional: true,
            hint: 'UNCONFIRMED on this endpoint. If Orion ignores it you receive the SAME page again.' },
          { name: 'diagnostic', type: :boolean, label: 'Diagnostic mode', default: false,
            hint: 'Returns the untouched response so the real shape can be read first.' }
        ]
      end,
      execute: lambda do |connection, input|
        limit = input['top'].nil? ? 1000 : input['top'].to_i
        params = {
          'isActive' => input['isActive'].nil? ? 'true' : input['isActive'].to_s,
          'status' => input['status'].presence,
          'top' => limit,
          'skip' => input['skip']
        }.reject { |_, v| v.nil? }
        res = get('/api/v1/Billing/Clients/Grid')
          .params(params)
          .headers(call('orion_headers', '/billing/clients'))
          .after_error_response(/.*/) do |code, body, headers, message|
            error("Orion Billing Clients Grid Error (#{code}): #{message}. " \
                  "Body: #{call('safe_body', connection, body, 500)}. " \
                  "Correlation ID: #{call('orion_correlation_id', headers)}")
          end
        if call('to_bool', input['diagnostic'], false)
          next { 'raw' => { 'response' => call('sanitize_any', connection, res) } }
        end
        rows = call('unwrap_array', res).select { |r| r.is_a?(Hash) }
        # Measured against what Orion returned, before the client side filters below.
        truncated = rows.length >= limit
        rows = rows.map { |r| r.reject { |k, _| k.to_s.start_with?('udf') || k == 'additionalColumns' } }
        if input['clientId'].present?
          target = input['clientId'].to_s.strip
          rows = rows.select { |r| r['id'].to_s.strip == target }
        end
        if input['representativeNumber'].present?
          target = input['representativeNumber'].to_s.strip
          rows = rows.select { |r| r['representativeNumber'].to_s.strip == target }
        end
        rows = call('sanitize_rows', connection, rows)
        {
          'billingClients' => rows,
          'billingClientCount' => rows.length,
          'feeScheduleResolved' => rows.all? { |r| r['feeSchedule'].present? },
          'truncated' => truncated,
          'pagingUnverified' => input['skip'].to_i.positive?
        }
      end,
      output_fields: lambda do
        [
          {
            name: 'billingClients',
            type: :array,
            of: :object,
            properties: [
              { name: 'id', type: :integer },
              { name: 'billClientId', type: :integer, hint: 'Same value as id on this tenant.' },
              { name: 'firstName', type: :string },
              { name: 'lastName', type: :string },
              { name: 'fullName', type: :string, hint: 'Frequently null in staging' },
              { name: 'aum', type: :number },
              { name: 'statusType', type: :string, hint: 'e.g. "Ready to Bill", "Pending Review".' },
              { name: 'billStatusId', type: :integer },
              { name: 'relatedClients', type: :integer },
              { name: 'recurrentAdjustments', type: :integer },
              { name: 'feePayingAccounts', type: :integer },
              { name: 'representativeName', type: :string },
              { name: 'representativeNumber', type: :string },
              { name: 'feeScheduleId', type: :integer, hint: 'Frequently null in staging. Join key to List Billing Schedules when populated.' },
              { name: 'feeSchedule', type: :string, hint: 'Resolved fee schedule name. Frequently null in staging' },
              { name: 'masterPayoutScheduleId', type: :integer },
              { name: 'masterPayoutSchedule', type: :string },
              { name: 'createdBy', type: :string },
              { name: 'createdDate', type: :string },
              { name: 'editedBy', type: :string },
              { name: 'editedDate', type: :string },
              { name: 'isActive', type: :boolean }
            ]
          },
          { name: 'billingClientCount', type: :integer },
          { name: 'feeScheduleResolved', type: :boolean,
            hint: 'FALSE means at least one row has no fee schedule. Say the fee must be confirmed from the ' \
                  'advisory agreement. Never estimate a fee.' },
          { name: 'truncated', type: :boolean,
            hint: 'TRUE means Orion hit the record limit before the client side filters ran, so a missing row may just not have been on this page.' },
          { name: 'pagingUnverified', type: :boolean,
            hint: 'TRUE whenever Skip was supplied. Orion is not confirmed to honour it on this ' \
                  'endpoint - if it is ignored you get the same page back.' },
          { name: 'raw', type: :object, hint: 'Diagnostic mode only. Masked and scrubbed like any other output.' }
        ]
      end
    },
    list_billing_schedules: {
      title: 'List Billing Schedules',
      subtitle: 'Fee schedule labels, no structured rate field exists',
      description: 'Fee schedule names and types. Rates are free text - never parse them',
      input_fields: lambda do
        [
          { name: 'scheduleId', type: :integer, label: 'Schedule ID', optional: true, hint: 'Supplied to fetch a single schedule by path.' },
          { name: 'top', type: :integer, label: 'Top / Record Limit', default: 200 },
          { name: 'diagnostic', type: :boolean, label: 'Diagnostic mode', default: false }
        ]
      end,
      execute: lambda do |connection, input|
        res = if input['scheduleId'].present?
                get("/api/v1/Billing/Schedules/#{input['scheduleId'].to_i}")
                  .headers(call('orion_headers', '/billing/schedules'))
                  .after_error_response(/.*/) do |code, body, headers, message|
                    error("Orion Billing Schedule Error (#{code}): #{message}. " \
                          "Body: #{call('safe_body', connection, body, 500)}. " \
                          "Correlation ID: #{call('orion_correlation_id', headers)}")
                  end
              else
                get('/api/v1/Billing/Schedules')
                  .params('top' => input['top'].nil? ? 200 : input['top'].to_i)
                  .headers(call('orion_headers', '/billing/schedules'))
                  .after_error_response(/.*/) do |code, body, headers, message|
                    error("Orion Billing Schedules Error (#{code}): #{message}. " \
                          "Body: #{call('safe_body', connection, body, 500)}. " \
                          "Correlation ID: #{call('orion_correlation_id', headers)}")
                  end
              end
        if call('to_bool', input['diagnostic'], false)
          next { 'raw' => { 'response' => call('sanitize_any', connection, res) } }
        end
        rows = call('unwrap_array', res).select { |r| r.is_a?(Hash) }
        if input['scheduleId'].present?
          target = input['scheduleId'].to_s.strip
          rows = rows.select { |r| r['id'].to_s.strip == target }
        end
        { 'schedules' => call('sanitize_rows', connection, rows), 'scheduleCount' => rows.length }
      end,
      output_fields: lambda do
        [
          {
            name: 'schedules',
            type: :array,
            of: :object,
            properties: [
              { name: 'id', type: :integer },
              { name: 'name', type: :string, hint: 'No structured rate field. Any rate is free text inside this name, e.g. "Green Linear <$3MM=-0.80%". Never parse it into a fee - confirm from the advisory agreement.' },
              { name: 'description', type: :string },
              { name: 'type', type: :string, hint: 'e.g. "Linear", "Flat".' },
              { name: 'basis', type: :string, hint: 'e.g. "Household", "Account", "Fee Schedule".' },
              { name: 'minFeeAcctValueThreshold', type: :number },
              { name: 'minimumFee', type: :number },
              { name: 'billEntityName', type: :string },
              { name: 'isActive', type: :boolean },
              { name: 'isPayoutCreditOffset', type: :boolean }
            ]
          },
          { name: 'scheduleCount', type: :integer },
          { name: 'raw', type: :object, hint: 'Diagnostic mode only. Masked and scrubbed like any other output.' }
        ]
      end
    }
  }
}
