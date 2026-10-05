# frozen_string_literal: true

require "json"
require "net/http"
require "uri"

module StandardId
  module Providers
    # Sign in with the organisation's Void-Which-Binds broker (moneta), per
    # ADR-0023: OpenID Connect authorization code + PKCE S256 + nonce, and an
    # Ed25519 (EdDSA) ID token verified only under PINNED key thumbprints.
    #
    # Web flow only. standard_id (0.46+) generates the state, the nonce and,
    # because supports_pkce? is true, a fresh PKCE verifier for every sign-in,
    # and keeps all three in the browser's encrypted pending-requests cookie;
    # only the S256 challenge leaves the server. At the web callback core
    # passes the stored verifier (`code_verifier:`) and the callback's RFC 9207
    # `iss` (`callback_iss:`). The native/API callback never passes a verifier
    # (it has no server-held flow state), so it is refused, and core's API
    # social login grant refuses a PKCE provider before it starts.
    class VoidWhichBinds < Base
      PROVIDER_NAME = "void_which_binds"
      DEFAULT_SCOPE = "openid email"

      class << self
        def provider_name
          PROVIDER_NAME
        end

        # :nonce makes standard_id's login controller generate a nonce for
        # every flow and hand it back to get_user_info at the callback.
        def supported_authorization_params
          [:nonce]
        end

        def default_scope
          DEFAULT_SCOPE
        end

        # Core-managed PKCE (standard_id 0.46): core generates and stores the
        # verifier, sends its S256 challenge to authorization_url, and hands
        # it back to get_user_info on the web callback only.
        def supports_pkce?
          true
        end

        # moneta verifies the address before it sets email_verified (a link
        # it mailed to that address, or an org-administered domain; ADR-0023
        # D7), so a verified moneta email may link to an existing verified
        # account created another way. Only an org's OWN identity provider may
        # return true here; see the README.
        def trusted_for_linking?
          true
        end

        def config_schema
          {
            void_which_binds_client_id: { type: :string, default: nil },
            void_which_binds_client_secret: { type: :string, default: nil, required: true },
            void_which_binds_issuer: { type: :string, default: nil, required: true },
            void_which_binds_org: { type: :string, default: nil, required: true },
            # Array of RFC 7638 thumbprints, or one comma/space-separated
            # String (the ENV form).
            void_which_binds_jwks_pins: { type: :any, default: nil, required: true },
            # The JWKS inline (JSON or a Hash); nil fetches
            # issuer + /.well-known/jwks.json. Either way only pinned keys count.
            void_which_binds_jwks: { type: :any, default: nil },
            # Override discovery (issuer + /.well-known/openid-configuration).
            void_which_binds_authorization_endpoint: { type: :string, default: nil },
            void_which_binds_token_endpoint: { type: :string, default: nil },
            # Enforced by StandardId::VoidWhichBinds.staff_policy, and gates
            # the staff lock on a roster removal.
            void_which_binds_require_for_staff: { type: :boolean, default: true },
            # ->(account) { truthy for staff }; a callable, so never from ENV.
            void_which_binds_staff_predicate: { type: :any, default: nil, env: false }
          }
        end

        def authorization_url(state:, redirect_uri:, nonce: nil, code_challenge: nil, code_challenge_method: nil, **_options)
          raise StandardId::InvalidRequestError, "Void-Which-Binds sign-in needs a server-generated nonce" if nonce.blank?
          if code_challenge.blank? || code_challenge_method != StandardId::VoidWhichBinds::Pkce::METHOD
            raise StandardId::InvalidRequestError, "Void-Which-Binds sign-in needs a server-generated PKCE S256 challenge"
          end

          authorization_endpoint, = StandardId::VoidWhichBinds::Broker.endpoints
          query = {
            client_id: credentials[:client_id],
            redirect_uri: redirect_uri,
            response_type: "code",
            state: state,
            scope: DEFAULT_SCOPE,
            nonce: nonce,
            code_challenge: code_challenge,
            code_challenge_method: code_challenge_method
          }
          "#{authorization_endpoint}?#{URI.encode_www_form(query)}"
        rescue StandardId::VoidWhichBinds::Error => e
          raise StandardId::InvalidRequestError, "Void-Which-Binds is misconfigured: #{e.message}"
        end

        # Exchanges the code (client_secret_basic, PKCE verifier), verifies the
        # ID token under the pinned keys exactly as void-which-binds-go's
        # oidc.VerifyIDToken does, refuses a token issued at or before the
        # subject's revocation watermark, and returns its claims.
        #
        # `code_verifier` comes only from core's web callback (the verifier it
        # stored with this flow's state); its absence means the native/API
        # callback, which is refused. `callback_iss` is the callback's RFC 9207
        # `iss`, checked before the code is exchanged.
        def get_user_info(code: nil, id_token: nil, access_token: nil, redirect_uri: nil, nonce: nil,
                          callback_iss: nil, code_verifier: nil, **_options)
          if id_token.present? || access_token.present?
            raise StandardId::InvalidRequestError, "Void-Which-Binds sign-in accepts only the authorization code flow"
          end

          rescue_to_oauth_error do
            raise StandardId::InvalidRequestError, "Void-Which-Binds authorization code is missing" if code.blank?
            # Only core's web callback passes the server-held verifier.
            if code_verifier.blank?
              raise StandardId::InvalidRequestError, "Void-Which-Binds sign-in is only available through the web callback"
            end
            raise StandardId::InvalidRequestError, "Void-Which-Binds sign-in needs a server-generated nonce" if nonce.blank?
            raise StandardId::InvalidRequestError, "Void-Which-Binds redirect_uri is missing" if redirect_uri.blank?

            with_refusals_as_oauth_errors do
              check_callback_issuer!(callback_iss)
              token = exchange_code(code: code, redirect_uri: redirect_uri, code_verifier: code_verifier)
              claims = verify_id_token(token, nonce: nonce)
              StandardId::VoidWhichBinds::Logins.check!(iss: claims.iss, sub: claims.sub, login_iat: claims.iat)
              StandardId::VoidWhichBinds::Current.pending_login = { iss: claims.iss, sub: claims.sub, iat: claims.iat }

              build_response(user_info(claims), tokens: { id_token: token })
            end
          end
        end

        # Verifies an ID token for this app's configuration and the session's
        # nonce; raises StandardId::VoidWhichBinds::Refusal.
        def verify_id_token(token, nonce:, now: Time.now.to_i)
          StandardId::VoidWhichBinds::Broker.with_pins do |pins|
            StandardId::VoidWhichBinds::IdToken.verify(token, StandardId::VoidWhichBinds::IdToken::Expect.new(
              issuer: StandardId::VoidWhichBinds::Configuration.issuer,
              client_id: credentials[:client_id],
              org: StandardId::VoidWhichBinds::Configuration.org,
              nonce: nonce.to_s,
              pins: pins,
              now: now,
              leeway: StandardId::VoidWhichBinds::IdToken::MAX_LEEWAY
            ))
          end
        end

        private

        # A verifier's refusal names only its verdict (never a token value);
        # misconfiguration names the field.
        def with_refusals_as_oauth_errors
          yield
        rescue StandardId::VoidWhichBinds::Refusal => e
          raise StandardId::InvalidRequestError, "Void-Which-Binds sign-in refused (#{e.verdict})"
        rescue StandardId::VoidWhichBinds::BrokerUnavailable => e
          raise StandardId::InvalidRequestError, "Void-Which-Binds is unavailable: #{e.message}"
        rescue StandardId::VoidWhichBinds::Error => e
          raise StandardId::InvalidRequestError, "Void-Which-Binds is misconfigured: #{e.message}"
        end

        def credentials
          client_id = StandardId::VoidWhichBinds::Configuration.client_id
          raise StandardId::InvalidRequestError, "Void-Which-Binds is not configured" if client_id.nil?
          if (error = StandardId::VoidWhichBinds::Validators.client_id_error(client_id))
            raise StandardId::VoidWhichBinds::ConfigurationError, "void_which_binds_client_id: #{error}"
          end

          { client_id: client_id, client_secret: StandardId::VoidWhichBinds::Configuration.client_secret }
        end

        # RFC 9207: the redirect carries moneta's `iss`, checked before the
        # code is exchanged (mix-up defence). A missing one is refused: moneta
        # always sends it.
        def check_callback_issuer!(callback_iss)
          return if callback_iss.is_a?(String) && callback_iss == StandardId::VoidWhichBinds::Configuration.issuer

          raise StandardId::InvalidRequestError, "Void-Which-Binds sign-in refused (callback iss)"
        end

        def exchange_code(code:, redirect_uri:, code_verifier:)
          creds = credentials
          raise StandardId::InvalidRequestError, "Void-Which-Binds client secret is not set" if creds[:client_secret].blank?

          _, token_endpoint = StandardId::VoidWhichBinds::Broker.endpoints
          response = StandardId::VoidWhichBinds::Http.post_form(
            token_endpoint,
            {
              grant_type: "authorization_code",
              code: code,
              redirect_uri: redirect_uri,
              code_verifier: code_verifier
            },
            basic_auth: basic_auth(creds[:client_id], creds[:client_secret])
          )
          unless response.is_a?(Net::HTTPSuccess)
            raise StandardId::InvalidRequestError, "Failed to exchange Void-Which-Binds authorization code: #{error_reason(response)}"
          end

          parsed = JSON.parse(response.body.to_s)
          token = parsed.is_a?(Hash) ? parsed["id_token"] : nil
          raise StandardId::InvalidRequestError, "Void-Which-Binds token response is missing id_token" unless token.is_a?(String) && token.present?

          token
        end

        # client_secret_basic (RFC 6749 §2.3.1): both parts form-urlencoded,
        # then base64.
        def basic_auth(client_id, client_secret)
          pair = "#{URI.encode_www_form_component(client_id)}:#{URI.encode_www_form_component(client_secret)}"
          "Basic #{[pair].pack("m0")}"
        end

        def user_info(claims)
          {
            "sub" => claims.sub,
            "email" => claims.email,
            "email_verified" => claims.email_verified,
            "org" => claims.org,
            "role" => claims.role,
            "amr" => claims.amr,
            "iss" => claims.iss,
            "iat" => claims.iat,
            "auth_time" => claims.auth_time
          }.compact
        end

        def error_reason(response)
          body = JSON.parse(response.body.to_s)
          reason = body["error"] if body.is_a?(Hash)
          reason.is_a?(String) && reason.present? ? reason : "HTTP #{response.code}"
        rescue JSON::ParserError
          "HTTP #{response.code}"
        end
      end
    end
  end
end
