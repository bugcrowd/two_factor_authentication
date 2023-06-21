require 'two_factor_authentication/hooks/two_factor_authenticatable'
module Devise
  module Models
    module TwoFactorAuthenticatable
      extend ActiveSupport::Concern

      # We can't bump ROTP because it breaks this Gem and can't use the version of ROTP that this Gem requires
      # because it breaks in Ruby 3 as URI.encode does not exist
      module Ruby3RotpPatch
        refine ROTP::TOTP do
          def provisioning_uri(name)
            # The format of this URI is documented at:
            # https://github.com/google/google-authenticator/wiki/Key-Uri-Format
            # For compatibility the issuer appears both before that account name and also in the
            # query string.
            issuer_string = issuer.nil? ? "" : "#{CGI::escape(issuer)}:"
            params = {
              secret: secret,
              period: interval == 30 ? nil : interval,
              issuer: issuer,
              digits: digits ==  ROTP::TOTP::DEFAULT_DIGITS ? nil : digits,
              algorithm: digest.upcase == 'SHA1' ? nil : digest.upcase,
            }

            encode_params("otpauth://totp/#{issuer_string}#{CGI::escape(name)}", params)
          end
        end
      end
      module ClassMethods

        def has_one_time_password(options = {})

          cattr_accessor :otp_column_name
          self.otp_column_name = "otp_secret_key"


          include InstanceMethodsOnActivation

          before_create { populate_otp_column }

          if respond_to?(:attributes_protected_by_default)
            def self.attributes_protected_by_default #:nodoc:
              super + [self.otp_column_name]
            end
          end
        end
        ::Devise::Models.config(self, :max_login_attempts, :allowed_otp_drift_seconds)
      end

      module InstanceMethodsOnActivation
        using Ruby3RotpPatch

        def authenticate_otp(code, options = {})
          totp = ROTP::TOTP.new(self.otp_column)
          drift = options[:drift] || self.class.allowed_otp_drift_seconds

          totp.verify_with_drift(code, drift)
        end

        def otp_code(time = Time.now)
          ROTP::TOTP.new(self.otp_column).at(time, true)
        end

        def provisioning_uri(account = nil, options = {})
          account ||= self.email if self.respond_to?(:email)
          ROTP::TOTP.new(self.otp_column, options).provisioning_uri(account)
        end

        def otp_column
          self.send(self.class.otp_column_name)
        end

        def otp_column=(attr)
          self.send("#{self.class.otp_column_name}=", attr)
        end

        def need_two_factor_authentication?(request)
          true
        end

        def send_two_factor_authentication_code
          raise NotImplementedError.new("No default implementation - please define in your class.")
        end

        def max_login_attempts?
          second_factor_attempts_count.to_i >= max_login_attempts.to_i
        end

        def max_login_attempts
          self.class.max_login_attempts
        end

        def populate_otp_column
          self.otp_column = ROTP::Base32.random_base32
        end

      end
    end
  end
end
