class Devise::TwoFactorAuthenticationController < DeviseController
  prepend_before_action :authenticate_scope!
  before_action :prepare_and_validate, :handle_two_factor_authentication

  def show
  end

  def update
    render :show and return if params[:code].nil?

    if resource.authenticate_otp(params[:code])
      warden.session(resource_name)['need_two_factor_authentication'] = false
      # For compatability with devise versions below v4.2.0
      # https://github.com/plataformatec/devise/commit/2044fffa25d781fcbaf090e7728b48b65c854ccb
      if respond_to?(:bypass_sign_in)
        bypass_sign_in(resource, scope: resource_name)
      else
        sign_in(resource_name, resource, bypass: true)
      end

      set_flash_message :notice, :success
      redirect_to stored_location_for(resource_name) || :root
      resource.update_attribute(:second_factor_attempts_count, 0)
    else
      resource.second_factor_attempts_count += 1
      resource.save
      flash.now[:error] = find_message(:attempt_failed)
      if resource.max_login_attempts?
        sign_out(resource)
        render :max_login_attempts_reached
      else
        render :show
      end
    end
  end

  private

    def authenticate_scope!
      self.resource = send("current_#{resource_name}")
    end

    def prepare_and_validate
      redirect_to :root and return if resource.nil?
      @limit = resource.max_login_attempts
      if resource.max_login_attempts?
        sign_out(resource)
        render :max_login_attempts_reached and return
      end
    end
end
