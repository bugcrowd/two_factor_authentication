ENV["RAILS_ENV"] ||= "test"
require File.expand_path("../rails_app/config/environment.rb",  __FILE__)

require 'rspec/rails'

# See http://rubydoc.info/gems/rspec-core/RSpec/Core/Configuration
RSpec.configure do |config|
  config.treat_symbols_as_metadata_keys_with_true_values = true
  config.run_all_when_everything_filtered = true
  config.filter_run :focus

  config.use_transactional_examples = true

  # Run specs in random order to surface order dependencies. If you find an
  # order dependency and want to debug it, you can fix the order by providing
  # the seed, which is printed after each run.
  #     --seed 1234
  config.order = 'random'
end

Dir["#{Dir.pwd}/spec/support/**/*.rb"].each {|f| require f}
