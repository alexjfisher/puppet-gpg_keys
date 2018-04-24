require 'puppetlabs_spec_helper/rake_tasks'

# load optional tasks for releases
# only available if gem group releases is installed
begin
  require 'puppet_blacksmith/rake_tasks'
  require 'puppet-strings/tasks'
rescue LoadError
end

PuppetLint.configuration.log_format = '%{path}:%{line}:%{check}:%{KIND}:%{message}'
PuppetLint.configuration.fail_on_warnings = true
PuppetLint.configuration.send('relative')
PuppetLint.configuration.send('disable_140chars')
PuppetLint.configuration.send('disable_class_inherits_from_params_class')
PuppetLint.configuration.send('disable_documentation')
PuppetLint.configuration.send('disable_single_quote_string_with_variables')

exclude_paths = %w(
  pkg/**/*
  vendor/**/*
  .vendor/**/*
  spec/**/*
)
PuppetLint.configuration.ignore_paths = exclude_paths
PuppetSyntax.exclude_paths = exclude_paths

desc 'Auto-correct puppet-lint offenses'
task 'lint:auto_correct' do
  PuppetLint.configuration.fix = true
  Rake::Task[:lint].invoke
end

desc 'Run acceptance tests'
RSpec::Core::RakeTask.new(:acceptance) do |t|
  t.pattern = 'spec/acceptance'
end

desc 'Run tests metadata_lint, release_checks'
task test: [
  :metadata_lint,
  :release_checks,
]

desc "Run main 'test' task and report merged results to coveralls"
task test_with_coveralls: [:test] do
  if Dir.exist?(File.expand_path('../lib', __FILE__))
    require 'coveralls/rake/task'
    Coveralls::RakeTask.new
    Rake::Task['coveralls:push'].invoke
  else
    puts 'Skipping reporting to coveralls.  Module has no lib dir'
  end
end

# vim: syntax=ruby
