require 'puppet/provider'

class Puppet::Provider::Gpg_keys < Puppet::Provider
  def gpg_cmd(*args)
    resolved_executable = Puppet::Util.which('gpg')
    raise Puppet::MissingCommand, format(_("Command #{name} is missing"), name: @name) if resolved_executable.nil?
    command = [resolved_executable] + ['--homedir', resource[:homedir], '--batch'] + args
    Puppet::Util::Execution.execute(command, failonfail: true, combine: true, uid: resource[:user])
  end

  def fingerprint
    Puppet.debug("Getting fingerprint of key id #{resource[:longkeyid]}")
    output = gpg_cmd(['--fingerprint', '--with-colons', resource[:longkeyid]])
    fingerprint_line = output.split("\n").sort.grep(%r{^fpr}).first
    fingerprint_line.split(':')[9]
  end
end
