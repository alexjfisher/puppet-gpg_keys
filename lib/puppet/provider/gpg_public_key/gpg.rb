Puppet::Type.type(:gpg_public_key).provide(:gpg) do
  commands gpg: 'gpg'

  def gpg_cmd(*args)
    resolved_executable = Puppet::Util.which('gpg')
    raise Puppet::MissingCommand, _("Command %{name} is missing") % { name: @name } if resolved_executable.nil?
    command = [resolved_executable] + ['--homedir', resource[:homedir], '--batch'] + args
    Puppet::Util::Execution.execute(command, failonfail: true, combine: true, uid: resource[:user])
  end

  def public_keys_ids(user, gnuhome)
    begin
      output = gpg_cmd(['--list-keys', '--with-colons'])
    rescue Puppet::ExecutionFailure => e
      Puppet.debug("#get_public_keys had an error -> #{e.inspect}")
      return nil
    end
    public_keys = output.split("\n").sort.grep(/^pub/)
    public_keys.map { |key| key.split(':')[4] }
  end

  def exists?
    public_keys_ids(
      resource[:user],
      resource[:name]
    ).include?(resource[:longkeyid])
  end

  def create
    Puppet.debug "Importing key #{resource[:longkeyid]}"
    keyfile = Tempfile.new('key')
    keyfile.write(resource[:content])
    keyfile.close
    FileUtils.chmod 'a+r', keyfile.path
    output = gpg_cmd(['--import', keyfile.path])
    Puppet.debug output
    keyfile.unlink
  end

  def destroy
    Puppet.debug "Deleting key #{resource[:longkeyid]}"
    output = gpg_cmd(['--yes', '--delete-key', resource[:longkeyid]])
    Puppet.debug output
  end

  def content
    output = gpg_cmd(['--export', '--armor', resource[:longkeyid]])
    raise Puppet::Error, 'Exported key invalid' unless valid_public_key?(output)
    output
  end

  def valid_public_key?(key)
    return false if key.split("\n").first !~ /-----BEGIN PGP PUBLIC KEY BLOCK-----/
    return false if key.split("\n").last  !~ /-----END PGP PUBLIC KEY BLOCK-----/
    Puppet.debug('key looks valid')
    true
  end

  def content=(value)
    Puppet.debug("Replacing key #{resource[:longkeyid]}")
    destroy
    create
  end
end
