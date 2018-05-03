require File.join(File.dirname(__FILE__), '..', 'gpg_keys')

Puppet::Type.type(:gpg_secret_key).provide(:gpg, parent: Puppet::Provider::Gpg_keys) do
  commands gpg: 'gpg'
  def secret_keys_ids
    begin
      output = gpg_cmd(['--list-secret-keys', '--with-colons'])
    rescue Puppet::ExecutionFailure => e
      Puppet.debug("#secret_keys_id had an error -> #{e.inspect}")
      return nil
    end
    keys = output.split("\n").sort.grep(%r{^sec})
    keys.map { |key| key.split(':')[4] }
  end

  def exists?
    secret_keys_ids.include?(resource[:longkeyid])
  end

  def create
    raise Puppet::Error, "'content' is mandatory when creating a gpg_secret_key" unless resource[:content]
    Puppet.debug "Importing secret key #{resource[:longkeyid]}"
    keyfile = Tempfile.new('key')
    keyfile.write(resource[:content])
    keyfile.close
    FileUtils.chmod 'a+r', keyfile.path
    output = gpg_cmd(['--import', keyfile.path])
    Puppet.debug output
    keyfile.unlink
  end

  def destroy
    Puppet.debug "Deleting secret key #{resource[:longkeyid]}"
    output = gpg_cmd(['--yes', '--delete-secret-key', fingerprint])
    Puppet.debug output
  end

  def content
    output = gpg_cmd(['--export-secret-key', '--armor', resource[:longkeyid]])
    raise Puppet::Error, 'Exported secret key invalid' unless valid_secret_key?(output)
    output
  end

  def valid_secret_key?(key)
    return false if key.split("\n").first !~ %r{-----BEGIN PGP PRIVATE KEY BLOCK-----}
    return false if key.split("\n").last  !~ %r{-----END PGP PRIVATE KEY BLOCK-----}
    Puppet.debug('key looks valid')
    true
  end

  def content=(_value)
    Puppet.debug("Replacing secret key #{resource[:longkeyid]}")
    destroy
    create
  end
end
