require File.join(File.dirname(__FILE__), '..', 'gpg_keys')

Puppet::Type.type(:gpg_public_key).provide(:gpg, parent: Puppet::Provider::Gpg_keys) do
  commands gpg: 'gpg'
  def public_keys_ids
    begin
      output = gpg_cmd(['--list-keys', '--with-colons'])
    rescue Puppet::ExecutionFailure => e
      Puppet.debug("#get_public_keys had an error -> #{e.inspect}")
      return nil
    end
    public_keys = output.split("\n").sort.grep(%r{^pub})
    public_keys.map { |key| key.split(':')[4] }
  end

  def exists?
    public_keys_ids.include?(resource[:longkeyid])
  end

  def create
    raise Puppet::Error, "'content' is mandatory when creating a gpg_public_key" unless resource[:content]
    Puppet.debug "Importing key #{resource[:longkeyid]}"
    keyfile = Tempfile.new('key')
    keyfile.write(resource[:content])
    keyfile.close
    FileUtils.chmod 'a+r', keyfile.path
    output = gpg_cmd(['--import', keyfile.path])
    Puppet.debug output
    keyfile.unlink

    self.trust = resource[:trust] unless resource[:trust].nil?
  end

  def destroy
    Puppet.debug "Deleting key #{resource[:longkeyid]}"
    output = gpg_cmd(['--yes', '--delete-secret-key', fingerprint]) if has_secret_key?
    output = gpg_cmd(['--yes', '--delete-key', resource[:longkeyid]])
    Puppet.debug output
  end

  def has_secret_key?
    output = gpg_cmd(['--list-secret-keys', '--with-colons'])
    output.include? resource[:longkeyid]
  end

  def content
    output = gpg_cmd(['--export', '--armor', resource[:longkeyid]])
    raise Puppet::Error, 'Exported key invalid' unless valid_public_key?(output)
    output
  end

  def valid_public_key?(key)
    return false if key.split("\n").first !~ %r{-----BEGIN PGP PUBLIC KEY BLOCK-----}
    return false if key.split("\n").last  !~ %r{-----END PGP PUBLIC KEY BLOCK-----}
    Puppet.debug('key looks valid')
    true
  end

  def content=(_value)
    Puppet.debug("Replacing key #{resource[:longkeyid]}")
    destroy
    create
  end

  def trust
    trust = exported_owner_trust[fingerprint]
    Puppet.debug("Trust in #{resource[:longkeyid]} is #{trust}")
    return 'unknown' if trust.nil?
    trust
  end

  def trust=(value)
    Puppet.debug("Setting trust of #{resource[:longkeyid]} to #{value}")
    Puppet.debug(trust_to_import(value))
    trustfile = Tempfile.new('trust')
    trustfile.write(trust_to_import(value))
    trustfile.close
    FileUtils.chmod 'a+r', trustfile.path
    output = gpg_cmd(['--import-ownertrust', trustfile.path])
    Puppet.debug output
    trustfile.unlink
  end

  def trust_to_import(trust_string)
    "#{fingerprint}:#{trustvalue(trust_string)}:\n"
  end

  def exported_owner_trust
    owner_trust = {}
    Puppet.debug "Exporting owner trust for #{resource[:longkeyid]}"
    output = gpg_cmd(['--export-ownertrust'])
    Puppet.debug output
    output.split("\n").each do |line|
      matchdata = line.match(%r{
                             ^
                             (?<key_id>\h{40})
                             :
                             (?<trust_value>[2-6])
                             :
                             }x)
      next unless matchdata
      owner_trust[matchdata[:key_id]] = truststring(matchdata[:trust_value].to_i)
    end
    owner_trust
  end

  def truststring(value)
    str = trustmap.key(value)
    raise Puppet::Error, 'Unrecognised trust value' if str.nil?
    str
  end

  def trustvalue(str)
    raise Puppet::Error, 'Unrecognised trust string' unless trustmap.key?(str)
    trustmap[str]
  end

  def trustmap
    {
      undefined: 2,
      none:      3,
      marginal:  4,
      full:      5,
      ultimate:  6
    }
  end
end
