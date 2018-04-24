Puppet::Type.newtype(:gpg_public_key) do
  ensurable do
    defaultvalues
    defaultto :present
  end

  newparam(:name) do
    isnamevar
  end

  newparam(:homedir) do
    defaultto '~/.gnupg'
    validate do |value|
      raise Puppet::Error, "'homedir' file path must be absolute, not '#{value}'" unless Puppet::Util.absolute_path?(value) || value == '~/.gnupg'
    end
  end

  newparam(:user) do
    validate do |value|
      raise Puppet::Error, "'user' is mandatory for gpg_keyring_key" if value.nil?
    end
  end

  newparam(:longkeyid) do
    validate do |value|
      raise Puppet::Error, "'longkeyid' is mandatory for longkeyid" if value.nil?
    end
  end

  newproperty(:content) do
    validate do |value|
      raise Puppet::Error, "'content' is mandatory for gpg_keyring_key" if value.nil?
      raise Puppet::Error, "'content' must be a PGP public key" unless provider.valid_public_key?(value)
    end

    # Ignore 'Version' header when comparing keys
    def insync?(is)
      remove_version_header(is) == remove_version_header(should)
    end

    def remove_version_header(key)
      lines = key.split("\n")
      lines.map! { |line| line unless line =~ %r{^Version} }
      lines.join("\n")
    end
  end

  newproperty(:trust) do
  end
end
