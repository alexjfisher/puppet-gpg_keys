Puppet::Type.newtype(:gpg_secret_key) do
  ensurable do
    defaultvalues
    defaultto :present
  end

  validate do
    raise Puppet::Error, "'user' is mandatory for gpg_secret_key" unless self[:user]
    raise Puppet::Error, "'longkeyid' is mandatory for gpg_secret_key" unless self[:longkeyid]
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
  end

  newparam(:longkeyid) do
  end

  newproperty(:content) do
    validate do |value|
      raise Puppet::Error, "'content' must be a PGP private key" unless provider.valid_secret_key?(value)
    end

    # Ignore 'Version' header when comparing keys
    def insync?(is)
      remove_version_header(is.gsub(/^$\n/, '')) == remove_version_header(should.gsub(/^$\n/, ''))
    end

    def remove_version_header(key)
      lines = key.split("\n")
      lines.map! { |line| line unless line =~ %r{^Version} }
      lines.join("\n")
    end
  end
end
