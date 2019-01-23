Puppet::Type.newtype(:gpgkey) do
  ensurable do
    defaultvalues
    defaultto :present
  end

  validate do
    raise Puppet::Error, "'user' is mandatory for gpgkey" unless self[:user]
    raise Puppet::Error, "'longkeyid' is mandatory for gpgkey" unless self[:longkeyid]
  end

  newparam(:name) do
    desc "The default namevar"
  end

  def self.title_patterns
    [
      [
        %r{^(([^/]+)/([^/]+))$},
        [
          [:name],
          [:user],
          [:longkeyid]
        ]
      ],
      [
        %r{(.*)},
        [
          [:name]
        ]
      ]
    ]
  end

  newparam(:user) do
    isnamevar
  end

  newparam(:longkeyid) do
    isnamevar
  end

  newproperty(:public_key) do
    validate do |value|
      raise Puppet::Error, "'public_key' must be a PGP public key" unless provider.class.valid_public_key?(value)
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

  newproperty(:secret_key) do
    # TODO: Support deleting secret keys
    validate do |value|
      raise Puppet::Error, "'secret_key' must be a PGP secret key" unless provider.class.valid_secret_key?(value)
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

  newproperty(:trust) do
    newvalues(:undefined, :none, :marginal, :full, :ultimate)
  end
end
