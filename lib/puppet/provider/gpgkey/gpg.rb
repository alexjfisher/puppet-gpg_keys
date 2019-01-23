require 'tempfile'

Puppet::Type.type(:gpgkey).provide(:gpg) do
  commands gpg: 'gpg'

  mk_resource_methods

  # Class methods

  def self.instances
    get_list_of_keys.collect do |key|
      key_properties = get_key_properties(key)
      new(key_properties)
    end
  end

  def self.prefetch(resources)
    # Due to the way composite namevars have been used, the resource title might not be of the form 'user/keyid'
    # We need our own logic to match the catalog resource to the resources this provider has discovered on the system.
    instances.each do |prov|
      resource = resources.select do | k,v |
        v.original_parameters[:longkeyid] == prov.longkeyid && v.original_parameters[:user] == prov.user
      end
      resource.values[0].provider = prov unless resource.size != 1
    end
  end

  def self.gpg_cmd(user, *args)
    resolved_executable = Puppet::Util.which('gpg')
    raise Puppet::MissingCommand, format(_("Command #{name} is missing"), name: @name) if resolved_executable.nil?
    command = [resolved_executable] + ['--homedir', '~/.gnupg', '--batch'] + args
    Puppet::Util::Execution.execute(command, failonfail: true, combine: true, uid: user)
  end

  def self.get_list_of_keys
    keys = []
    users_with_keyrings.each do |user|
      output = gpg_cmd(user,['--list-keys', '--with-colons'])
      public_keys = output.split("\n").sort.grep(%r{^pub})
      key_ids = public_keys.map { |key| key.split(':')[4] }
      key_ids.each do |key|
        keys << { user: user, key_id: key }
      end
    end
    keys
  end

  def self.users_with_keyrings
    users = []
    File.open('/etc/passwd') do |f|
      f.each_line do |line|
        user = line.split(":")
        account = user[0]
        uid     = user[2].to_i
        home    = user[5]
        next unless File.file?("#{home}/.gnupg/pubring.gpg")
        next unless File.stat("#{home}/.gnupg/pubring.gpg").uid  == uid
        users << account
      end
    end
    Puppet.debug "Found #{users.size} users with gpg keyrings"
    users
  end

  def self.get_key_properties(key)
    key_properties = {}
    key_properties[:ensure]     = :present
    key_properties[:name]       = "#{key[:user]}/#{key[:key_id]}"
    key_properties[:provider]   = :gpg
    key_properties[:user]       = key[:user]
    key_properties[:longkeyid]  = key[:key_id]
    key_properties[:public_key] = export_public_key(key[:user], key[:key_id])
    key_properties[:secret_key] = export_secret_key(key[:user], key[:key_id])
    key_properties[:trust]      = trust(key[:user], key[:key_id])
    key_properties
  end

  def self.fingerprint(user,key)
    Puppet.debug("Getting fingerprint of key id #{user}/#{key}")
    output = gpg_cmd(user,['--fingerprint', '--with-colons', key])
    fingerprint_line = output.split("\n").sort.grep(%r{^fpr}).first
    fingerprint_line.split(':')[9]
  end

  def self.has_secret_key?(user,key)
    output = gpg_cmd(user, ['--list-secret-keys', '--with-colons'])
    output.include? key
  end

  def self.export_public_key(user, key)
    output = gpg_cmd(user, ['--export', '--armor', key])
    raise Puppet::Error, 'Exported key invalid' unless valid_public_key?(output)
    output
  end

  def self.export_secret_key(user, key)
    return nil unless has_secret_key?(user, key)
    output = gpg_cmd(user, ['--export-secret-key', '--armor', key])
    raise Puppet::Error, 'Exported key invalid' unless valid_secret_key?(output)
    output
  end

  def self.valid_public_key?(key)
    return false if key.split("\n").first !~ %r{-----BEGIN PGP PUBLIC KEY BLOCK-----}
    return false if key.split("\n").last  !~ %r{-----END PGP PUBLIC KEY BLOCK-----}
    Puppet.debug('public key looks valid')
    true
  end

  def self.valid_secret_key?(key)
    return false if key.split("\n").first !~ %r{-----BEGIN PGP PRIVATE KEY BLOCK-----}
    return false if key.split("\n").last  !~ %r{-----END PGP PRIVATE KEY BLOCK-----}
    Puppet.debug('secret key looks valid')
    true
  end

  def self.trust(user,key)
    trust = export_owner_trust(user,key)[fingerprint(user,key)]
    return 'unknown' if trust.nil?
    trust
  end

  def self.export_owner_trust(user,key)
    owner_trust = {}
    Puppet.debug "Exporting owner trust for #{user}/#{key}"
    output = gpg_cmd(user, ['--export-ownertrust'])
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

  def self.truststring(value)
    key = trustmap.key(value)
    raise Puppet::Error, 'Unrecognised trust value' if key.nil?
    key
  end

  def self.trustvalue(str)
    raise Puppet::Error, 'Unrecognised trust string' unless trustmap.key?(str)
    trustmap[str]
  end

  def self.trustmap
    {
      undefined: 2,
      none:      3,
      marginal:  4,
      full:      5,
      ultimate:  6
    }
  end

  # Instance methods
  def initialize(value={})
    super(value)
    @property_flush = {}
  end

  def trust=(value)
    @property_flush[:trust] = value
  end

  def public_key=(value)
    @property_flush[:public_key] = value
  end

  def secret_key=(value)
    @property_flush[:secret_key] = value
  end

  def exists?
    @property_hash[:ensure] == :present
  end

  def create
    @property_flush[:ensure] = :present
  end

  def destroy
    @property_flush[:ensure] = :absent
  end

  def flush
    # flush is called whenever there is at least one property that needs updating

    if @property_flush[:ensure] == :absent
      delete_key
      @property_hash.clear
      return
    end

    if @property_flush[:ensure] == :present
      # The key didn't exist previously
      create_key
    else
      replace_key unless @property_flush[:public_key].nil? && @property_flush[:secret_key].nil?
    end

    set_trust unless @property_flush[:trust].nil?
    @property_hash = self.class.get_key_properties(user: resource[:user], key_id: resource[:longkeyid])
  end

  def gpg_cmd(*args)
    self.class.gpg_cmd(resource[:user], args)
  end

  def fingerprint
    self.class.fingerprint(resource[:user],resource[:longkeyid])
  end

  def create_key
    raise Puppet::Error, "'public_key' is mandatory when creating a gpgkey" unless resource[:public_key]
    import_key(resource[:public_key])
    import_key(resource[:secret_key]) if resource[:secret_key]
    set_trust unless resource[:trust].nil?
  end

  def delete_key
    Puppet.debug "Deleting key #{resource[:longkeyid]}"
    if @property_hash[:secret_key]
      output = gpg_cmd(['--yes', '--delete-secret-key', fingerprint])
      Puppet.debug output
    end
    output = gpg_cmd ['--yes', '--delete-key', resource[:longkeyid] ]
    Puppet.debug output
  end

  def replace_key
    Puppet.debug "Replacing gpg key #{resource[:longkeyid]} for user #{resource[:user]}"
    delete_key
    create_key
  end

  def import_key(key)
    keyfile = Tempfile.new('key')

    if is_secret_key? key
      Puppet.debug "Importing secret key #{resource[:longkeyid]}"
      keyfile.write(resource[:secret_key])
    else
      Puppet.debug "Importing public key #{resource[:longkeyid]}"
      keyfile.write(resource[:public_key])
    end

    keyfile.close
    FileUtils.chmod 'a+r', keyfile.path

    output = gpg_cmd(['--import', keyfile.path])
    Puppet.debug output
    keyfile.unlink
  end

  def is_secret_key?(key)
    return true if key.include? 'PRIVATE'
    false
  end

  def set_trust
    Puppet.debug("Setting trust of #{resource[:longkeyid]} to #{resource[:trust]}")
    trustfile = Tempfile.new('trust')
    trustfile.write("#{fingerprint}:#{self.class.trustvalue(resource[:trust])}:\n")
    trustfile.close
    FileUtils.chmod 'a+r', trustfile.path
    output = gpg_cmd(['--import-ownertrust', trustfile.path])
    Puppet.debug output
    trustfile.unlink
  end

end
