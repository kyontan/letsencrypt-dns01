require_relative 'core'

require 'fileutils'
require 'date'

class Letsencrypt::Dns01::BIND9
  def initialize(cfg)
    @serial = Date.today.strftime('%Y%m%d00').to_i
    @core = Letsencrypt::Dns01::Core.new(cfg)
  end

  def update
    # add token and update serial
    @core.authorize do |v|
      update_zonefile(v)
    end

    @serial
  end

  def update_zonefile(token = '')
    filename = @core.zone[:zonefile]
    content = File.read(filename)
    # update serial
    content.sub!(/^\s+(\d+)\s*\;\s*serial$/i) do |_m|
      @serial = [Regexp.last_match(1).to_i + 1, @serial].max
      $&.sub(/\d+/, @serial.to_s)
    end
    # delete old token
    content.sub!(/^\; token area$.*\z/im) do |_m|
      "; token area\n"
    end
    # add new token
    content += token

    # write zonefile
    File.write(filename, content)

    # reload name server
    @core.zone[:command].each { |c| system(c) } if @core.zone[:command]
  end
end

if $PROGRAM_NAME == __FILE__
  Letsencrypt::Dns01::BIND9.new(
    name: 'example.com',
    zonefile: 'spec/data/example.com.zone',
    nameserver: ['203.0.113.0'],
    domains: [
      'example.com',
      'www.example.com'
    ],
    authkey: 'spec/data/key/example.com.pem',
    certdir: 'spec/data/example.com',
    logfile: 'spec/data/letsencrypt_example.com.log',
    commands: [
      # 'service nsd restart',
      # 'nginx -s reload',
    ],
    endpoint: 'https://acme-staging.api.letsencrypt.org',
    mail: 'hogehoge@hotmail.com'
  ).update
end
__END__
