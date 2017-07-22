require_relative 'core'

require 'fileutils'
require 'date'
require 'ostruct'
require 'net/http'
require 'json'
require 'open-uri'

class GehirnDNS
  attr_accessor :base_uri, :token, :secret
  attr_accessor :logger

  def initialize(base_uri: "https://api.gis.gehirn.jp/dns/v1/", token: nil, secret: nil)
    @base_uri = ::URI.parse(base_uri)
    @token = token || ENV.fetch('GEHIRN_DNS_API_TOKEN')
    @secret = secret || ENV.fetch('GEHIRN_DNS_API_SECRET')
    @logger = nil
  end

  def get(endpoint)
    request klass: ::Net::HTTP::Get, endpoint: endpoint
  end

  def post(endpoint, body)
    request klass: ::Net::HTTP::Post, endpoint: endpoint, body: body
  end

  def put(endpoint, body)
    request klass: ::Net::HTTP::Put, endpoint: endpoint, body: body
  end

  def delete(endpoint)
    request klass: ::Net::HTTP::Delete, endpoint: endpoint
  end

  def zones
    get 'zones'
  end

  def zone(name:)
    zones.find{|z| z.name == name }
  rescue
    logger&.info("Can't retrieve zone: #{config_zone['name']}")
  end

  def records(name:)
    zone = zone(name: name)
    get("zones/#{zone.id}/versions/#{zone.current_version_id}/records")
  rescue
    logger&.info("Can't retrieve zone: #{config_zone['name']}")
  end

  def record(name:, host: '', type:)
    records(name: name).find{|r| r.name == fqdn(host, name) && r.type == type }
  end

  # NOTE: alias record isn't supported
  def add_records(name:, type:, host:, records:, override: false, ttl: nil)
    records = [records] if records.is_a? Hash

    z = zone(name: name)
    current_record = record(name: name, host: host, type: type)
    raise "alias record is not supported" if current_record&.enable_alias

    unless current_record
      new_record = {
        enable_alias: false,
        name: fqdn(host, name),
        ttl: ttl || 60,
        records: records,
        type: type
      }
      post "zones/#{z.id}/versions/#{z.current_version_id}/records", new_record
      return
    end

    if override
      current_record.records = records
    else
      current_record.records += records
    end

    current_record.ttl = ttl if ttl
    put "zones/#{z.id}/versions/#{z.current_version_id}/records/#{current_record.id}", current_record
  end

  # NOTE: alias record isn't supported
  def delete_records(name:, type:, host:, records:)
    records = [records] if records.is_a? Hash

    z = zone(name: name)
    current_record = record(name: name, host: host, type: type)
    raise "alias record is not supported" if current_record&.enable_alias

    current_record.records -= records
    puts "zones/#{z.id}/versions/#{z.current_version_id}/records/#{current_record.id}"
  end

  def clear_records(name:, type:, host:)
    z = zone(name: name)
    current_record = record(name: name, host: host, type: type)
    raise "alias record is not supported" if current_record&.enable_alias

    delete "zones/#{z.id}/versions/#{z.current_version_id}/records/#{current_record.id}"
  end

  private

  def fqdn(host, name)
    "#{host}.#{name}."
  end

  def http
    http = ::Net::HTTP.new(@base_uri.host, @base_uri.port)
    http.use_ssl = true
    http
  end

  def request(klass:, endpoint:, body: nil)
    body = body.to_h if body.is_a? OpenStruct
    body = body.to_json if body.is_a? Hash
    $stderr.puts "#{klass} #{@base_uri.path + endpoint}, #{body}"

    request = klass.new(@base_uri.path + endpoint)

    if body
      request.content_type = 'application/json'      
      request.body = body
    end

    request.basic_auth(token, secret)
    response = http.request(request)

    if response.code.to_i != 200
      if response.body
        raise "Failed to request. got #{response.code} description: #{JSON.parse(response.body)['message']}"
      else
        raise "Failed to request, got #{response.code}. couldn't access to server."
      end
    end

    parsed_response = JSON.parse(response.body)
    try_create_openstruct(parsed_response)
  end

  def try_create_openstruct(obj)
    case obj
    when Array
      obj.map{|x| try_create_openstruct(x) }
    when Hash
      OpenStruct.new(obj)
    else
      obj
    end
  end
end


class Letsencrypt::Dns01::GehirnDNS
  def initialize(cfg)
    @gehirn_dns = GehirnDNS.new(token: cfg[:token], secret: cfg[:secret])
    @core = Letsencrypt::Dns01::Core.new(cfg)
    @records = []
  end

  def update
    # add token and update serial
    @core.authorize do |record|
      $stderr.puts record

      if record.empty?
        clear_records
        next
      end
      match_data = record.match(/\A(?<fqdn>.*) IN (?<type>[A-Z]+) "(?<context>.*)"/)
      if match_data.nil?
        raise "#{record} can't parse as a record"
      end

      record_to_update = {
        fqdn: match_data[:fqdn],
        record_type: match_data[:type],
        context: match_data[:context]
      }
      
      update_zone(**record_to_update)
      @records << record_to_update
    end
  end

  def update_zone(fqdn:, record_type:, context:)
    $stderr.puts "Add: #{fqdn}, #{record_type}, #{context}"

    zone = @gehirn_dns.zones.select{|zone| fqdn.end_with?(zone.name + '.') }.max_by(&:length)
    raise "Can't found zone including #{fqdn}" unless zone

    host = fqdn.sub(/.#{Regexp.escape(zone.name)}.$/, '')

    records = [{ data: context }]
    @gehirn_dns.add_records(name: zone.name, type: record_type, host: host, records: records)
  end

  def clear_records
    @records.each do |record|
      fqdn = record[:fqdn]
      record_type = record[:record_type]
      context = record[:context]

      $stderr.puts "Delete: #{fqdn}, #{record_type}, #{context}"

      zone = @gehirn_dns.zones.select{|zone| fqdn.end_with?(zone.name + '.') }.max_by(&:length)
      raise "Can't found zone including #{fqdn}" unless zone

      host = fqdn.sub(/.#{Regexp.escape(zone.name)}.$/, '')
      records = [{ data: context }]

      @gehirn_dns.delete_records(name: zone.name, type: record_type, host: host, records: records)
    end

    @records = []
  end
end

if $PROGRAM_NAME == __FILE__
#   Letsencrypt::Dns01::GehirnDNS.new(
#     token: "GEHIRN_DNS_API_TOKEN",
#     secret: "GEHIRN_DNS_API_SECRET",
#     nameserver: ['ns2.gehirndns.jp'],
#     domains: [
#       'example.com',
#       'www.example.com'
#     ],
#     authkey: 'spec/data/key/example.com.pem',
#     certdir: 'spec/data/example.com',
#     logfile: 'spec/data/letsencrypt_example.com.log',
#     commands: [
#       # 'service nsd restart',
#       # 'nginx -s reload',
#     ],
#     endpoint: 'https://acme-staging.api.letsencrypt.org',
#     mail: 'hogehoge@hotmail.com'
#   ).update
end
__END__
