require 'resolv'
require 'logger'
require 'acme-client'
require 'fileutils'
require 'date'
# require 'mail'

# module Letsencrypt
#   module Dns01
#     # Your code goes here...
#   end
# end

class Letsencrypt::Dns01::Core
  Token = Struct.new(:domain, :challenge)
  attr_reader :zone, :log

  # initialize login to ACME server.
  # And it creates an authrization key file, if necessary.
  def initialize(zone = {})
    @zone = normalization(zone)
    @client = set_client
    @log = Logger.new(@zone[:logfile], 5, 1_024_000)
  end

  # authorize gets the authrization/verification token from the ACME server according to the domain list.
  # returns a number of verification.

  # rubocop:disable Metrics/MethodLength
  def authorize
    unless expire?
      @log.info 'skip update'
      @log.close
    end

    @log.info 'start update'
    updated_domains_count = @zone[:domain].reduce(0) do |sum, domain|
      @log.info "authorize #{sum}, #{domain}"

      # get challenge token
      authorization = @client.authorize(domain: domain)
      challenge = authorization.dns01

      # update DNS record
      yield %(#{challenge.record_name}.#{domain}. IN #{challenge.record_type} "#{challenge.record_content}"\n)

      # check DNS record
      dns = Resolv::DNS.new(nameserver: @zone[:nameserver])
      cname = "#{challenge.record_name}.#{domain}"
      ctxt = challenge.record_content
      @log.info "token #{sum}, #{ctxt}"

      loop do
        sleep 3
        ret = dns.getresources(cname, Resolv::DNS::Resource::IN::TXT)
        break if 0 < ret.size && ctxt == ret[0].data
      end

      verify_status = request_verification(challenge)
      @log.info "#{domain}: verify status: #{verify_status}"

      verify_status == 'valid' ? sum + 1 : sum
    end

    # delete DNS record
    yield ''

    # cartificate
    if updated_domains_count == @zone[:domain].size
      update_cert
    end

    @log.info 'complete update.'
  end
  # rubocop:enable Metrics/MethodLength

  # private

  def request_verification(challenge)
    challenge.request_verification

    sleep 5 while challenge.verify_status == 'pending'
    challenge.verify_status
  end

  def normalization(zone)
    zone[:endpoint] ||= 'https://acme-staging.api.letsencrypt.org'
    zone[:mail] ||= 'root@example.com'

    zone[:margin_days] ||= 30
    zone[:warning_days] ||= 7

    domains = zone[:domains] || zone[:domain]
    zone[:domain] = domains
    zone[:domain] = [domains] unless domains.instance_of?(Array)

    commands = zone[:commands] || zone[:command] || []
    zone[:command] = commands
    zone[:command] = [commands] unless commands.instance_of?(Array)

    zone[:certdir] ||= File.expand_path(File.dirname($PROGRAM_NAME))
    zone[:certname] ||= {}
    zone[:certname][:privkey] ||= 'privkey.pem'
    zone[:certname][:cert] ||= 'cert.pem'
    zone[:certname][:chain] ||= 'chain.pem'
    zone[:certname][:fullchain] ||= 'fullchain.pem'

    zone[:logfile] ||= STDOUT

    zone
  end

  def set_client
    filename = @zone[:authkey]
    if File.exist?(filename)
      key = OpenSSL::PKey::RSA.new(File.read(filename))
      return Acme::Client.new(private_key: key, endpoint: @zone[:endpoint])
    end
    key = OpenSSL::PKey::RSA.new(4096)
    cli = Acme::Client.new(private_key: key, endpoint: @zone[:endpoint])
    registration = cli.register(contact: "mailto:#{@zone[:mail]}")
    registration.agree_terms
    FileUtils.mkdir_p(File.dirname(filename))
    File.write(filename, key.to_pem)
    File.chmod(0400, filename)
    cli
  end

  # update_cert updates/create some certification files under serial dir.
  def update_cert(serial: nil)
    serial ||= Time.now.strftime('%Y%m%d%H%M%S')
    @log.info "update_cert #{serial}"
    rcsr = { names: @zone[:domain] }
    rcsr[:common_name] = @zone[:domain][0] if @zone[:domain].size > 1
    csr = Acme::Client::CertificateRequest.new(rcsr)
    certificate = @client.new_certificate(csr)

    cdir = @zone[:certdir] + '/current'
    rdir = @zone[:certdir] + "/#{serial}/"

    FileUtils.mkdir_p(rdir)

    File.write(rdir + @zone[:certname][:privkey], certificate.request.private_key.to_pem)
    File.write(rdir + @zone[:certname][:cert], certificate.to_pem)
    File.write(rdir + @zone[:certname][:chain], certificate.chain_to_pem)
    File.write(rdir + @zone[:certname][:fullchain], certificate.fullchain_to_pem)

    FileUtils.rm(cdir, force: true)
    FileUtils.ln_s(rdir.chop, cdir, force: true)
  end

  # expire? check rest days by the current public key .
  # return true if no file or file is expired.
  def expire?
    fname = @zone[:certdir] + '/current/' + @zone[:certname][:cert]
    return true unless File.exist?(fname)

    cert = OpenSSL::X509::Certificate.new(File.read(fname))
    rest = cert.not_after - Time.now
    return false if rest > (@zone[:margin_days] * 24 * 60 * 60)
    true
  end
end
