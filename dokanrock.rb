#!/usr/bin/ruby
# -*- coding: utf-8 -*-
#
# The Dokanrock is utility script for TvRock based on Dokan.
# The Dokan is a command line Twitter poster.
#
# Copyright (c) 2010 Takuo Kitame <kitame@debian.org>
# License: Ruby's
#
#
require 'time'
begin
  require 'oauth'
rescue LoadError
  require 'rubygems'
  require 'oauth'
end
require 'pstore'
require 'optparse'
require 'hmac'
require 'nkf'

DOKAN_VERSION = "4.0"

# oAuth fix for >= 1.9.0
if RUBY_VERSION >= "1.9.0" and HMAC::VERSION < "0.4.0"
  module HMAC
    class Base
      def set_key(key)
        key = @algorithm.digest(key) if key.size > @block_size
        key_xor_ipad = Array.new(@block_size, 0x36)
        key_xor_opad = Array.new(@block_size, 0x5c)
        key.bytes.each_with_index do |value, index|
          key_xor_ipad[index] ^= value
          key_xor_opad[index] ^= value
        end
        @key_xor_ipad = key_xor_ipad.pack('c*')
        @key_xor_opad = key_xor_opad.pack('c*')
        @md = @algorithm.new
        @initialized = true
      end
    end
  end
end

class Dokan
  CONSUMER_KEY="n3ffbB9xTNuiEmJPFjehQ"
  CONSUMER_SEC="18t3QnB6KsueaSjMsZwI4pW6DZXiBw0RnvTuysDw40"
  TWEET_URL = "https://api.twitter.com/1/statuses/update.json"
  GOOGL_SHORTEN = "http://goo.gl/api/shorten"
  DOKAN_FILE = File.join( ENV['HOME'], ".dokanrc.db" )
  SEARCH = {
    :START => "録画開始", :END => "録画終了"
  }

  # new
  def initialize( opt )
    params = { :site => "https://api.twitter.com" }
    consumer = OAuth::Consumer.new( CONSUMER_KEY, CONSUMER_SEC, params )
    @consumer = consumer
    @db = PStore.new( DOKAN_FILE )
    auth( consumer, opt[:user] ) if opt[:auth] and opt[:user]
    default( opt[:user] ) if opt[:default]
    @user = opt[:user] if opt[:user]
    loadconf( consumer )
    if @access_token.nil? and ! opt[:auth] and opt[:user]
      auth( consumer, opt[:user] )
    end
    @tags = opt[:tags]
    @mode = opt[:mode]
    @title   = NKF.nkf( '-w', opt[:title] ) if opt[:title]
    @channel = NKF.nkf( '-w', opt[:channel] ) if opt[:channel]
    @time    = NKF.nkf( '-w', opt[:time] ) if opt[:time]
    @device  = opt[:device]
  end

  private
  def find_tvrock_log
    retval = nil
    IO::popen('reg QUERY HKCU\Software\TvRock /v DOCUMENT') do |reg|
      while reg.gets
        vals = $_.chomp.split( " ", 3 )
        if vals[0] == 'DOCUMENT'
          retval = File.join( vals[2], 'tvrock.log2' )
          break if File.exist?( retval )
          retval = File.join( vals[2], 'tvrock.log' )
          break if File.exist?( retval )
          retval = nil
          break
        end
      end
    end
    raise RuntimeError, "Could not find tvrock.log from registry!" unless retval
    return retval
  end

  def loadconf( consumer )
    @db.transaction do
      @db[:tokens] = Hash.new unless @db.root?( :tokens )
      @user = @db[:default_user] unless @user
      raise RuntimeError, "Default user was not found!" unless @user
      token = @db[:tokens][@user][:access_token] if @db[:tokens][@user]
      secret = @db[:tokens][@user][:access_token_secret] if @db[:tokens][@user]
      if token and secret
        @access_token = OAuth::AccessToken.new( consumer, token, secret )
        @access = OAuth::Token.new( token, secret )
      end
    end
  end
  
  def default( user = nil )
    @db.transaction do
      @db[:default_user] = user if user
      @user = @db[:default_user]
    end
    print "Current default user is: #{@user}\n"
  end

  # proxy is not implement yet
  def http_new( uri, use_proxy = true )
    http = Net::HTTP.new( uri.host, uri.port )
    if uri.scheme == 'https'
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end
    http
  end

  def get_access_token( consumer, user, pass )
    rt = consumer.get_request_token()
    u = URI::parse rt.authorize_url
    http =  http_new( u, false )
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    req = Net::HTTP::Post.new( u.request_uri )
    res = http.request( req )
    raise RuntimeError, "HTTP: #{res.code}" if res.code != "200"
    at = ot = nil
    res.body.split( /\n/ ).each do |line|
      if /name="authenticity_token" type="hidden" value="([^"]+)"/ =~ line
        at = $1
      end
      if /name="oauth_token" type="hidden" value="([^"]+)"/ =~ line
        ot = $1
      end
      break if at && ot
    end
    raise RuntimeError, "Could not get tokens" if at.nil? or ot.nil?
    query = [ "authenticity_token=#{at}",
          "oauth_token=#{ot}",
          "session[username_or_email]=#{user}",
          "session[password]=#{pass}",
          "submit=Allow" ].join( "&" )
    u = URI::parse( "https://api.twitter.com/oauth/authorize" ) 
    http = http_new( u, false )
    res = http.post( u.request_uri, query )
    raise RuntimeError, "HTTP: #{res.code}" if res.code != "200"
    pin = nil
    lines = res.body.split( /\n/ )
    i = 0
    while i < lines.size
      if lines[i] =~ /oauth_pin/
        pin = lines[i+1].chomp.strip
        break
      end
      i+=1;
    end
    token = rt.get_access_token( :oauth_verifier => pin ) if pin
    return token
  end

  def auth( consumer, user )
    print "Enter the password for #{user}: "
    revertstty = `stty -g` rescue nil
    `stty -echo` rescue nil
    pass = STDIN.gets.chomp.strip
    print "\n"
    `stty #{revertstty}` rescue nil  

    @access_token = get_access_token( consumer, user, pass )
    raise RuntimeError, "OAuth authentication was failed!" unless @access_token

    @db.transaction do
      @db[:default_user] = user unless @db.root?( :default_user )
      @db[:tokens] = Hash.new unless @db.root?( :tokens )
      @db[:tokens][user] = { :access_token => @access_token.token,
                            :access_token_secret => @access_token.secret }
    end
    File.chmod( 0600, DOKAN_FILE )
  end

  def googl( url )
    return url unless url.size > 20
    res = Net::HTTP.post_form( URI::parse( GOOGL_SHORTEN ), { :url => url} )
    if res.code == "200" or res.code == "201"
      json = JSON::parse( res.body )
      return json['short_url']
    end
    url
  end

  public
  def post( string )
    text = string.dup
    text = NKF::nkf( '-w', text )
    uris = URI::extract( text )
    uris.each do |uri|
      suri = googl( uri )
      text.gsub!( uri, suri )
    end
    text += @tags.map do |x| " ##{x}" end.join
    count = 0
    begin
      ret = @access_token.post( TWEET_URL, { :status => text } )
      raise RuntimeError, "Failed to post with error: HTTP/#{ret.code}" if ret.code != "200"
    rescue
      count += 1
      if count < 5
        sleep 3
        retry
      end
      raise $!
    ensure
      return ret
    end
  end

  def rock
    file = find_tvrock_log
    data = nil
    if @device
      search = /\[\d+\/\d+\/\d+ \d+:\d+:\d+ (\S+)\]:\[(#{@device})\]番組「#{Regexp.quote(@title)}」 #{SEARCH[@mode]} Card=\S+, Error=(\d+), Sig=([\d\.]+), Bitrate=([\d\.]+)Mbps, Drop=(\d+), Scrambling=(\d+), BcTimeDiff=([\d\.+-]+)sec, TimeAdj=([\d\.+-]+)sec, CPU_Weight=([\d\.]+%), FreeMem=(\S+), DiskFree=([\d\.]+%)/
    else
      search = /\[\d+\/\d+\/\d+ \d+:\d+:\d+ (\S+)\]:\[(\S+)\]番組「#{Regexp.quote(@title)}」 #{SEARCH[@mode]} Card=\S+, Error=(\d+), Sig=([\d\.]+), Bitrate=([\d\.]+)Mbps, Drop=(\d+), Scrambling=(\d+), BcTimeDiff=([\d\.+-]+)sec, TimeAdj=([\d\.+-]+)sec, CPU_Weight=([\d\.]+%), FreeMem=(\S+), DiskFree=([\d\.]+%)/
    end

    open( file ) do |fp|
      while line = fp.gets
        line =  NKF::nkf( '-w', line )
        if search =~ line
          data = "[%s]%s%s%s「%s」 [Er%s,Sg%s,Br%s,Dr%s,Sc%s,Td%s,Ta%s,TvRock V%s]" % [ $2, SEARCH[@mode], @time ? " #{@time} " : " ", @channel,@title,$3,$4,$5,$6,$7,$8,$9,$1 ]
          data.gsub!(/#/, '&#35;')
          break if File.extname( file ) == ".log2"
        end 
      end
    end 
    post( data ) if data
  end
end

## __MAIN__

## command line options
opt = Hash.new
opt[:auth]    = false
opt[:user]    = nil
opt[:default] = false
opt[:tags]    = Array.new
opt[:mode]    = nil
opt[:title]   = nil
opt[:channel] = ""
opt[:device]  = nil
opt[:time]    = nil

opts = OptionParser.new
opts.on( "-a", "--auth",nil, "Authentication via OAuth") { opt[:auth] = true }
opts.on( "-u", "--user=user", String, "Username for Twitter" ) { |v| opt[:user] = v }
opts.on( "-d", "--default", nil, "Set as default user, or show current default user" ) { |v| opt[:default] = true }
opts.on( "-t", "--tags=tag,tag...", Array, "Insert hashtag automatically. Comma-Separated values. (w/o `#')" ) { |v| opt[:tags] = v }
opts.on( "-s", "--start=title", String, "Start recording title (%d)" ) { |v| opt[:mode] = :START; opt[:title] = NKF.nkf( '-w', v ) }
opts.on( "-e", "--end=title", String, "End recording title (%d)" ) { |v| opt[:mode] = :END; opt[:title] = NKF.nkf( '-w', v ) }
opts.on( "-c", "--channel=channel", String, "Channel name (%5)" ) { |v| opt[:channel] = NKF.nkf( '-w', v ) }
opts.on( "-r", "--reserve=timestring", String, "Time string '[%i, %j %k-%l]'" ) { |v| opt[:time] = NKF.nkf( '-w', v ) }
opts.on( "-h", "--hardware=devicecode", String, "TvRock Device code (%h)") { |v| opt[:device] = v }
opts.version = DOKAN_VERSION
opts.program_name = "dokanrock"
opts.parse!( ARGV )

## option validation
if opt[:user].nil? and opt[:auth] == true
  print "Username must be specified!!\n"
  exit 1
end

Signal.trap(:INT) {
  exit
}
Signal.trap(:TERM) {
  exit
}

## run program
begin
  dokan = Dokan.new( opt )
  if opt[:mode] == :START or opt[:mode] == :END
    dokan.rock
  elsif ARGV.size > 0
    dokan.post( ARGV.first )
  elsif opt[:default] or opt[:auth]
    exit
  end
rescue
  print "Error: #{$!.to_s}\n"
  exit 1
end
