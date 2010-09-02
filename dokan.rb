#!/usr/bin/ruby
# -*- coding: utf-8 -*-
#
# The Dokan is a command line Twitter poster.
#
# Copyright (c) 2010 Takuo Kitame <kitame@debian.org>
# License: Ruby's
#
#
require 'time'
require 'oauth'
require 'pstore'
require 'optparse'
require 'json'
require 'readline'
require 'hmac'

DOKAN_VERSION = "2.0"

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

module Net
  class HTTPResponse
    def each_line( rs = "\n" )
      stream_check
      while line = @socket.readuntil( rs )
        yield line
      end
      self
    end
  end
end

class Dokan
  CONSUMER_KEY="Lk9wVIWctgYK5eWwC9Texg"
  CONSUMER_SEC="ZlR9oVd03qlhqnKvEO7QqN7rbjhEXptKUfqzOu3bY4"
  TWEET_URL = "https://api.twitter.com/1/statuses/update.json"
  STREAM_URL = "https://betastream.twitter.com/2b/user.json"
  BITLY_API = "http://api.bit.ly/v3/shorten?"
  BITLY_LOGIN = "dokan"
  BITLY_KEY   = "R_885043b52ca063cc775c95acc9594a5e"
  DOKAN_FILE = File.join( ENV['HOME'], ".dokanrc.db" )

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
  end

  private
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

  def bitly( url )
    return url if url.size <= 21
    encoded = URI::encode( url, URI::REGEXP::PATTERN::RESERVED + "#" )
    params = {
      "login" => BITLY_LOGIN,
      "apiKey" => BITLY_KEY,
      "longUrl" => encoded
    }.map do |k, v| "#{k}=#{v}" end.join( "&" )
    u = URI::parse( BITLY_API + params )
    http = Net::HTTP.new( u.host )
    res = http.get( u.request_uri )
    if res.code == "200"
      json = JSON::parse( res.body )
      return json['data']['url'] if json['status_code'] == 200
    end
    url
  end
 
  public 
  def post( source )
    text = source.dup
    text = text.encode( "UTF-8" ) unless text.encoding == Encoding::UTF_8
    uris = URI::extract( text )
    uris.each do |uri|
      suri = bitly( uri )
      text.gsub!( uri, suri )
    end
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

  def post_edit
    text = ""
    prompt = "> "
    while line = Readline.readline( prompt )
      break if /^$/ =~ line
      text << line
      prompt = ""
    end
    if text.empty?
      print "\n>> Canceld.\n"
      return
    end
    print ">> Posting... "
    ret = post( text )
    return if ret.nil?
    print " HTTP:#{ret.code} #{ret.message}\n"
  end

  def pipe
    text = STDIN.read
    post( text ) unless text.empty?
  end

  def unescape( text )
    text.gsub( /&(amp|quot|gt|lt);/u ) do
      match = $1.dup
      case match
      when 'amp'  then '&'
      when 'quot' then '"'
      when 'gt'   then '>'
      when 'lt'   then '<'
      else
        "&#{match};"
      end
    end unless text.nil? || text.empty?
  end

  def stream
    puts "Streaming."
    u = URI::parse( STREAM_URL )
    http = http_new( u )
    request = Net::HTTP::Post.new( u.request_uri )
    #request.set_form_data( { "replies" => "all" } )
    request.oauth!( http, @consumer, @access )
    begin
      http.request( request ) do |res|
        res.each_line( "\r\n" ) do |line|
          json = JSON::parse( line ) rescue next
          if json['user'] and json['text']
            time = Time.parse( json['created_at'] ).strftime("%H:%M:%S")
            source = json['source'].gsub(/<[^>]+>/, '')
            if json['retweeted_status']
              rtsource = json['retweeted_status']['source'].gsub(/<[^>]+>/, '')
              rttime = Time.parse( json['retweeted_status']['created_at'] )
              now = Time.now
              if rttime.year != now.year && rttime.month != now.month && rttime.day != now.day
                timestr = rttime.strftime("%m/%d %H:%M:%S")
              else 
                timestr = rttime.strftime("%H:%M:%S")
              end
              puts "[@#{json['retweeted_status']['user']['screen_name']} at #{timestr} from #{source}]"
              puts unescape( json['retweeted_status']['text'] )
              puts "   (RT by @#{json['user']['screen_name']} at #{time} from #{source})"
            else
              puts "[@#{json['user']['screen_name']} at #{time.to_s} from #{source}]"
              puts unescape( json['text'] )
            end
            puts "-" * 74
          elsif json['event'] == "list_member_removed"
            puts "** Removed from: #{json['target_object']['full_name']}"
            puts "-" * 74
          elsif json['event'] == "list_member_added"
            puts "** Added to: #{json['target_object']['full_name']}"
            puts "-" * 74
          else
            puts "** Unhandled event: #{json['event']}"
            puts "-" * 74
          end
        end
      end
    ensure
      http.finish
    end
  end
end

## __MAIN__

## command line options
opt = Hash.new
opt[:auth]    = false
opt[:user]    = nil
opt[:default] = false
opt[:extreme] = false
opt[:stream]  = false

opts = OptionParser.new
opts.on( "-a", "--auth",nil, "Authentication via OAuth") { opt[:auth] = true }
opts.on( "-u", "--user=user", String, "Username for Twitter" ) { |v| opt[:user] = v }
opts.on( "-d", "--default", nil, "Set as default user, or show current default user" ) { |v| opt[:default] = true }
opts.on( "-e", "--extreme", nil, "Enable extreme mode. Don't use with command line pipe.") { opt[:extreme] = true }
opts.on( "-s", "--stream", nil, "Get timeline via user stream" ) { opt[:stream] = true }
opts.version = DOKAN_VERSION
opts.program_name = "dokan"
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
  if opt[:stream]
    dokan.stream
    exit
  end
  if ARGV.size > 0
    dokan.post( ARGV.first )
  elsif opt[:default] or opt[:auth]
    exit
  elsif opt[:extreme] and STDIN.tty?
    print ">> Extreme mode is enabled. Post with empty line or EOF, exit with ^C.\n"
    loop do
      dokan.post_edit
    end
  elsif STDIN.tty?
    dokan.post_edit
  else
    dokan.pipe
  end
rescue
  print "Error: #{$!.to_s}\n"
  exit 1
end
