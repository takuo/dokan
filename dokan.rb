#!/usr/bin/ruby
# -*- coding: utf-8 -*-
#
# The Dokan is a command line Twitter poster.
#
# Copyright (c) 2010 Takuo Kitame <kitame@debian.org>
# License: Ruby's
#
#
require 'oauth'
require 'pstore'
require 'optparse'

DOKAN_VERSION = "1.0"

# oAuth fix for >= 1.9.0
if RUBY_VERSION >= "1.9.0"
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
  CONSUMER_KEY="Lk9wVIWctgYK5eWwC9Texg"
  CONSUMER_SEC="ZlR9oVd03qlhqnKvEO7QqN7rbjhEXptKUfqzOu3bY4"
  TWEET_URL = "https://api.twitter.com/1/statuses/update.json"
  DOKAN_FILE = File.join( ENV['HOME'], ".dokanrc.db" )

  # new
  def initialize( opt )
    params = { :site => "https://api.twitter.com" }
    consumer = OAuth::Consumer.new( CONSUMER_KEY, CONSUMER_SEC, params )
    @db = PStore.new( DOKAN_FILE )
    auth( consumer, opt[:user] ) if opt[:auth] and opt[:user]
    default( opt[:user] ) if opt[:default] and opt[:user]
    loadconf( consumer )
  end

  def loadconf( consumer )
    @db.transaction do
      @user = @db[:default_user]
      raise RuntimeError, "Default user was not found!" unless @user
      token = @db[:tokens][@user][:access_token]
      secret = @db[:tokens][@user][:access_token_secret]
      if token and secret
        @access_token = OAuth::AccessToken.new( consumer, token, secret )
      end
    end
  end
  
  def default(user)
    @db.transaction do
      @db[:default_user] = user
    end
    @user = user
    print "#{@user} has been set as Default user.\n"
  end

  # proxy does not implement yet
  def http_new( uri, use_proxy = true )
    Net::HTTP.new( uri.host, uri.port )
  end

  def get_access_token( consumer, user, pass )
    rt = consumer.get_request_token()
    u = URI::parse rt.authorize_url
    http =  http_new( u, false )
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    req = Net::HTTP::Post.new(u.request_uri)
    res = http.request(req)
    raise RuntimeError, "HTTP: #{res.code}" if res.code != "200"
    at = ot = nil
    res.body.split(/\n/).each do |line|
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
          "submit=Allow" ].join("&")
    u = URI::parse( "https://api.twitter.com/oauth/authorize" ) 
    http = http_new( u, false )
    http.use_ssl = true
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    res = http.post(u.request_uri, query)
    raise RuntimeError, "HTTP: #{res.code}" if res.code != "200"
    pin = nil
    lines = res.body.split(/\n/)
    i = 0
    while i < lines.size
      if lines[i] =~ /oauth_pin/
        pin = lines[i+1].chomp.strip
        break
      end
      i+=1;
    end
    if pin
      token = rt.get_access_token( :oauth_verifier => pin ) 
    end 
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
    # puts "ACCESS_TOKEN=\"#{at.token}\""
    # puts "ACCESS_TOKEN_SEC=\"#{at.secret}\""

    @db.transaction do
      @db[:default_user] = user unless @db.root?( :default_user )
      @db[:tokens] = Hash.new unless @db.root?( :tokens )
      @db[:tokens][user] = { :access_token => @access_token.token,
                            :access_token_secret => @access_token.secret }
    end
    File.chmod( 0600, DOKAN_FILE )
  end
  
  def post( text )
    ret = @access_token.post( TWEET_URL, { :status => text.encode("UTF-8") } )
    raise RuntimeError, "Failed to post with error: HTTP/#{ret.code}" if ret.code != "200"
  end
  
end

## __MAIN__

## command line options
opt = Hash.new
opt[:auth] = false
opt[:user] = nil
opt[:default] = false

opts = OptionParser.new
opts.on( "-a", "--auth",nil, "Authentication via OAuth") { opt[:auth] = true }
opts.on( "-u", "--user=user", String, "Username for Twitter" ) { |v| opt[:user] = v }
opts.on( "-d", "--default", nil, "Set as default user" ) { |v| opt[:default] = true }
opts.version = DOKAN_VERSION
opts.program_name = "dokan"
opts.parse!( ARGV )

## option validation
if opt[:user].nil? and (opt[:default] == true || opt[:auth] == true)
  puts "Username must be specified!!"
  exit 1
end

## run program
begin
  dokan = Dokan.new( opt )
  dokan.post( ARGV.first ) if ARGV.size > 0
rescue
  print "Error: #{$!.to_s}"
  exit 1
end
