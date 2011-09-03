#!/usr/bin/ruby
# -*- coding: utf-8 -*-
#
# The Dokan is a command line Twitter poster.
#
# Copyright (c) 2011 Takuo Kitame <kitame@debian.org>
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
require 'json'
require 'readline'
require 'hmac'
require 'nkf'
require 'thread'

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

class Time
  def today?
    today = Time.now
    self.year == today.year && self.month == today.month && self.day == today.day
  end
end

class Dokan
  CONSUMER_KEY="n3ffbB9xTNuiEmJPFjehQ"
  CONSUMER_SEC="18t3QnB6KsueaSjMsZwI4pW6DZXiBw0RnvTuysDw40"
  TWEET_URL = "https://api.twitter.com/1/statuses/update.json"
  STREAM_URL = "https://userstream.twitter.com/2/user.json"
#  GOOGL_SHORTEN = "http://goo.gl/api/shorten"
  GOOGL_SHORTEN = "http://ga.vg/api/shorten"
  BITLY_API = "http://api.bit.ly/v3/shorten?"
  BITLY_LOGIN = "dokan"
  BITLY_KEY   = "R_885043b52ca063cc775c95acc9594a5e"
  DOKAN_FILE = File.join( ENV['HOME'], ".dokanrc.db" )

  class Color
    BLACK   = "30"
    RED     = "31"
    GREEN   = "32"
    YELLOW  = "33"
    BLUE    = "34"
    MAGENTA = "35"
    CYAN    = "36"
    GRAY    = "37"
  end

  Tweet = Struct.new( :user, :status_id, :text )

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
    @stalker = opt[:stalker]
    if @access_token.nil? and ! opt[:auth] and opt[:user]
      auth( consumer, opt[:user] )
    end
    @tags = opt[:tags]
    @color = opt[:color]
    @ignores = Regexp.new( opt[:ignores].join("|"), Regexp::IGNORECASE ) if opt[:ignores].size > 0
    @ignore_users = opt[:ignore_users]
    @friends = []
    @userdb = {}
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
    end
    http
  end

  def get_access_token( consumer, user, pass )
    rt = consumer.get_request_token()
    u = URI::parse rt.authorize_url
    http =  http_new( u, false )
    http.use_ssl = true
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
      if lines[i] =~ /<code>(\d+)/
        pin = $1
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
  def post( source )
    text = source.dup
    text = NKF::nkf('-w', text )
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

  def post_edit
    text = ""
    if @tags.size > 0
      prompt = @tags.map do |x| "##{x}" end.join( ',' ) + "> "
    else
      prompt = "> "
    end
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

  def format_text( tweet, rtby = nil )
    entities = tweet['entities']
    user = tweet['user']
    text = ""
    time = Time.parse( tweet['created_at'] )
    source = tweet['source'].gsub(/<[^>]+>/, '')

    if tweet['retweeted_status']
      rt = "  (RT by " + decorate( "@#{user['screen_name']}",  :underline=>true, :color=>  Color::GREEN ) + " at #{time.strftime("%H:%M:%S")} from #{source})\n"
      text = format_text( tweet['retweeted_status'], rt )
      return text
    end

    if time.today?
      timestr = time.strftime("%H:%M:%S")
    else 
      timestr = time.strftime("%m/%d %H:%M:%S")
    end
    if @friends.include?( user['id'] )
      text += "[[ " + decorate( "#{user['screen_name']}", :underline=>true,  :bold=>true, :color => Color::GREEN ) +  " at #{timestr} from #{source} ]]\n"
    else
      text += "<< " + decorate( "#{user['screen_name']}", :underline=>true,  :bold=>true, :color => Color::GREEN ) +  " at #{timestr} from #{source} >>\n"
    end
    text += decorate_text( unescape( tweet['text'] ), entities )
    text += "\n"

    permalink = "(%s) http://twitter.com/%s/status/%d" % [ @user, user['screen_name'], tweet['id'] ]
    permalink = sprintf("%74s", permalink)
    text += decorate( permalink, :color=>Color::GRAY )
    text += "\n"
    text += rtby if rtby
    text
  end

  def stream
    print "Start streaming for #{@user}.\n"
    u = URI::parse( STREAM_URL )
    http = http_new( u )
    request = Net::HTTP::Post.new( u.request_uri )
    request.set_form_data( { "replies" => "all" } ) if @stalker
    request.oauth!( http, @consumer, @access )
    begin
      buf = ''
      http.request( request ) do |res|
        raise RuntimeError, "Error on HTTP HTTP:#{res.code} #{res.to_s}" if res.code.to_i != 200
        res.read_body do |str|
          buf << str
          buf.gsub!( /[\s\S]+?\r\n/ ) do |chunk|
            json = JSON::parse( chunk )
            next unless json.kind_of?(Hash)
            if json['user']
              @userdb[json['user']['id']] = json['user'] if !@userdb.key?(json['user']['id'])
            end
            if json['user'] and json['text']
              next if @ignores and @ignores =~ json['text']
              next if @ignore_users.include?( json['user']['screen_name'] )
              t = Tweet.new
              t.user = json['user']['screen_name']
              t.text = format_text( json )
              t.status_id = json['id']
              $gqueue.push t
            elsif json['event'] == "list_member_removed"
              print "#{@user} ** Removed from: #{json['target_object']['full_name']}\n" +
                    ("-" * 74) + "\n"
            elsif json['event'] == "list_member_added"
              print "#{@user} ** Added to: #{json['target_object']['full_name']}\n" +
                    ("-" * 74) + "\n"
            elsif json['event'] == 'follow'
              if json['source']['screen_name'] == @user
                @friends.push json['target']['id']
              end
            elsif json['event'] == 'favorite' or json['event'] == 'unfavorite'
              target = json['target_object']
              user = json['source']['screen_name']
              string_data = "** %s %ss \n %s" % [ user, json['event'], target['text'] ]
              permalink = "http://twitter.com/%s/status/%d" % [ target['user']['screen_name'], target['id'] ]
              permalink = sprintf("%74s", permalink)
              string_data << decorate( permalink, :color=>Color::GRAY )
              print string_data + "\n" + ("-" * 74) + "\n" 
            elsif json['friends']
              @friends = json['friends']
            elsif json['delete'] && json['delete']['status']
              uid = json['delete']['status']['user_id']
              sid = json['delete']['status']['id']
              if @userdb[uid]
                uid = @userdb[uid]['screen_name']
              end
              print "** Deleted: http://twitter.com/%s/status/%s \n" % [ uid, sid ]
              print ("-" * 74) + "\n"
            else
              print "** Unhandled event: #{json['event']}" +
                    ("-" * 74) + "\n"
            end
            nil
          end
        end
      end
    rescue
      puts $!.to_s
      puts $!.backtrace.join("\n")
    ensure
      http.finish
    end
  end

  # experimental
  def decorate( string, params = {} )
    return string unless @color
    reset = "\033[0m"
    params = { :bold => false, :underline => false, :blink => false, :reverse => false }.update( params )
    res = "\033["
    code = []
    code << "1" if params[:bold]
    code << "4" if params[:underline]
    code << "5" if params[:blink]
    code << "7" if params[:reverse]
    code << params[:color] if params[:color]
    res += code.join(";") + "m" + string + reset
    res
  end

  def decorate_text( text, ent )
    res = text
    if ent
      ent['user_mentions'].each do |m|
        u = m['screen_name']
        if u == @user
          dec = decorate( "@#{u}", :underline=>true, :color=>Color::RED)
        else
          dec = decorate( "@#{u}", :underline=>true )
        end
        res.gsub!(/@#{u}/, dec )
      end
      ent['urls'].each do |url|
        u = url['url']
        dec = decorate( u, :underline => true, :color=>Color::CYAN )
        res.gsub!(/#{u}/, dec )
      end
      ent['hashtags'].each do |h|
        tag = h['text']
        dec = decorate( "##{tag}", :color=>Color::YELLOW )
        res.gsub!(/##{tag}/, dec)
      end
    end
    res.gsub!(/([RQ]T)/, decorate('\1', :bold=>true))
    return res
  rescue
    puts $!
    return text
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
opt[:stalker] = false
opt[:color]   = false
opt[:tags]    = Array.new
opt[:ignores] = Array.new
opt[:ignore_users] = Array.new

opts = OptionParser.new
opts.on( "-a", "--auth",nil, "Authentication via OAuth") { opt[:auth] = true }
opts.on( "-u", "--user=user", String, "Username for Twitter" ) { |v| opt[:user] = v }
opts.on( "-d", "--default", nil, "Set as default user, or show current default user" ) { |v| opt[:default] = true }
opts.on( "-e", "--extreme", nil, "Enable extreme mode. Don't use with command line pipe.") { opt[:extreme] = true }
opts.on( "-t", "--tags=tag,tag...", Array, "Insert hashtag automatically. Comma-Separated values. (w/o `#')" ) { |v| opt[:tags] = v }
opts.on( "-s", "--stream", nil, "Get timeline via user stream" ) { opt[:stream] = true }
opts.on( "-i", "--ignore=word,word...", Array, "Ignore keywords (NG word)" ) { |v| opt[:ignores] = v }
opts.on( "-I", "--ignore-user=user,user...", Array, "Ignore users" ) { |v| opt[:ignore_users] = v }
opts.on( "-c", "--color", nil, "Colorize stream text") { opt[:color] = true }
opts.on( "-x", "--stalker", nil, "Stalking mode. All replies will be shown on stream.") { opt[:stalker] = true }
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

$gqueue = Queue.new

accounts = opt[:user].split(',')
Thread.abort_on_exception = true
## run program
begin
  if opt[:stream]
    accounts.each do |user|
      account = opt.dup
      account[:user] = user
      dokan = Dokan.new( account )
      Thread.new do
        dokan.stream
      end
    end 
    dupcache = []
    while true
       data = $gqueue.pop
       next if dupcache.include?(data.status_id)
       dupcache.push data.status_id
       print data.text +
       ("-" * 74) + "\n"
       if dupcache.size > 100
         dupcache.shift
       end
    end
  else
    dokan = Dokan.new( opt )
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
