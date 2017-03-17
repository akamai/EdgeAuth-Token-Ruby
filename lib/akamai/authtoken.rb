# Copyright 2017 Akamai Technologies http://developer.akamai.com.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


require 'cgi'
require 'openssl'
require 'optparse'


ENV['TZ'] = 'GMT'


module Akamai
    class AuthTokenError < Exception
        """Base-class for all exceptions raised by AuthToken Class"""
    end


    class AuthToken
        attr_accessor :token_type, :token_name, :key, :algorithm, :salt, 
                :start_time, :end_time, :window_secondse, :field_delimiter, 
                :acl_delimiter, :escape_early, :verbose
        
        @@acl_delimiter = '!'
        def self.ACL_DELIMITER
            @@acl_delimiter
        end
        
        def initialize(token_type: nil, token_name: '__token__', key: nil,
                algorithm: 'sha256', salt: nil, start_time: nil, end_time: nil,
                window_seconds: nil, field_delimiter: '~', escape_early: false, verbose: false)

            @token_type = token_type
            @token_name = token_name
            @start_time = start_time
            @end_time = end_time
            @window_seconds = window_seconds
            if !key || key.length <= 0
                raise AuthTokenError, 
                    'You must provide a secret in order to generate a new token.'
            end
            @key = key
            @algorithm = algorithm
            @salt = salt
            @field_delimiter = field_delimiter
            @escape_early = escape_early
            @verbose = verbose
        end

        def _escapeEarly(text)
            if @escape_early
                return CGI::escape(text).gsub(/(%..)/) {$1.downcase}
            else
                return text
            end
        end

        def generateToken(url: nil, acl: nil, start_time: nil, end_time: nil, window_seconds: nil,
                        ip: nil, payload: nil, session_id: nil)
            
            if !start_time
                start_time = @start_time
            end
            if !end_time
                end_time = @end_time
            end
            if !window_seconds
                window_seconds = @window_seconds
            end

            if start_time.to_s.downcase == 'now'
                start_time = Time.new.getgm.to_i
            elsif start_time && !(start_time.is_a? Integer)
                raise AuthTokenError, 'start_time must be numeric or now'
            end

            if end_time && !(end_time.is_a? Integer)
                raise AuthTokenError, 'end_time must be numeric or now'
            end

            if window_seconds && !(window_seconds.is_a? Integer)
                raise AuthTokenError, 'window_seconds must be numeric or now'
            end

            if !end_time
                if window_seconds.to_i > 0
                    if !start_time
                        end_time = Time.new.getgm.to_i + window_seconds
                    else
                        end_time = start_time + window_seconds
                    end
                else
                    raise AuthTokenError, 'You must provide an expiration time or a duration window..'
                end
            end

            if start_time && end_time < start_time
                raise AuthTokenError, 'Token will have already expired.'
            end

            if (!acl && !url) || (acl && url)
                raise AuthTokenError, 'You must provide a URL or an ACL'
            end

            if @verbose
                puts "Akamai Token Generation Parameters"
                puts "Token Type      : #{@token_type}"
                puts "Token Name      : #{@token_name}"
                puts "Start Time      : #{start_time}"
                puts "End Time        : #{end_time}"
                puts "Window(seconds) : #{window_seconds}"
                puts "IP              : #{ip}"
                puts "URL             : #{url}"
                puts "ACL             : #{acl}"
                puts "Key/Secret      : #{@key}"
                puts "Payload         : #{payload}"
                puts "Algo            : #{@algo}"
                puts "Salt            : #{@salt}"
                puts "Session ID      : #{session_id}"
                puts "Field Delimiter : #{@field_delimiter}"
                puts "ACL Delimiter   : #{@@acl_delimiter}"
                puts "Escape Early    : #{@escape_early}"
            end

            hash_code = Array.new
            new_token = Array.new

            if ip
                new_token.push('ip=%s' % _escapeEarly(ip))
            end
            if start_time
                new_token.push('st=%s' % start_time)
            end
            new_token.push('exp=%s' % end_time)

            if acl
                new_token.push('acl=%s' % acl)
            end
            if session_id
                new_token.push('id=%s' % _escapeEarly(session_id))
            end
            if payload
               new_token.push('data=%s' % _escapeEarly(payload))
            end

            hash_code = new_token.clone
            
            if url and !acl
                hash_code.push('url=%s' % _escapeEarly(url))
            end

            if @salt
                hash_code.push('salt=%s' % @salt)
            end
            if !(['sha256', 'sha1', 'md5'].include? @algorithm)
                raise AuthTokenError, 'Unknown algorithm'
            end
            
            bin_key = Array(@key.gsub(/\s/,'')).pack("H*")
            digest = OpenSSL::Digest.new(@algorithm)
            token_hmac = OpenSSL::HMAC.new(bin_key, digest)
            token_hmac.update(hash_code.join(@field_delimiter))

            new_token.push('hmac=%s' % token_hmac)

            return new_token.join(@field_delimiter)
        end
    end
end