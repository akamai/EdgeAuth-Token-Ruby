# Copyright 2018 Akamai Technologies http://developer.akamai.com.

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
    class EdgeAuthError < Exception
        """Base-class for all exceptions raised by EdgeAuth Class"""
    end


    class EdgeAuth
        attr_accessor :token_type, :token_name, :key, :algorithm, :salt,
                :ip, :payload, :session_id, :start_time, :end_time, 
                :window_seconds, :field_delimiter, :acl_delimiter, 
                :escape_early, :verbose
        
        def initialize(token_type: nil, token_name: '__token__', 
                key: nil, algorithm: 'sha256', salt: nil,
                ip: nil, payload: nil, session_id: nil,
                start_time: nil, end_time: nil, window_seconds: nil, 
                field_delimiter: '~', acl_delimiter: '!', 
                escape_early: false, verbose: false)
            @token_type = token_type
            @token_name = token_name
            if !key || key.length <= 0
                raise EdgeAuthError, 
                    'You must provide a secret in order to generate a new token.'
            end
            @key = key
            @salt = salt
            @algorithm = algorithm
            @ip = ip
            @payload = payload
            @session_id = session_id
            @start_time = start_time
            @end_time = end_time
            @window_seconds = window_seconds
            @field_delimiter = field_delimiter
            @acl_delimiter = acl_delimiter
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

        def _generateToken(path, isUrl)
            start_time = @start_time
            end_time = @end_time

            if start_time.to_s.downcase == 'now'
                start_time = Time.new.getgm.to_i
            elsif start_time
                begin
                    if start_time <= 0
                        raise EdgeAuthError, 'start_time must be ( > 0 )'
                    end
                rescue
                    raise EdgeAuthError, 'start_time must be numeric or now'
                end
                
            end

            if end_time
                begin
                    if end_time <= 0
                        raise EdgeAuthError, 'end_time must be ( > 0 )'
                    end
                rescue
                    raise EdgeAuthError, 'end_time must be numeric'
                end
            end

            if @window_seconds
                begin
                    if @window_seconds <= 0
                        raise EdgeAuthError, 'window_seconds must be ( > 0 )'
                    end
                rescue
                    raise EdgeAuthError, 'window_seconds must be numeric'
                end
            end

            if !end_time
                if @window_seconds
                    if !start_time
                        end_time = Time.new.getgm.to_i + @window_seconds
                    else
                        end_time = start_time + @window_seconds
                    end
                else
                    raise EdgeAuthError, 'You must provide an expiration time or a duration window..'
                end
            end

            if start_time && end_time <= start_time
                raise EdgeAuthError, 'Token will have already expired.'
            end

            if @verbose
                puts "Akamai Token Generation Parameters"
                puts "Token Type      : #{@token_type}"
                puts "Token Name      : #{@token_name}"
                puts "Start Time      : #{start_time}"
                puts "End Time        : #{end_time}"
                puts "Window(seconds) : #{@window_seconds}"
                puts "IP              : #{@ip}"
                puts "URL/ACL         : #{path}"
                puts "Key/Secret      : #{@key}"
                puts "Payload         : #{@payload}"
                puts "Algo            : #{@algo}"
                puts "Salt            : #{@salt}"
                puts "Session ID      : #{@session_id}"
                puts "Field Delimiter : #{@field_delimiter}"
                puts "ACL Delimiter   : #{@acl_delimiter}"
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

            if !isUrl
                new_token.push('acl=%s' % path)
            end
            if session_id
                new_token.push('id=%s' % _escapeEarly(session_id))
            end
            if payload
               new_token.push('data=%s' % _escapeEarly(payload))
            end

            hash_code = new_token.clone
            
            if isUrl
                hash_code.push('url=%s' % _escapeEarly(path))
            end

            if @salt
                hash_code.push('salt=%s' % @salt)
            end
            if !(['sha256', 'sha1', 'md5'].include? @algorithm)
                raise EdgeAuthError, 'Unknown algorithm'
            end
            
            bin_key = Array(@key.gsub(/\s/,'')).pack("H*")
            digest = OpenSSL::Digest.new(@algorithm)
            token_hmac = OpenSSL::HMAC.new(bin_key, digest)
            token_hmac.update(hash_code.join(@field_delimiter))

            new_token.push('hmac=%s' % token_hmac)

            return new_token.join(@field_delimiter)
        end

        def generateACLToken(acl)
            if !acl
                raise EdgeAuthError, 'You must provide the ACL(s)'
            elsif acl.is_a?(Array)
                acl = acl.join(@acl_delimiter)
            end
            return _generateToken(acl, false)
        end

        def generateURLToken(url)
            if !url
                raise EdgeAuthError, 'You must provide a URL'
            end

            return _generateToken(url, true)
        end
    end
end