require 'net/http'
require 'test/unit'

require_relative '../lib/akamai/authtoken'


# export TEST_MODE=LOCAL
if ENV['TEST_MODE'] == 'LOCAL'
    require_relative 'secrets'
else
    AT_HOSTNAME = ENV['AT_HOSTNAME']
    AT_ENCRYPTION_KEY = ENV['AT_ENCRYPTION_KEY']
    AT_TRANSITION_KEY = ENV['AT_TRANSITION_KEY']
    AT_SALT = ENV['AT_SALT']
end
DEFAULT_WINDOW_SECONDS = 500


class TestAuthToken < Test::Unit::TestCase
    def setup
        # Test for Query String
        @at = Akamai::AuthToken.new(**{key: AT_ENCRYPTION_KEY,
                                   window_seconds: DEFAULT_WINDOW_SECONDS})
        
        # Test for Cookie
        @cat = Akamai::AuthToken.new(**{key: AT_ENCRYPTION_KEY, 
                                    algorithm: 'sha1', 
                                    window_seconds: DEFAULT_WINDOW_SECONDS})

        # Test for Header
        @hat = Akamai::AuthToken.new(**{key: AT_ENCRYPTION_KEY, 
                                    algorithm: 'md5', 
                                    window_seconds: DEFAULT_WINDOW_SECONDS})
    end

    def _token_setting(ttype, escape_early, transition)
        t = nil
        if ttype == 'q'
            t = @at
        elsif ttype == 'c'
            t = @cat
        elsif ttype == 'h'
            t = @hat
        end

        if transition
            t.key = AT_TRANSITION_KEY
        else
            t.key = AT_ENCRYPTION_KEY
        end

        t.escape_early = escape_early
    end

    def _queryAssertEqual(path, expacted, query: '', escape_early: false, transition: false,
                          payload: nil, session_id: nil, isUrl: true)
        _token_setting('q', escape_early, transition)
        
        if isUrl
            token = @at.generateToken(url: path, payload: nil, session_id: nil)
        else
            token = @at.generateToken(acl: path, payload: nil, session_id: nil)
        end
        
        uri = URI("http://#{AT_HOSTNAME}#{path}"\
                  "#{path.include?('?') ? '&' : '?' }#{@at.token_name}=#{token}")
        res = Net::HTTP.get_response(uri)
        assert_equal(expacted, res.code)
    end

    def _cookieAssertEqual(path, expacted, query: '', escape_early: false, transition: false,
                           payload: nil, session_id: nil, isUrl: true)
        _token_setting('c', escape_early, transition)
        if isUrl
            token = @cat.generateToken(url: path, payload: nil, session_id: nil)
        else
            token = @cat.generateToken(acl: path, payload: nil, session_id: nil)
        end

        uri = URI("http://#{AT_HOSTNAME}#{path}")
        http = Net::HTTP.new(uri.host, uri.port)
        req = Net::HTTP::Get.new(uri)
        req['Cookie'] = "#{@cat.token_name}=#{token}"
        res = http.request(req)
        assert_equal(expacted, res.code)
    end

    def _test_case_set(query_path, cookie_path, escape_early, isUrl)
        _queryAssertEqual(query_path, "404", escape_early: escape_early, isUrl: isUrl)
        _cookieAssertEqual(cookie_path, "404", escape_early: escape_early, isUrl: isUrl)
    end

    def test_url_escape_on__ignoreQuery_yes
        _test_case_set("/q_escape_ignore", "/c_escape_ignore", true, true)
    end
end