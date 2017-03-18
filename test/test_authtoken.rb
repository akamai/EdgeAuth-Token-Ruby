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

    def _queryAssertEqual(path, expacted, escape_early: false, transition: false,
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

    def _cookieAssertEqual(path, expacted, escape_early: false, transition: false,
                           payload: nil, session_id: nil, isUrl: true)
        _token_setting('c', escape_early, transition)
        if isUrl
            token = @cat.generateToken(url: path, payload: nil, session_id: nil)
        else
            token = @cat.generateToken(acl: path, payload: nil, session_id: nil)
        end

        uri = URI("http://#{AT_HOSTNAME}#{path}")
        http = Net::HTTP.new(uri.host)
        req = Net::HTTP::Get.new(uri)
        req['Cookie'] = "#{@cat.token_name}=#{token}"
        res = http.request(req)
        assert_equal(expacted, res.code)
    end

    def _headerAssertEqual(path, expacted, escape_early: false, transition: false,
                           payload: nil, session_id: nil, isUrl: true)
        _token_setting('h', escape_early, transition)
        if isUrl
            token = @hat.generateToken(url: path, payload: nil, session_id: nil)
        else
            token = @hat.generateToken(acl: path, payload: nil, session_id: nil)
        end

        uri = URI("http://#{AT_HOSTNAME}#{path}")
        http = Net::HTTP.new(uri.host)
        req = Net::HTTP::Get.new(uri)
        req[@hat.token_name] = token
        res = http.request(req)
        assert_equal(expacted, res.code)
    end

    def _test_case_set(query_path, cookie_path, header_path, escape_early, isUrl)
        _queryAssertEqual(query_path, "404", escape_early: escape_early, isUrl: isUrl)
        _cookieAssertEqual(cookie_path, "404", escape_early: escape_early, isUrl: isUrl)
        _headerAssertEqual(header_path, "404", escape_early: escape_early, isUrl: isUrl)

        if isUrl
            query_string="?foo=bar&hello=world"
            _queryAssertEqual(query_path + query_string, "403", escape_early: (false==escape_early), isUrl: isUrl)
            _cookieAssertEqual(cookie_path + query_string, "403", escape_early: (false==escape_early), isUrl: isUrl)
            _headerAssertEqual(header_path + query_string, "403", escape_early: (false==escape_early), isUrl: isUrl)
        end

        # Transition Key Test
        _queryAssertEqual(query_path, "404", transition: true, escape_early: escape_early, isUrl: isUrl)
        _cookieAssertEqual(cookie_path, "404", transition: true, escape_early: escape_early, isUrl: isUrl)
        _headerAssertEqual(header_path, "404", transition: true, escape_early: escape_early, isUrl: isUrl)

        # Payload Test
        _queryAssertEqual(query_path, "404", payload: 'SOME_PAYLOAD_DATA', escape_early: escape_early, isUrl: isUrl)
        _cookieAssertEqual(cookie_path, "404", payload: 'SOME_PAYLOAD_DATA', escape_early: escape_early, isUrl: isUrl)
        _headerAssertEqual(header_path, "404", payload: 'SOME_PAYLOAD_DATA', escape_early: escape_early, isUrl: isUrl)

        # Session Id Test
        _queryAssertEqual(query_path, "404", session_id: 'SOME_SESSION_ID_DATA', escape_early: escape_early, isUrl: isUrl)
        _cookieAssertEqual(cookie_path, "404", session_id: 'SOME_SESSION_ID_DATA', escape_early: escape_early, isUrl: isUrl)
        _headerAssertEqual(header_path, "404", session_id: 'SOME_SESSION_ID_DATA', escape_early: escape_early, isUrl: isUrl)
    end

    ##########
    # URL TEST
    ##########
    def test_url_escape_on__ignoreQuery_yes
        _test_case_set("/q_escape_ignore", "/c_escape_ignore", "/h_escape_ignore", true, true)
    end

    def test_url_escape_off__ignoreQuery_yes
        _test_case_set("/q_ignore", "/c_ignore", "/h_ignore", false, true)
    end

    def test_url_escape_on__ignoreQuery_no
        query_path = "/q_escape"
        cookie_path = "/c_escape"
        header_path = "/h_escape"
        _test_case_set(query_path, cookie_path, header_path, true, true)

        query_string="?foo=bar&hello=world"
        _queryAssertEqual(query_path + query_string, "404", escape_early: true, isUrl: true)
        _cookieAssertEqual(cookie_path + query_string, "404", escape_early: true, isUrl: true)
        _headerAssertEqual(header_path + query_string, "404", escape_early: true, isUrl: true)
    end

    def test_url_escape_off__ignoreQuery_no
        query_path = "/q"
        cookie_path = "/c"
        header_path = "/h"
        _test_case_set(query_path, cookie_path, header_path, false, true)
        
        query_string="?foo=bar&hello=world"
        _queryAssertEqual(query_path + query_string, "404", escape_early: false, isUrl: true)
        _cookieAssertEqual(cookie_path + query_string, "404", escape_early: false, isUrl: true)
        _headerAssertEqual(header_path + query_string, "404", escape_early: false, isUrl: true)
    end
    
    def test_url_query_escape_on__ignore_yes_with_salt
        query_salt_path = "/salt"
        ats = Akamai::AuthToken.new(key: AT_ENCRYPTION_KEY, salt: AT_SALT, window_seconds: DEFAULT_WINDOW_SECONDS, escape_early: true)
        token = ats.generateToken(url: query_salt_path)
        uri = URI("http://#{AT_HOSTNAME}#{query_salt_path}?#{ats.token_name}=#{token}")
        res = Net::HTTP.get_response(uri)
        assert_equal("404", res.code)
    end
    ##########

    ##########
    # ACL TEST
    ##########
    def test_acl_escape_on__ignoreQuery_yes
        _test_case_set("/q_escape_ignore", "/c_escape_ignore", "/h_escape_ignore", false, false)
    end

    def test_acl_escape_off__ignoreQuery_yes
        _test_case_set("/q_ignore", "/c_ignore", "/h_ignore", false, false)
    end

    def test_acl_escape_on__ignoreQuery_no
        _test_case_set("/q_escape", "/c_escape", "/h_escape", false, false)
    end

    def test_acl_escape_off__ignoreQuery_no
        _test_case_set("/q", "/c", "/h", false, false)
    end
    
    def test_acl_asta_escape_on__ignoreQuery_yes
        ats = Akamai::AuthToken.new(key: AT_ENCRYPTION_KEY, window_seconds: DEFAULT_WINDOW_SECONDS, escape_early: false)
        token = ats.generateToken(acl: '/q_escape_ignore/*')
        uri = URI("http://#{AT_HOSTNAME}/q_escape_ignore/hello?#{ats.token_name}=#{token}")
        res = Net::HTTP.get_response(uri)
        assert_equal("404", res.code)
    end

    def test_acl_deli_escape_on__ignoreQuery_yes
        ats = Akamai::AuthToken.new(key: AT_ENCRYPTION_KEY, window_seconds: DEFAULT_WINDOW_SECONDS, escape_early: false)
        acl = ["/q_escape_ignore", "/q_escape_ignore/*"]
        token = ats.generateToken(acl: acl.join(Akamai::AuthToken.ACL_DELIMITER))
        uri = URI("http://#{AT_HOSTNAME}/q_escape_ignore?#{ats.token_name}=#{token}")
        res = Net::HTTP.get_response(uri)
        assert_equal("404", res.code)

        uri = URI("http://#{AT_HOSTNAME}/q_escape_ignore/world/?#{ats.token_name}=#{token}")
        res = Net::HTTP.get_response(uri)
        assert_equal("404", res.code)
    end
    ##########

    def test_times
        att = Akamai::AuthToken.new(key: AT_ENCRYPTION_KEY, window_seconds: DEFAULT_WINDOW_SECONDS)
        # start_time
        assert_raise Akamai::AuthTokenError do
            att.generateToken(start_time: -1)
        end
        assert_raise Akamai::AuthTokenError do
            att.generateToken(start_time: 'hello')
        end

        # end_time
        assert_raise Akamai::AuthTokenError do
            att.generateToken(end_time: -1)
        end
        assert_raise Akamai::AuthTokenError do
            att.generateToken(end_time: 'hello')
        end

        # window_seconds
        assert_raise Akamai::AuthTokenError do
            att.generateToken(window_seconds: -1)
        end
        assert_raise Akamai::AuthTokenError do
            att.generateToken(window_seconds: 'hello')
        end
    end
end