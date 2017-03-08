# Akamai-AuthToken: Akamai Authorization for Ruby

Akamai-AuthToken is Akamai Authorization Token in the HTTP Cookie, Query String and Header for a client.
You can configure it in the Property Manager at https://control.akamai.com.
It's a behavior which is Auth Token 2.0 Verification.  

Akamai-AuthToken supports Ruby 2.0+. (This is Akamai unofficial code)


## Installation

To install Akamai Authorization Token for Ruby:  

```Shell
    $ gem install akamai-authtoken
```
  
  
## Example

```ruby
    require 'net/http' # Just for this Example
    require 'akamai/authtoken'

    AA_HOSTNAME = 'auth-token.akamaized.net'
    AA_ENCRYPTION_KEY = 'YourEncryptionKey' 
    DURATION = 500 # seconds
```
AA_ENCRYPTION_KEY must be hexadecimal digit string with even-length.  
Don't expose AA_ENCRYPTION_KEY on the public repository.  


#### URL parameter option

```ruby
    path = "/akamai/authtoken"
    
    # 1) Cookie
    at = Akamai::AuthToken.new(key: AT_ENCRYPTION_KEY, 
        window_seconds: DEFAULT_WINDOW_SECONDS, 
        escape_early: true)
    token = at.generateToken(url: path)
    url = "http://#{AA_HOSTNAME}#{path}"
    
    http = Net::HTTP.new(uri.host)
    req = Net::HTTP::Get.new(uri)
    req['Cookie'] = "#{at.token_name}=#{token}"
    res = http.request(req)
    p res # [<#Net::HTTPOK 200 OK readbody=true>]
    
    # 2) Query string
    at = Akamai::AuthToken.new(key: AT_ENCRYPTION_KEY, 
        window_seconds: DEFAULT_WINDOW_SECONDS, 
        escape_early: true)
    token = at.generateToken(url: path)
    url = URI("http://#{AA_HOSTNAME}#{path}#{at.token_name}=#{token}")
    res = Net::HTTP.get_response(uri)
    p res
```
It depends on turning on/off 'Escape token input' in the property manager. (on => escape_early: True / off => escape_early: false)  
In [Example 2], it's only okay for 'Ignore query string' option on in the property manager.  
If you want to 'Ignore query string' off using query string as your token, Please contact your Akamai representative.  


## Usage

#### AuthToken Class

```ruby
class AuthToken
    def initialize(token_type: nil, token_name: '__token__', key: nil,
                algorithm: 'sha256', salt: nil, start_time: nil, end_time: nil,
                window_seconds: nil, field_delimiter: '~', acl_delimiter: '!',
                escape_early: false, verbose: false)
```

| Parameter       | Description                                                                                        |
|-----------------|----------------------------------------------------------------------------------------------------|
| token_type      | Select a preset. (Not Supported Yet)                                                               |
| token_name      | Parameter name for the new token. [Default: __token__]                                             |
| key             | Secret required to generate the token. It must be hexadecimal digit string with even-length.       |
| algorithm       | Algorithm to use to generate the token. (sha1, sha256, or md5) [Default:sha256]                    |
| salt            | Additional data validated by the token but NOT included in the token body. (It will be deprecated) |
| start_time      | What is the start time? (Use string 'now' for the current time)                                    |
| end_time        | When does this token expire? 'end_time' overrides 'window_seconds'                                 |
| window_seconds  | How long is this token valid for?                                                                  |
| field_delimiter | Character used to delimit token body fields. [Default: ~]                                          |
| acl_delimiter   | Character used to delimit acl fields. [Default: !]                                                 |
| escape_early    | Causes strings to be 'url' encoded before being used.                                              |
| verbose         | Print all parameters.                                                                              |


#### AuthToken's Method

```ruby

generateToken(url: nil, acl: nil, start_time: nil, end_time: nil, 
    window_seconds: nil, ip: nil, payload: nil, session_id: nil)

# Returns the authorization token string.
```

| Parameter      | Description                                                                                             |
|----------------|-----------------------------------------------------------------------------------------------|
| url            | Single URL path.                                                                                        |
| acl            | Access control list delimited by ! [ie. /\*]                                                            |
| start_time     |                                                                                                         |
| end_time       | Same as Authtoken's variables, but they overrides Authtoken's.                                          |
| window_seconds |                                                                                                         |
| ip             | IP Address to restrict this token to. (Troublesome in many cases (roaming, NAT, etc) so not often used) |
| payload        | Additional text added to the calculated digest.                                                         |
| session_id     | The session identifier for single use tokens or other advanced cases.                                   |


## License

Copyright 2017 Akamai Technologies, Inc.  All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at `<http://www.apache.org/licenses/LICENSE-2.0>`_.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.