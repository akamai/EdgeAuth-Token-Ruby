# Akamai-EdgeAuth: Akamai Edge Authorization Token for Ruby

[![Gem Version](https://badge.fury.io/rb/akamai-edgeauth.svg)](https://badge.fury.io/rb/akamai-edgeauth)
[![Build Status](https://travis-ci.org/AstinCHOI/Akamai-EdgeAuth-Ruby.svg?branch=master)](https://travis-ci.org/AstinCHOI/Akamai-EdgeAuth-Ruby)
[![License](http://img.shields.io/:license-apache-blue.svg)](https://github.com/AstinCHOI/Akamai-EdgeAuth-Ruby/blob/master/LICENSE)

Akamai-EdgeAuth is Akamai Edge Authorization Token in the HTTP Cookie, Query String and Header for a client.
You can configure it in the Property Manager at https://control.akamai.com.
It's a behavior which is Auth Token 2.0 Verification.  

Akamai-EdgeAuth supports Ruby 2.0+. (This is Akamai unofficial code)

<div style="text-align:center"><img src=https://github.com/AstinCHOI/akamai-asset/blob/master/edgeauth/edgeauth.png?raw=true/></div>


## Installation

To install Akamai Edge Authorization Token for Ruby:  

```shell
$ gem install akamai-edgeauth
```
  

## Example

```ruby
require 'net/http' # Just for this Example
require 'akamai/edgeauth'

ET_HOSTNAME = 'edgeauth.akamaized.net'
ET_ENCRYPTION_KEY = 'YourEncryptionKey' 
DURATION = 500 # seconds
```
ET_ENCRYPTION_KEY must be hexadecimal digit string with even-length.  
Don't expose ET_ENCRYPTION_KEY on the public repository.  


#### URL parameter option

```ruby
path = "/akamai/edgeauth"

# 1) Cookie
et = Akamai::EdgeAuth.new(key: ET_ENCRYPTION_KEY, 
    window_seconds: DURATION, 
    escape_early: true)
token = et.generateToken(url: path)
uri = URI("http://#{ET_HOSTNAME}#{path}")

http = Net::HTTP.new(uri.host)
req = Net::HTTP::Get.new(uri)
req['Cookie'] = "#{et.token_name}=#{token}"
res = http.request(req)
p res # Maybe not 403

# 2) Query string
token = et.generateToken(url: path)
uri = URI("http://#{ET_HOSTNAME}#{path}#{et.token_name}=#{token}")
res = Net::HTTP.get_response(uri)
p res
```
It depends on turning on/off 'Escape token input' in the property manager. (on: [escape_early: True] / off: [escape_early: false])  
In [Example 2], it's only okay for 'Ignore query string' option on in the property manager.  
If you want to 'Ignore query string' off using query string as your token, Please contact your Akamai representative.  


#### ACL(Access Control List) parameter option

```ruby
# 1) Header using *
et = Akamai::EdgeAuth.new(key: ET_ENCRYPTION_KEY, window_seconds: DURATION)
token = et.generateToken(acl: "/akamai/edgeauth/list/*")
uri = URI("http://#{ET_HOSTNAME}/akamai/edgeauth/list/something")

http = Net::HTTP.new(uri.host)
req = Net::HTTP::Get.new(uri)
req[et.token_name] = token
res = http.request(req)
p res

# 2) Cookie Delimited by '!'
acl = ["/akamai/edgeauth", "/akamai/edgeauth/list/*"]
token = et.generateToken(acl: acl.join(Akamai::EdgeAuth.ACL_DELIMITER))
uri = URI("http://#{ET_HOSTNAME}/akamai/edgeauth/list/something2")
    # or URI("http://#{ET_HOSTNAME}/akamai/edgeauth")

http = Net::HTTP.new(uri.host)
req = Net::HTTP::Get.new(uri)
req['Cookie'] = "#{et.token_name}=#{token}"
res = http.request(req)
p res
```
It doesn't matter turning on/off 'Escape token input' in the property manager, but you should keep escape_early: false (Default)


## Usage

#### EdgeAuth Class

```ruby
class EdgeAuth
    def initialize(token_type: nil, token_name: '__token__', key: nil,
                algorithm: 'sha256', salt: nil, start_time: nil, end_time: nil,
                window_seconds: nil, field_delimiter: '~', escape_early: false, verbose: false)
```

| Parameter | Description |
|-----------|-------------|
| token_type | Select a preset. (Not Supported Yet) |
| token_name | Parameter name for the new token. [ Default: \_\_token\_\_ ] |
| key | Secret required to generate the token. It must be hexadecimal digit string with even-length. |
| algorithm  | Algorithm to use to generate the token. (sha1, sha256, or md5) [ Default:sha256 ] |
| salt | Additional data validated by the token but NOT included in the token body. (It will be deprecated) |
| start_time | What is the start time? (Use string 'now' for the current time) |
| end_time | When does this token expire? 'end_time' overrides 'window_seconds' |
| window_seconds | How long is this token valid for? |
| field_delimiter | Character used to delimit token body fields. [ Default: ~ ] |
| escape_early | Causes strings to be 'url' encoded before being used. |
| verbose | Print all parameters. |

#### EdgeAuth Static Variable

```ruby
ACL_DELIMITER = '!' # Character used to delimit acl fields.
```

#### EdgeAuth's Method

```ruby
def generateToken(url: nil, acl: nil, start_time: nil, end_time: nil, 
                window_seconds: nil, ip: nil, payload: nil, session_id: nil)

# Returns the authorization token string.
```

| Parameter | Description |
|-----------|-------------|
| url | Single URL path. |
| acl | Access control list delimited by ! [ ie. /\* ] |
| start_time <br/> end_time <br/> window_seconds | Same as Authtoken's parameters, but they overrides Authtoken's. |
| ip | IP Address to restrict this token to. (Troublesome in many cases (roaming, NAT, etc) so not often used) |
| payload | Additional text added to the calculated digest. |
| session_id | The session identifier for single use tokens or other advanced cases. |


## License

Copyright 2017 Akamai Technologies, Inc.  All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.