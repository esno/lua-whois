# lua-whois

## dependencies

    luarocks install luasocket
    
## example

    local whois = require('whois')
    whois:query('iana', 'example.org')
    whois:domain('example.org')
    
returns `nil` or a `table` containing all data
