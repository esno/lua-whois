#!/usr/bin/env lua

local cjson = require('cjson')
local requests = require('requests')

local ripe = {
	url = {
		test = 'https://rest-test.db.ripe.net',
		prod = 'https://rest.db.ripe.net'
	}
}

function ripe.search(self, query)
	local headers = { Accept = 'application/json' }
	local response = requests.get{
		url = ripe.url.prod .. '/search?source=ripe&query-string=' .. query,
		headers = headers
	}
	local json = cjson.new()
	return (json.decode(response.text).objects or {}).object or nil
end

return ripe
