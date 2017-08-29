#!/usr/bin/env lua

local socket = require('socket')

local whois = {}

local _server = {
	-- discovery
	iana = { host = 'whois.iana.org', port = 43 },
	-- ip address registrar
	ripe = { host = 'whois.ripe.net', port = 43 },
	-- local domain registrar
	de = { host = 'whois.denic.de', port = 43, args = '-T dn', parser = _parseDomain }
}

local _parseDomain = function(str)
        local obj = {
		generic = {}
	}
	local category = 'generic'
	for line in string.gmatch(str, '[^\r\n]+') do
		if string.match(line, '^%[') then
			category = string.sub(line, 2, line:len() - 1)
			obj[category] = {}
		end
		if string.match(line, '^%a') then
			local padding = string.find(line, ':')
			local key = string.sub(line, 0, padding - 1)
			local value = string.sub(line, padding + 2)
			obj[category][key] = value
		end
	end
	return obj
end

local _parse = function(str, provider)
	if (_server[provider] or {}).parser then
		return _server[provider].parser(str)
	else
		return str
	end
end

function whois.domain(self, domain)
	local padding = string.find(domain, '%.')
	local tld = ''
	if padding then
		tld = string.sub(domain, padding + 1)
	end
	if tld then
		if not _server[tld] then tld = 'iana' end
		return whois:query(tld, domain)
	end
	return nil
end

function whois.query(self, provider, resource)
	if _server[provider] then
		local tcp = socket.tcp()
		tcp:connect(_server[provider].host, _server[provider].port)
		if _server[provider].args then
			query = _server[provider].args .. ' ' .. resource
		else
			query = resource
		end
		tcp:send(query .. '\r\n')
		local response = tcp:receive('*a')
		tcp:close()
		return _parse(response, provider)
	end
	return nil
end

return whois
