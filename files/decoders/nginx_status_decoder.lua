--[[

Parses a payload containing the contents of the output from the Nginx `stub_status`
module. See: http://nginx.org/en/docs/http/ngx_http_stub_status_module.html

Config:

- payload_keep (bool, optional, default false)
    Always preserve the original log line in the message payload.

*Example Heka Configuration*

.. code-block:: ini

    [HttpInput]
    url = "http://127.0.0.1:8000/_status"
    ticker_interval = 5
    decoder = "NginxStatusDecoder"

    [NginxStatusDecoder]
    type = "SandboxDecoder"
    filename = "lua_decoders/nginx_status.lua"

*Example Heka Message*

:Timestamp: 2014-11-11 22:13:52 +0000 UTC
:Type: stats.nginx
:Hostname: ip-10-80-155-196
:Pid: 0
:Uuid: 9a129dd8-98dc-4e98-a60f-b27e01c4d653
:Logger: http://127.0.0.1:8000/_status
:Payload:
:EnvVersion:
:Severity: 6
:Fields:
    | name:"Requests" type:double value:237
    | name:"Waiting" type:double value:0
    | name:"Active" type:double value:1
    | name:"Reading" type:double value:0
    | name:"Writing" type:double value:1
    | name:"Handled" type:double value:203
    | name:"Accepted" type:double value:203

--]]

local l = require 'lpeg'
l.locale(l)

local l = require 'lpeg'
l.locale(l)

num = l.digit^1 / tonumber
nonspace = l.C((l.P(1)-l.space)^1)

nginxstatus = l.P('Active connections: ') *
    l.Cg(num, 'Active') * l.space^1 *
    l.P("server accepts handled requests") * l.space^1 *
    l.Cg(num, 'Accepted') * l.space^1 *
    l.Cg(num, 'Handled') * l.space^1 *
    l.Cg(num, 'Requests') * l.space^1 *
    l.P('Reading:')  * l.space^1 *
    l.Cg(num, 'Reading') * l.space^1 *
    l.P('Writing:')  * l.space^1 *
    l.Cg(num, 'Writing') * l.space^1 *
    l.P('Waiting:')  * l.space^1 *
    l.Cg(num, 'Waiting')

grammar = l.Ct(nginxstatus)

local payload_keep = read_config("payload_keep")

local msg = {
    Type = "stats.nginx",
    Payload = nil,
    Fields = nil
}

function process_message()
    local data = read_message("Payload")
    msg.Fields = grammar:match(data)

    if not msg.Fields then
        return -1
    end

    if payload_keep then
        msg.Payload = data
    end

    msg.Fields.FilePath = read_message("Fields[FilePath]")
    inject_message(msg)
    return 0
end
