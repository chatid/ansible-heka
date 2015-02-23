--[[

Parses a payload containing the contents of a `cat /proc/net/dev | tail -n +3` call into a Heka
message.

Config:

- payload_keep (bool, optional, default false)
    Always preserve the original log line in the message payload.

*Example Heka Configuration*

.. code-block:: ini

    [net_stats_input]
    type = "ProcessInput"
    ticker_interval = 10
    decoder = "net_stats_decoder"

        [net_stats_input.command.0]
        bin = "/bin/cat"
        args = ["/proc/net/dev"]

        [net_stats_input.command.1]
        bin = "/usr/bin/tail"
        args = ["-n", "+3"]

    [net_stats_decoder]
    type = "SandboxDecoder"
    filename = "lua_decoders/linux_netstats.lua"

*Example Heka Message*

:Timestamp: 2014-11-13 00:02:00 +0000 UTC
:Type: stats.network
:Hostname: test.example.com
:Pid: 7367
:Uuid: 07e1d518-c619-44a5-a859-e2d70570c1b0
:Logger: net_stats_input
:Payload:
:EnvVersion:
:Severity: 7
:Fields:
    | name:"TransmitErrs" type:double value:0
    | name:"ReceivePackets" type:double value:1.371141e+06
    | name:"TransmitCarrier" type:double value:0
    | name:"TransmitPackets" type:double value:1.356754e+06
    | name:"ReceiveDrop" type:double value:0
    | name:"TransmitDrop" type:double value:0
    | name:"ReceiveFrame" type:double value:0
    | name:"TransmitCompressed" type:double value:0
    | name:"Interface" type:string value:"docker0"
    | name:"TransmitColls" type:double value:0
    | name:"ReceiveErrs" type:double value:0
    | name:"ReceiveFifo" type:double value:0
    | name:"TransmitFifo" type:double value:0
    | name:"ReceiveMulticast" type:double value:0
    | name:"ReceiveBytes" type:double value:1.62891849e+08
    | name:"TransmitBytes" type:double value:1.38906657e+08
    | name:"ReceiveCompressed" type:double value:0

--]]

local l = require 'lpeg'
l.locale(l)

local num = l.digit^1 / tonumber
local alphanumeric = l.C(l.R("AZ", "az", "09")^1)

local netstats = l.space^0 * l.Cg(alphanumeric, "Interface") * ":" *
    l.space^1 * l.Cg(num, "ReceiveBytes") *
    l.space^1 * l.Cg(num, "ReceivePackets") *
    l.space^1 * l.Cg(num, "ReceiveErrs") *
    l.space^1 * l.Cg(num, "ReceiveDrop") *
    l.space^1 * l.Cg(num, "ReceiveFifo") *
    l.space^1 * l.Cg(num, "ReceiveFrame") *
    l.space^1 * l.Cg(num, "ReceiveCompressed") *
    l.space^1 * l.Cg(num, "ReceiveMulticast") *
    l.space^1 * l.Cg(num, "TransmitBytes") *
    l.space^1 * l.Cg(num, "TransmitPackets") *
    l.space^1 * l.Cg(num, "TransmitErrs") *
    l.space^1 * l.Cg(num, "TransmitDrop") *
    l.space^1 * l.Cg(num, "TransmitFifo") *
    l.space^1 * l.Cg(num, "TransmitColls") *
    l.space^1 * l.Cg(num, "TransmitCarrier") *
    l.space^1 * l.Cg(num, "TransmitCompressed")

local grammar = l.Ct(netstats)

local payload_keep = read_config("payload_keep")

local msg = {
    Type = "stats.network",
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
