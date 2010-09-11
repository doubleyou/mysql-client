-module(mysql_connection).
-behaviour(gen_fsm).
-export([
	send_query/3,
	start_link/6
]).
-export([
	code_change/4,
	handle_event/3,
	handle_sync_event/4,
	handle_info/3,
	init/1,
	terminate/3
]).
-export([
	fields/2,
	header/2,
	idle/2,
	rows/2
]).

-record(state, {
	connector,
	sock,
	acc = [],
	fields = [],
	rows = [],
	caller_pid,
	callback_pid
}).

send_query(Pid, Query, CallbackPid) ->
	gen_fsm:send_event(Pid, {mysql_query, Query, CallbackPid}).

start_link(Host, Port, User, Password, DB, CallerPid) ->
	gen_fsm:start_link(?MODULE, [Host, Port, User, Password, DB, CallerPid], []).

init([Host, Port, User, Password, DB, CallerPid]) ->
	Connector = fun() ->
		{ok, S} = gen_tcp:connect(Host, Port, [binary, {packet, 0}]),
		ok = mysql_connect(S, iolist_to_binary(User), iolist_to_binary(Password), iolist_to_binary(DB)),
		S
	end,
	Sock = Connector(),
	State = #state{
		connector = Connector,
		sock = Sock,
		caller_pid = CallerPid
	},
	{ok, idle, State}.

idle({mysql_query, Query, CallbackPid}, State = #state { sock = Sock }) ->
	send(Sock, mysql_bin:query_packet(iolist_to_binary(Query))),
	?MODULE:header(recv, State#state{ callback_pid = CallbackPid, fields = [], rows = [], acc = [] }).

header(recv, State = #state{ acc = [] }) ->
	recv(header, State, <<>>);
header(parse, State = #state{ acc = [Header | Packets] }) ->
	case mysql_bin:parse_packet(Header, header) of
		{ok, _} -> finish(norows, State);
		{error, _} -> finish(error, State);
		_ -> fields(parse, State#state{ acc = Packets })
	end.

fields(parse, State = #state{ acc = [Chunk] }) ->
	recv(fields, State, Chunk);
fields(parse, State = #state{ acc = [H | T], fields = Fields }) ->
	case mysql_bin:parse_packet(H, field) of
		{field, Field} ->
			fields(parse, State#state{ acc = T, fields = [Field | Fields]});
		{eof, _} ->
			rows(parse, State#state{ acc = T, fields = lists:reverse(Fields) })
	end.

rows(parse, State = #state{ acc = [Chunk] }) ->
	recv(rows, State, Chunk);
rows(parse, State = #state{ acc = [H | T], rows = Rows }) ->
	case mysql_bin:parse_packet(H, row) of
		{row, Row} ->
			rows(parse, State#state{ acc = T, rows = [Row | Rows] });
		{eof, _} ->
			finish(rows, State)
	end.

finish(rows, State = #state{ caller_pid = CallerPid, callback_pid = CallbackPid, rows = Rows, fields = Fields }) ->
	CallerPid ! {connection_free, self()},
	CallbackPid ! {mysql_response, {Fields, Rows}},
	{next_state, idle, State};
finish(norows, State = #state{ caller_pid = CallerPid, callback_pid = CallbackPid }) ->
	CallerPid ! {connection_free, self()},
	CallbackPid ! {mysql_response, ok},
	{next_state, idle, State};
finish(error, State = #state{ caller_pid = CallerPid, callback_pid = CallbackPid }) ->
	CallerPid ! {connection_free, self()},
	CallbackPid ! {mysql_response, error},
	{next_state, idle, State}.

recv(StateName, State = #state{ connector = Connector, callback_pid = CallbackPid }, Acc) ->
	receive
		{tcp, _, Packet} ->
			WholePacket = <<Acc/binary,Packet/binary>>,
			{Packets, _} = mysql_bin:decode_packet(WholePacket),
			?MODULE:StateName(parse, State#state{ acc = Packets });
		{tcp_closed, _} ->
			io:format("Socket closed, reconnecting...~n"),
			CallbackPid ! error,
			{next_state, idle, State#state{ sock = Connector() }};
		{tcp_error, _, _Reason} ->
			io:format("TCP error, reconnecting...~n"),
			CallbackPid ! error,
			{next_state, idle, State#state{ sock = Connector() }}
	end.

handle_event(_Event, StateName, State) ->
	{next_state, StateName, State}.

handle_sync_event(_Event, _From, StateName, State) ->
	{next_state, StateName, State}.

handle_info(_Info, StateName, State) ->
	{next_state, StateName, State}.

code_change(_OldVsn, StateName, State, _Extra) ->
	{ok, StateName, State}.

terminate(_Reason, _StateName, _State) ->
	ok.

mysql_connect(Sock, User, Password, DB) ->
	receive
		{tcp, _, Packet} ->
			{[HSPacket, <<>>], SeqNum} = mysql_bin:decode_packet(Packet),
			{ServerCaps, ServerLang, ScrambleBuf} = mysql_bin:parse_handshake_packet(HSPacket),
			EncryptedPassword = mysql_bin:encrypt_password(Password, ScrambleBuf),
			send(Sock, mysql_bin:auth_packet(User, EncryptedPassword, DB, ServerCaps, ServerLang), SeqNum + 1),
			receive
				{tcp, _, Response} ->
					{[P, <<>>], _} = mysql_bin:decode_packet(Response),
					case mysql_bin:parse_packet(P) of
						{error, Err} ->
							io:format("Connection error: ~p~n", [Err]),
							error;
						{ok, _} ->
							ok
					end
			end
	end,
	ok.

send(Sock, Packet) ->
	send(Sock, Packet, 0).
send(Sock, Packet, SeqNum) ->
	gen_tcp:send(Sock, mysql_bin:encode_packet(iolist_to_binary(Packet), SeqNum)). 
