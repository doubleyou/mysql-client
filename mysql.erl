-module(mysql).
-behaviour(gen_server).
-export([
	start_link/1,
	start_link/6
]).
-export([
	code_change/3,
	handle_call/3,
	handle_cast/2,
	handle_info/2,
	init/1,
	terminate/2
]).
-export([
	do/3,
    do/4
]).

-record(state, {
	connector,
	connections = []
}).

-define(TIMEOUT, 10000).

do(Instance, Query, Options) ->
	do(Instance, Query, Options, ?TIMEOUT).

do(Instance, Query, Options, Timeout) ->
	gen_server:call(Instance, {mysql_query, Query}),
	Result = receive
		{mysql_response, Data} -> Data;
		error -> error
	after Timeout ->
		timeout
	end,
    case Result of
        {_, _} -> lists:foldl(
                        fun(Action, Acc) ->
                            format_response(Acc, Action)
                        end,
                    Result, Options);
        V -> V
    end.
	
start_link(InstanceName) ->
    start_link(InstanceName, cfg:get(mysql_host), cfg:get(mysql_port), cfg:get(mysql_user), cfg:get(mysql_password), cfg:get(list_to_atom("mysql_" ++ atom_to_list(InstanceName) ++ "_database"))).

start_link(InstanceName, Host, Port, User, Password, DB) ->
	gen_server:start_link({local, InstanceName}, ?MODULE, [Host, Port, User, Password, DB], []).

init([Host, Port, User, Password, DB]) ->
	Self = self(),
	State = #state{
		connector = fun() ->
			{ok, Pid} = mysql_connection:start_link(Host, Port, User, Password, DB, Self),
			Pid
		end
	},
	{ok, State}.

handle_call({mysql_query, Query}, {Pid, _Ref} , State = #state{ connector = Connector, connections = Connections }) ->
	{Connection, Rest} = case Connections of
		[C | R] -> {C, R};
		[] -> {Connector(), []}
	end,
	mysql_connection:send_query(Connection, Query, Pid),
	{reply, ok, State#state{ connections = Rest }}.

handle_cast(_Msg, State) ->
	{noreply, State}.

handle_info({connection_free, Pid}, State = #state{ connections = Connections }) ->
	{noreply, State#state{ connections = [Pid | Connections] }};
handle_info(_Info, State) ->
	{noreply, State}.

code_change(_OldVsn, State, _Extra) ->
	{ok, State}.

terminate(_Reason, _State) ->
	ok.

format_response({Fields, Rows}, order) ->
    {Fields, lists:reverse(Rows)};
format_response({Fields, Rows}, kv) ->
    FNames = [binary_to_list(FName) || {field, FName, _Type, _Extra} <- Fields],
    {Fields, [lists:zip(FNames, Row) || Row <- Rows]};
format_response({Fields, Rows}, type) ->
    Types = [Type || {field, _FName, Type, _Extra} <- Fields],
    TypedRows = [convert_type(Row, Types) || Row <- Rows],
    {Fields, TypedRows}.

convert_type([], []) -> [];
convert_type([{FName, Col} | Cols], [Type | Types]) ->
    [{FName, convert(Col, Type)} | convert_type(Cols, Types)];
convert_type([Col | Cols], [Type | Types]) ->
    [convert(Col, Type) | convert_type(Cols, Types)].

convert(Col, Type) ->
    case Type of
        T when  T == 'TINY';
                T == 'SHORT';
                T == 'LONG';
                T == 'LONGLONG';
                T == 'INT24';
                T == 'YEAR' ->
            list_to_integer(binary_to_list(Col));
        T when  T == 'DECIMAL';
                T == 'NEWDECIMAL';
                T == 'FLOAT';
                T == 'DOUBLE' ->
            L = binary_to_list(Col),
            {ok, Num, _} = case io_lib:fread("~f", [L]) of
                {error, _} -> io_lib:fread("~d", [L]);
                V -> V
            end,
            Num;
        _ ->
            Col
    end.
