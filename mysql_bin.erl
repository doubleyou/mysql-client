-module(mysql_bin).
-export([
	auth_packet/5,
	decode_packet/1,
	encode_packet/2,
	encrypt_password/2,
	parse_handshake_packet/1,
	parse_packet/2,
	parse_packet/1,
	query_packet/1
]).

-define(LONG_PASSWORD, 1).
-define(LONG_FLAG, 4).
-define(CONNECT_WITH_DB, 8).
-define(PROTOCOL, 512).
-define(TRANSACTIONS, 8192).
-define(SECURE_CONNECTION, 32768).
-define(MAX_PACKET_SIZE, 16777216).

-record(field, {
	name,
	type,
	flags
}).

encode_packet(Packet, SeqNum) ->
	<<(size(Packet)):24/little, SeqNum:8, Packet/binary>>.

decode_packet(RawPacket) ->
	decode_packet(RawPacket, 0, []).

decode_packet(Bin, SeqNum, Acc) when size(Bin) < 5 ->
    {lists:reverse([Bin | Acc]), SeqNum};
decode_packet(<<L:24/little, SeqNum:8, Rest/binary>>, _SN, Acc) when size(Rest) < L->
	{lists:reverse([<<L:24/little, SeqNum:8, Rest/binary>> | Acc]), SeqNum};
decode_packet(<<L:24/little, SeqNum:8, Packet/binary>>, _SN, Acc) ->
	<<Body:L/binary, Rest>> = Packet,
	decode_packet(Rest, SeqNum, [Body | Acc]).

parse_handshake_packet(Packet) ->
	<<_ProtocolVersion:8/little,Rest1/binary>> = Packet,
	{_ServerVersion, Rest2} = extract_until_null(Rest1),
	<<
		_ThreadID:32/little,
		ScrambleBufStart:8/binary,
		0:8,
		ServerCaps:16/little,
		ServerLang:8/little,
		_ServerStatus:16/little,
		0:13/integer-unit:8,
		ScrambleBufEnd:12/binary,
		0:8
		>> = Rest2,
	{ServerCaps, ServerLang, <<ScrambleBufStart/binary,ScrambleBufEnd/binary>>}.

encrypt_password(Password, ScrambleBuf) ->
	Hash1 = crypto:sha(Password),
	Hash2 = crypto:sha_final(
		crypto:sha_update(
			crypto:sha_update(
				crypto:sha_init(),
				ScrambleBuf
			),
			crypto:sha(Hash1)
		)
	),
	bin_bxor(Hash2, Hash1).

auth_packet(User, Password, DB, _ServerCaps, ServerLang) ->
	ClientFlags = ?LONG_PASSWORD bor ?LONG_FLAG bor ?CONNECT_WITH_DB bor ?PROTOCOL bor ?TRANSACTIONS bor ?SECURE_CONNECTION,
	<<
		ClientFlags:32/little,
		(?MAX_PACKET_SIZE):32/little,
		ServerLang:8,
		0:23/integer-unit:8,
		User/binary, 0:8,
		(size(Password)):8,
		Password/binary,
		DB/binary
	>>.

query_packet(Query) ->
	<<3:8,Query/binary>>.

parse_packet(Packet) ->
	parse_packet(Packet, undefined).

%% OK packet
parse_packet(<<0:8, Bin/binary>>, _D) ->
	{ok, Bin};

%% EOF packet
parse_packet(<<254:8, Warnings:16/little, Status:16/little>>, _D) ->
	{eof, {Warnings, Status}};

%% Error packet
parse_packet(<<255:8, Code:16/little, "#", _State:5/binary, Msg/binary>>, _D) ->
	{error, {Code, Msg}};

parse_packet(<<L:8/little>>, header) ->
	{header, {rows, L}};
parse_packet(Packet, header) ->
	{Rows, <<>>} = extract_by_length(Packet),
	{header, {rows, Rows}};

%% Field packet
parse_packet(Packet, field) ->
	{
		[
			OrigName,
			_Name,
			_OrgTable,
			_Table,
			_DB,
			_Catalog
		],
		Rest
	} = extract_length_coded_bins(Packet, 6),
	<<
		_:8,
		_Charset:16/little,
		_Length:32/little,
		Type:8/little,
		Flags:16/little,
		_Decimals:8/little,
		0:2/integer-unit:8
	>> = Rest,
	{field, #field{ name = OrigName, type = convert_type(Type), flags = Flags }};

parse_packet(Packet, row) ->
	{row, parse_row(Packet)}.

parse_row(<<>>) ->
	[];
parse_row(Packet) ->
	{Column, Rest} = extract_by_length(Packet),
	[Column | parse_row(Rest)].

extract_until_null(Bin) ->
	extract_until_null(Bin, <<>>).

extract_until_null(<<0:8, Rest/binary>>, Acc) ->
	{Acc, Rest};
extract_until_null(<<C:8, Rest/binary>>, Acc) ->
	extract_until_null(Rest, <<Acc/binary,C:8>>).

bin_bxor(<<>>, <<>>) -> <<>>;
bin_bxor(<<C1:8,Rest1/binary>>, <<C2:8,Rest2/binary>>) ->
	<<(C1 bxor C2):8, (bin_bxor(Rest1, Rest2))/binary>>.

extract_by_length(<<251:8, Data/binary>>) ->
    {null, Data};
extract_by_length(<<252:8, L:16/little, Data/binary>>) ->
    split_binary(Data, L);
extract_by_length(<<253:8, L:24/little, Data/binary>>) ->
    split_binary(Data, L);
extract_by_length(<<254:8, L:64/little, Data/binary>>) ->
    split_binary(Data, L);
extract_by_length(<<L:8/little, Data/binary>>) ->
    split_binary(Data, L).

extract_length_coded_bins(Binary, N) ->
	extract_length_coded_bins(Binary, N, []).

extract_length_coded_bins(Binary, 0, Acc) ->
	{Acc, Binary};
extract_length_coded_bins(Binary, N, Acc) ->
	{Bin, Rest} = extract_by_length(Binary),
	extract_length_coded_bins(Rest, N - 1, [Bin | Acc]).

convert_type(0) -> 'DECIMAL';
convert_type(1) -> 'TINY';
convert_type(2) -> 'SHORT';
convert_type(3) -> 'LONG';
convert_type(4) -> 'FLOAT';
convert_type(5) -> 'DOUBLE';
convert_type(6) -> 'NULL';
convert_type(7) -> 'TIMESTAMP';
convert_type(8) -> 'LONGLONG';
convert_type(9) -> 'INT24';
convert_type(10) -> 'DATE';
convert_type(11) -> 'TIME';
convert_type(12) -> 'DATETIME';
convert_type(13) -> 'YEAR';
convert_type(14) -> 'NEWDATE';
convert_type(15) -> 'VARCHAR';
convert_type(16) -> 'BIT';
convert_type(246) -> 'NEWDECIMAL';
convert_type(247) -> 'ENUM';
convert_type(248) -> 'SET';
convert_type(249) -> 'TINY_BLOB';
convert_type(250) -> 'MEDIUM_BLOB';
convert_type(251) -> 'LONG_BLOB';
convert_type(252) -> 'BLOB';
convert_type(253) -> 'VAR_STRING';
convert_type(254) -> 'STRING';
convert_type(255) -> 'GEOMETRY'.
