#### OTP-based MySQL Client

## Usage:
#### Starting server:
	mysql:start_link(mysql_client, "localhost", 3306, <<"root">>, <<"password">>, <<"test">>).
Note: the client starts with a single TCP connection to the MySQL server. This connection is persistent. However, if a new request is made and all opened connections are busy, a new persistent connection is created.

#### Basic query:
	{FieldsList, RowsList} = mysql:do(mysql_client, "SELECT * FROM test_table").

#### Ordering:
By default, Fields and Rows lists are reversed, just to avoid extra lists:reverse() calls. This can be overridden by specifying the order option:
	{FieldsList, RowsList} = mysql:do(mysql_client, "SELECT * FROM test_table", [order]).

#### Results as key-value pairs:
	{FieldsList, RowsList} = mysql:do(mysql_client, "SELECT * FROM test_table", [kv]),
	[Row | _RestRows] = RowsList,
	Value = proplists:get_value("id", Row).

#### Some basic type conversion for the results (currently only for numerical values):
	{FieldsList, RowsList} = mysql:do(mysql_client, "SELECT * FROM test_table", [type]),

