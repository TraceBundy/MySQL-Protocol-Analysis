#MySQL协议分析
三次握手后，Server发送第一个认证包，包的格式如下

***

| 			| 				|  					|
|----------|:--------------:|-------------------------:|
| Protocol (0a)| Server Version (NUL)| Connection ID(thread id)(4 bytes) |
|Auth Plugin Data Part I (8 bytes)| Filler（1 byte）| Capalitity Flags I （2 bytes）（lower 2 bytes）   |
|Character Set （1 byte）| Status Flags （2 bytes ） | Capability Flags II （2 bytes）(upper 2 bytes) |
|Auth plugin data part len (1 byte)| Reserved (10 bytes) | Auth Plugin Data Part II (len)|
|\0|Auth Plugin Name (NUL)| 

示例

	Protocol:a
	server_version:5.5.46-0ubuntu0.14.04.2
	connection_id:5f 0 0 0 
	auth_plugin_data_part_1:6c 62 2a 46 63 40 54 65  0 
	filler:0
	capalitity flags:ffffffff ffffffff
	character_set:8
	status_flags:2 0
	capability_flags_2:f ffffff80
	auth_plugin_data_len:15 -> 21
	auth_plugin_data:[~m&p(p~K7s_a]
	plugin name:[mysql_native_password]	

		0x0000:  4508 0093 28fa 4000 4006 1361 7f00 0001  E...(.@.@..a....
	0x0010:  7f00 0001 0cea 8a92 e16b 6ee1 438a f021  .........kn.C..!
	0x0020:  8018 0156 fe87 0000 0101 080a 087a 461b  ...V.........zF.
	0x0030:  087a 461b 5b00 0000 0a35 2e35 2e34 362d  .zF.[....5.5.46-
	0x0040:  3075 6275 6e74 7530 2e31 342e 3034 2e32  0ubuntu0.14.04.2
	0x0050:  005f 0000 006c 622a 4663 4054 6500 fff7  ._...lb*Fc@Te...
	0x0060:  0802 000f 8015 0000 0000 0000 0000 0000  ................
	0x0070:  7e6d 2670 2870 7e4b 3773 5f61 006d 7973  ~m&p(p~K7s_a.mys
	0x0080:  716c 5f6e 6174 6976 655f 7061 7373 776f  ql_native_passwo
	0x0090:  7264 00                                  rd.	
MySQL关于该包的函数在sql_authentication.cc:send_server_handshake_packet函数。

|字段|说明|
|--------|:-----:|
|Protocol|协议版本|
|Server Version|服务器版本|
|Connection ID| 连接ID(线程ID)|
|Plugin Data| 加密数据前8字节(这里只放前8字节是为了兼容旧版本协议)|
|filler|第一部分挑战数据结束符|
|capalitity|服务器功能标志低2字节|
|charater set|字符集|
|status flag |服务器状态|
|capability flags|服务器功能标志高2字节|
|plugn data len | 加密数据长度|
|reserved|保留长度10字节|
|plugin data|加密数据剩余部分|
|\0|加密数据结束符|
|plugin name| 加密数据名称|

客户端收到后返回给用户名，密码等信息
***
| 					| 					|		|
|------------------|:--------------:|--------------:|
|capability(4bytes)|max_len(4bytes)|charset(1byte);|
|user(NUL)|:auth_len(1byte):|authdata(20bytes)|
|database(EOF)(option)|

|字段|说明|
|--------|:-----:|
|capability| 用来返回客户端所支持的功能标志|
|max_len|客户端所支持的包长|
|charset|客户端字符集|
|user|用户名|
|auth_len|认证数据的长度|
|authdata|认证数据|
|database|数据库名（可选），需要支持CLIENT_CONNECT_WITH_DB标志|

客户端收到Server返回的认证结果
***
OK 包

| 					| 					|		|
|------------------|:--------------:|--------------:|
|header（0x00）|affected——rows(lenenc)|last_insert_id(lenenc)|
|status flags(2bytes)|warnings(2bytes)|info(EOF)(option)|

[lenenc说明](https://dev.mysql.com/doc/internals/en/integer.html#packet-Protocol::LengthEncodedInteger)

|字段|说明|
|--------|:-----:|
|header| 0x00|
|affected rows|影响行数（）|
|insert-id|inser id值|
|status|服务器状态|
|warnings|警告计数|
|info|服务器消息|

ERROR包

| 					| 					|		|
|------------------|:--------------:|--------------:|
|header（0xff）|error_code(2bytes)|sql_state_marker(1byte)|
|sql_state(5bytes)|error_message(EOF)|

|字段|说明|
|--------|:-----:|
|header| 0x00|
|error code|错误代码|
|sql_state_marker|错误状态标志（#）|
|sql_state|服务器状态|
|errpr_message|错误信息|