%% Message Notification Service for Ejabberd
%% Created: 07/09/2015 by mrDoctorWho，Modify by WangZhiguo 05/05/2016
%% License: MIT/X11

%% 快马仕消息服务器离线推送服务
-module(mod_kmsns_mysql).
-author("Wang Zhiguo").

-include("ejabberd.hrl").
-include("logger.hrl").
-include("jlib.hrl").
-include("ejabberd_sql_pt.hrl").

-behaviour(gen_mod).

%% user 用户jid，token是用户设备token，last_seen最后一次上线的时间，node_type推送服务类型【apns，jpush，xiaomi】
%% app_id, app_token  为客户端id, token
% -record(last_device, {user, token, last_seen, node_type, app_id, app_token}).

%% 缓存每个App的推送证书
% -record(kmsns_certs, {app_id, apnscert, apnscertdev, jpushkey, jpushsecret, xiaomikey, xiaomisecret, updatedate}).

%% 快马仕push namespace
-define(NS_KMSNS, "https://kuaimashi.com/push").

-export([start/2, stop/1, message/3, iq/3, mod_opt_type/1]).

-define(Timeout, 10000).

-define(CIPHERSUITES,
        [{K,C,H} || {K,C,H} <- ssl:cipher_suites(erlang),
                    %K =/= ecdh_ecdsa, K =/= ecdh_rsa, K =/= rsa,
                    K =/= ecdh_ecdsa, K =/= ecdh_rsa,
                    C =/= rc4_128, C =/= des_cbc, C =/= '3des_ede_cbc',
                    %H =/= sha, H =/= md5]).
                    H =/= md5]).

%% jpush json请求body模板
-define(JPUSH_OBJECT, "{
  \"platform\": [
    \"android\"
  ],
  \"audience\": {
    \"registration_id\": [
      \"~s\"
    ]
  },
  \"notification\": {
    \"alert\": \"~s\",
    \"android\": {
      \"extras\": {
        \"source\": \"~s\"
      }
    }
  }
}").

%% 格式化字符串
string_format(Pattern, Values) ->
    lists:flatten(io_lib:format(Pattern, Values)).

%% 从服务器上获取APNS证书
request_cert_for_apns(Host, AppID) ->
	%% 去平台服务器请求证书
	Method = post,
	%% 读取配置文件中mod_kmsns配置的获取推送证书信息URL
	URL = gen_mod:get_module_opt(Host, ?MODULE, certinfo, fun(V) -> binary_to_list(V) end, undefined),
	Header = [],
	Type = "application/x-www-form-urlencoded",
	Body = lists:concat(["appid=", binary_to_list(AppID), "&nodetype=", "apns"]),
	HTTPOptions = [],
	Options = [],
    case httpc:request(Method, {URL, Header, Type, Body}, HTTPOptions, Options) of   
        {ok, {_, _, ResponseBody}} ->
        	?DEBUG("CCDEBUG: Get APNS push cert info request response  ~s", [ResponseBody]), 
        	#xmlel{
        	name = <<"ret">>, 
        	children = [
        	#xmlel{name = <<"code">>, children = [{xmlcdata, Code}]}, 
        	#xmlel{name = <<"alt">>, children = [{xmlcdata, Alt}]}, 
        	#xmlel{name = <<"data">>, children = [
        		#xmlel{name = <<"apnscert">>, children = [{xmlcdata, ApnsCertBase64}]},
        		#xmlel{name = <<"apnscertdev">>, children = [{xmlcdata, ApnsCertDevBase64}]}
        	]},
        	#xmlel{name = <<"notifytime">>, children = [{xmlcdata, _}]}
        	]} = fxml_stream:parse_element(<<(list_to_binary(ResponseBody))/binary>>),
        	case Code of
        		<<"200">> -> 
        			%% 请求成功，证书是Base64编码的需要转换
        			ApnsCert = case ApnsCertBase64 of
        				<<"">> -> <<"">>;
        				_ -> base64:decode(ApnsCertBase64)
        			end,
        			ApnsCertDev = case ApnsCertDevBase64 of
        				<<"">> -> <<"">>;
        				_ -> base64:decode(ApnsCertDevBase64)
        			end,
        			
					TimeStamp = unix_timestamp_to_string(),

					%% 存储到数据库缓存
					%% mysql 数据库
					Table = <<"push_cert">>,
					Fields = [<<"appid">>, <<"apnscert">>, <<"apnscertdev">>, <<"updatetime">>],
					Vals = [AppID, ApnsCert, ApnsCertDev, list_to_binary(TimeStamp)],
					Where = <<"appid", "='", AppID/binary, "'">>,
					case catch sql_queries:update(Host, Table, Fields, Vals, Where) of 
						ok -> 
							?DEBUG("mod_kmsns: insert/update new apns cert into table ~p for appid [~p].", [Table, AppID]);
						Reason ->
							?DEBUG("mod_kmsns: update table ~p for appid [~p], error ~p.", [Table, AppID, Reason])
					end,
					%% mysql 数据库

        			%% mnesia数据库
        			% -record(kmsns_certs, {app_id, apnscert, apnscertdev, jpushkey, jpushsecret, xiaomikey, xiaomisecret, updatedate}).
        			%
        			% F = fun() -> 
        			% 	mnesia:write(#kmsns_certs{app_id=AppID, apnscert=ApnsCert, apnscertdev=ApnsCertDev, 
        			% 	jpushkey= <<"">>, jpushsecret= <<"">>, xiaomikey= <<"">>, xiaomisecret= <<"">>, updatedate=TimeStamp}) 
        			% end,
        			% case mnesia:dirty_read(kmsns_certs, AppID) of
        			% 	[] ->
        			% 		mnesia:transaction(F),
        			% 		?DEBUG("mod_kmsns: New Apns cert insert for AppID: ~p", [AppID]);
        			% 	[#kmsns_certs{app_id=AppID}] ->
        			% 		mnesia:transaction(F),
        			% 		?DEBUG("mod_kmsns: Update Apns cert for AppID: ~p", [AppID])
        			% end, 
        			%% mnesia数据库

        			{true, Alt, ApnsCert, ApnsCertDev};
        		_ -> {false, Alt, <<"">>, <<"">>}
        	end;
    	{error, Reason} ->
      		{false, Reason, <<"">>, <<"">>}
    end.

%% 请求jpush推送key和secret
request_jpush_key_secret(Host, AppID) ->
	Method = post,
	%% 读取配置文件中mod_kmsns配置的获取推送证书信息URL
	URL = gen_mod:get_module_opt(Host, ?MODULE, certinfo, fun(V) -> binary_to_list(V) end, undefined),
	Header = [],
	Type = "application/x-www-form-urlencoded",
	Body = lists:concat(["appid=", binary_to_list(AppID), "&nodetype=", "jpush"]),
	HTTPOptions = [],
	Options = [],
    case httpc:request(Method, {URL, Header, Type, Body}, HTTPOptions, Options) of   
        {ok, {_, _, ResponseBody}} ->
        	?DEBUG("CCDEBUG: Get jpush push key secret info request response  ~s", [ResponseBody]), 
        	#xmlel{
        	name = <<"ret">>, 
        	children = [
        	#xmlel{name = <<"code">>, children = [{xmlcdata, Code}]}, 
        	#xmlel{name = <<"alt">>, children = [{xmlcdata, Alt}]}, 
        	#xmlel{name = <<"data">>, children = [
        		#xmlel{name = <<"jpushkey">>, children = [{xmlcdata, JPushKey}]},
        		#xmlel{name = <<"jpushsecret">>, children = [{xmlcdata, JPushSecret}]}
        	]},
        	#xmlel{name = <<"notifytime">>, children = [{xmlcdata, _}]}
        	]} = fxml_stream:parse_element(<<(list_to_binary(ResponseBody))/binary>>),
        	case Code of
        		<<"200">> -> 
        			TimeStamp = unix_timestamp_to_string(),

        			%% 存储到数据库缓存
        			%% mysql数据库
        			Table = <<"push_cert">>,
					Fields = [<<"appid">>, <<"jpushkey">>, <<"jpushsecret">>, <<"updatetime">>],
					Vals = [AppID, JPushKey, JPushSecret, list_to_binary(TimeStamp)],
					Where = <<"appid", "='", AppID/binary, "'">>,
					case catch sql_queries:update(Host, Table, Fields, Vals, Where) of 
						ok -> 
							?DEBUG("mod_kmsns: insert/update new jpush cert into table ~p for appid [~p].", [Table, AppID]);
						Reason ->
							?DEBUG("mod_kmsns: update table ~p for appid [~p], error ~p.", [Table, AppID, Reason])
					end,
        			%% mysql数据库

        			%% mnesia数据库        			
        			% -record(kmsns_certs, {app_id, apnscert, apnscertdev, jpushkey, jpushsecret, xiaomikey, xiaomisecret, updatedate}).
        			%
        			% F = fun() -> 
        			% 	mnesia:write(#kmsns_certs{app_id=AppID, apnscert= <<"">>, apnscertdev= <<"">>, 
        			% 	jpushkey=JPushKey, jpushsecret=JPushSecret, xiaomikey= <<"">>, xiaomisecret= <<"">>, updatedate=TimeStamp}) 
        			% end,
        			% case mnesia:dirty_read(kmsns_certs, AppID) of
        			% 	[] ->
        			% 		mnesia:transaction(F),
        			% 		?DEBUG("mod_kmsns: New jpush key secret insert for AppID: ~p", [AppID]);
        			% 	[#kmsns_certs{app_id=AppID}] ->
        			% 		mnesia:transaction(F),
        			% 		?DEBUG("mod_kmsns: Update jpush key secret for AppID: ~p", [AppID])
        			% end, 
        			%% mnesia数据库

        			{true, Alt, JPushKey, JPushSecret};
        		_ -> {false, Alt, <<"">>, <<"">>}
        	end;
    	{error, Reason} ->
      		{false, Reason, <<"">>, <<"">>}
    end.

%% APNS发送Payload
send_payload(apns, Host, Payload, Token, AppID, _) ->
	%% 读取缓存中证书文件
	%% mysql数据库
	Table = <<"push_cert">>,
	SQLList = [<<"select">>, <<" apnscert, apnscertdev ">>, <<"from ">>, Table, <<" where appid=">>, <<"'">>, AppID, <<"'">>],
	Record = ejabberd_sql:sql_query(Host, SQLList),
	{Result, Info, Cert, CertDev} = case Record of
		{selected, _, R} ->
			case R of 
				[] -> 
					?DEBUG("mod_kmsns: No APNS cert records found for AppID: ~p, try from http and then cached.", [AppID]),
					request_cert_for_apns(Host, AppID);
				[H|_] ->
					[ApnsCert, ApnsCertDev] = H,
					if (ApnsCert == <<"">>) or (ApnsCertDev == <<"">>) ->
						request_cert_for_apns(Host, AppID);
					true -> {true, "Found APNS cert from db", ApnsCert, ApnsCertDev}
					end					
			end;
		Error ->
			?DEBUG("mod_kmsns: Read APNS cert from db faild, db error ~p", [Error]),
			{false, "DB error", <<"">>, <<"">>}
	end,
	%% mysql数据库
	
	%% mnesia数据库
	% Record = mnesia:dirty_read(kmsns_certs, AppID),
	% {Result, Info, Cert, CertDev} = case Record of 
	% 	[] ->
	% 		?DEBUG("mod_kmsns: No APNS cert records found for AppID: ~p, try from http and then cached.", [AppID]),
	% 		%%
	% 		request_cert_for_apns(Host, AppID);
	% 		%%
	% 	[#kmsns_certs{app_id=AppIDCached, apnscert=ApnsCertCached, apnscertdev=ApnsCertDevCached}] -> 
	% 		?DEBUG("mod_kmsns: Found APNS cert record for AppID: ~p.", [AppIDCached]),
	% 		{true, "Found APNS cert from local cached", ApnsCertCached, ApnsCertDevCached}
	% end,
	%% mnesia数据库

	case {Result, Info} of
		{true, _} ->
			%% 获取配置文件中部署环境，生产环境使用生产环境证书，开发环境使用开发环境证书
		    Env = gen_mod:get_module_opt(Host, ?MODULE, env, fun(V) -> binary_to_list(V) end, undefined),
		    ApnsHost = gen_mod:get_module_opt(Host, ?MODULE, apnshost, fun(V) -> binary_to_list(V) end, undefined),
			ApnsPort = gen_mod:get_module_opt(Host, ?MODULE, apnsport, fun(V) -> V end, undefined),
			FinalCert = case Env of
				"production" -> Cert;
				"develop" -> CertDev
			end,

			?DEBUG("mod_kmsns: APNS trying to send payload with these parameters: Address: ~p Port: ~p Cert: ~p, Token: ~p Payload: ~p",
				[ApnsHost, ApnsPort, FinalCert, Token, Payload]),

			[{'Certificate', CertDER, not_encrypted}, {'RSAPrivateKey', KeyDER, not_encrypted}] = public_key:pem_decode(FinalCert), 
			Options = [{cert, CertDER},
					 {key, {'RSAPrivateKey', KeyDER}}
		             %{versions, ['tlsv1.2']},
		             % {ciphers, ?CIPHERSUITES},
		             % {reuse_sessions, true},
		             % {secure_renegotiate, true}],
		             %{verify, verify_peer},
		             %{cacertfile, CACertFile}
		             ],

			case ssl:connect(ApnsHost, ApnsPort, Options, ?Timeout) of
				{ok, Socket} ->
					PayloadBin = Payload,
					PayloadLength = size(PayloadBin),
					TokenNum = erlang:binary_to_integer(Token, 16),
					TokenBin = <<TokenNum:32/integer-unit:8>>,
					Packet = <<
						0:8,
						32:16/big,
						TokenBin/binary,
						PayloadLength:16/big,
						PayloadBin/binary
					>>,
					ssl:send(Socket, Packet),
					ssl:close(Socket),
					?DEBUG("mod_kmsns: Successfully sent payload [~p] to the APNS server", [Payload]),
					ok;
				{error, Reason} ->
					?ERROR_MSG("mod_kmsns: Unable to connect to the APNS server: ~p", [Reason]),
					ok
			end;
		{false, Info} ->
			?ERROR_MSG("mod_kmsns: Unable to connect to the APNS server: ~p", [Info]),
			ok
	end;
send_payload(jpush, Host, Payload, _, AppID, _) ->
	%% mysql数据库
	Table = <<"push_cert">>,
	SQLList = [<<"select">>, <<" jpushkey, jpushsecret ">>, <<"from ">>, Table, <<" where appid=">>, <<"'">>, AppID, <<"'">>],
	Record = ejabberd_sql:sql_query(Host, SQLList),
	{Result, Info, Key, Secret} = case Record of
		{selected, _, [H|_]} ->
			case H of 
				[] -> 
					?DEBUG("mod_kmsns: No jpush key&secret records found for AppID: ~p, try from http and then cached.", [AppID]),
					request_jpush_key_secret(Host, AppID);
				_ ->
					[JPushKey, JPushSecret] = H,
					if (JPushKey == <<"0">>) or (JPushSecret == <<"0">>) ->
						request_jpush_key_secret(Host, AppID);
					true -> 
						{true, "Found jpush key&secret from db", JPushKey, JPushSecret}
					end					
			end;
		Error ->
			?DEBUG("mod_kmsns: Query jpush key&secret from db faild, db error ~p", [Error]),
			{false, "DB error", <<"">>, <<"">>}
	end,
	%% mysql数据库

	%% mnesia数据库 
	% Record = mnesia:dirty_read(kmsns_certs, AppID),
	% {Result, Info, Key, Secret} = case Record of 
	% 	[] ->
	% 		?DEBUG("mod_kmsns: No jpush key secret records found for AppID: ~p, try from http and then cached.", [AppID]),
	% 		request_jpush_key_secret(Host, AppID);
	% 	[#kmsns_certs{app_id=AppID, jpushkey=JPushKey, jpushsecret=JPushSecret}] ->
	% 		{true, "mod_kmsns: Found jpush key secret records", JPushKey, JPushSecret}
	% end,
	%% mnesia数据库

	case {Result, Info} of
		{true, _} ->
			%% 获取jpush配置
		    JPushHost = gen_mod:get_module_opt(Host, ?MODULE, jpushhost, fun(V) -> binary_to_list(V) end, undefined),
			_ = gen_mod:get_module_opt(Host, ?MODULE, jpushport, fun(V) -> V end, undefined),
			Method = post,
			Auth = "Basic " ++ binary_to_list(base64:encode(binary_to_list(Key) ++ ":" ++ binary_to_list(Secret))),
			Header = [{"Content-Type", "application/json"}, {"Authorization", Auth}],
			Type = "application/x-www-form-urlencoded",
			Body = Payload,
			HTTPOptions = [],
			Options = [],

			?DEBUG("mod_kmsns: jpush trying to send payload with these parameters: Address: ~p JPushKey: ~p, JPushSecret: ~p Payload: ~p",
				[JPushHost, Key, Secret, Payload]),

		    case httpc:request(Method, {JPushHost, Header, Type, Body}, HTTPOptions, Options) of
		    	{ok, {_, _, ResponseBody}} ->
		    		?DEBUG("mod_kmsns: Post to jpush success ~p", [ResponseBody]),
		    		ok;
		    	{error, Reason} -> 
		    		?DEBUG("mod_kmsns: Post to jpush faild ~p", [Reason]),
		    		ok
		    end;
		{false, Info} ->
			?DEBUG("mod_kmsns: Get jpush key secret error ~p", [Info]),
			ok
	end;
send_payload(xiaomi, Host, Payload, Token, AppID, _) ->
	%% TODO
	?DEBUG("mod_kmsns: jpush ~s ~s ~s ~s", [Host, Payload, Token, AppID]),
	ok;
send_payload(_, Host, Payload, Token, AppID, _) ->
	?DEBUG("mod_kmsns: jpush ~s ~s ~s ~s", [Host, Payload, Token, AppID]),
	ok.

message(From, To, Packet) ->
	Type = fxml:get_tag_attr_s(<<"type">>, Packet),
	% ?DEBUG("Offline message", []),
	case Type of 
		"normal" -> ok;
		_ ->
			%% Strings
			JFrom = jlib:jid_to_string(From#jid{user = From#jid.user, server = From#jid.server, resource = <<"">>}),
			JTo = jlib:jid_to_string(To#jid{user = To#jid.user, server = To#jid.server, resource = <<"">>}),
			ToUser = To#jid.user,
			ToServer = To#jid.server,
			Body = fxml:get_path_s(Packet, [{elem, <<"body">>}, cdata]),

			?DEBUG("mod_kmsns: Offline message from [~p] to [~p], message body [\"~p\"].", [JFrom, JTo, Body]),

			%% Checking subscription
			{Subscription, _Groups} = 
				ejabberd_hooks:run_fold(roster_get_jid_info, ToServer, {none, []}, [ToUser, ToServer, From]),

			?DEBUG("mod_kmsns: subscription, group = ~p, ~p.", [Subscription, _Groups]),
			%% FIXME: subsciption
			HackSubsciption = both,
			case HackSubsciption of
				both ->
					case Body of
						<<>> -> ok;
						_ ->
							%% mysql数据库
							Table = <<"last_device">>,
							case ejabberd_sql:sql_query(From#jid.server, [<<"select">>, <<" * ">>, <<"from ">>, Table, 
								<<" where user=">>, <<"\"">>, ToUser, <<"\"">>, <<";">>]) of
								{selected, _, [H|_]} ->
									% 查询到了记录
									[_, NodeType, DeviceToken, AppID, AppToken, _] = H,
									% 推送通知栏显示的内容由message节点的alt属性值决定
									TmpAltBody = fxml:get_path_s(Packet, [{attr, <<"alt">>}]),
									AltBody = if (TmpAltBody == <<>>) or (TmpAltBody == <<"">>) ->
										unicode:characters_to_binary("收到一条消息");
										true -> TmpAltBody
									end,
									%
									if DeviceToken /= <<"">> ->
										case NodeType of
										<<"apns">> ->
											% 构造Payload
											% {[{foo, [<<"bing">>, 2.3, true]}]} -> <<"{\"foo\":[\"bing\",2.3,true]}">>
											% {"aps":{"alert":"This is some fancy message.","sound": "default","badge":1}}
											Doc = {[{aps, {[{alert, AltBody}, {sound, <<"default">>}, {badge, 1}]}}, {source, base64:encode(Body)}]},
											Payload = jiffy:encode(Doc),
											?DEBUG("mod_kmsns: APNS Payload ~p.", [Payload]),
											
											% %% FIXME: Badges?
											% Sound = "default",
											% Msg = [{alert, binary_to_list(AltBody)}, {sound, Sound}],
											% Args = [{source, binary_to_list(base64:encode(Body))}],
											% Payload = create_playload(apns, Msg, Args),
											
											%% 发送到apns
											send_payload(apns, ToServer, Payload, DeviceToken, AppID, AppToken);											
										<<"jpush">> ->
											Payload = string_format(?JPUSH_OBJECT, 
												[binary_to_list(DeviceToken), binary_to_list(AltBody), binary_to_list(base64:encode(Body))]),
											send_payload(jpush, ToServer, Payload, DeviceToken, AppID, AppToken);
										<<"xiaomi">> ->
											%% TODO: xiaomi
											?DEBUG("mod_kmsns: has not implement for ~s", "xiaomipush");
										_ ->
											ok
										end;								
									true ->
										ok
									end;
								_ -> 
									?DEBUG("mod_kmsns: Not found user [~p] in Table ~p", [ToUser, Table])
							end

							%% mysql数据库

							%% mnesia数据库
							% Result = mnesia:dirty_read(kmsns_users, {ToUser, ToServer}),
							% case Result of 
							% 	[] ->
							% 		?DEBUG("mod_kmsns: No such record found for ~s", [JTo]);

							% 	[#kmsns_users{token = Token, node_type = NodeType, app_id = AppID, app_token = AppToken}] ->
							% 		%% 查找到了记录
							% 		%% 依据nodetype创建playload
							% 		case NodeType of
							% 			apns ->
							% 				Sound = "default",
							% 				%% TODO: Move binary_to_list to create_pair?
							% 				%% Badges?
							% 				Msg = [{alert, binary_to_list(Body)}, {sound, Sound}],
							% 				Args = [{source, binary_to_list(JFrom)}, {destination, binary_to_list(JTo)}],
							% 				Payload = create_playload(apns, Msg, Args),
							% 				%% 发送到apns
							% 				send_payload(apns, ToServer, Payload, Token, AppID, AppToken);
							% 			jpush ->
							% 				%% TODO: jpush
							% 				Payload = string_format(?JPUSH_OBJECT, [Token, Body, JFrom, JTo]),
							% 				send_payload(jpush, ToServer, Payload, Token, AppID, AppToken);
							% 			xiaomi ->
							% 				%% TODO: xiaomi
							% 				?DEBUG("mod_kmsns: has not implement for ~s", "xiaomipush");
							% 			_ -> ok
							% 		end
							% end
							%% mnesia数据库
					end;
				_ -> ok
			end
	end.

%% <iq to="YourServer" type="set">
%%   <register xmlns="https://kuaimashi.com/push" >
%%     <appid>APPID</appid>
%%	   <apptoken>APPTOKEN</apptoken>
%%	   <node>NODE_TYPE</node>  %% 推送服务器节点类型，[apns, jpush]
%% 	   <token>DEVICE_TOKEN</token>
%%   </register>
%% </iq>

iq(#jid{user = User, server = Server}, _, #iq{type = set, sub_el = SubEl} = IQ) ->
	%% ?DEBUG("mod_kmsns: Recv IQ -> ~p | SubEl -> ~p", [IQ, SubEl]),
	LUser = jlib:nodeprep(User),
	LServer = jlib:nameprep(Server),
	?DEBUG("mod_kmsns: LUser=~p, LServer=~p, SubEl=~p", [LUser, LServer, SubEl]),

	% 
	TimeStamp = unix_timestamp_to_string(),

	% 设备token
	Token = fxml:get_tag_cdata(fxml:get_subtag(SubEl, <<"token">>)),
	NodeType = fxml:get_tag_cdata(fxml:get_subtag(SubEl, <<"node">>)),
	AppID = fxml:get_tag_cdata(fxml:get_subtag(SubEl, <<"appid">>)),
	AppToken = fxml:get_tag_cdata(fxml:get_subtag(SubEl, <<"apptoken">>)),

	%% 写入mysql 的 lastdevice
	Table = <<"last_device">>,
	Fields = [<<"user">>, <<"nodetype">>, <<"token">>, <<"appid">>, <<"apptoken">>, <<"updatetime">>],
	Vals = [User, NodeType, Token, AppID, AppToken, list_to_binary(TimeStamp)],
	Where = <<"user", "='", User/binary, "'">>,
	case catch sql_queries:update(LServer, Table, Fields, Vals, Where) of 
		ok -> 
			?DEBUG("mod_kmsns: insert/update new user -> ~p into table last_device.", [User]);
		Reason ->
			?DEBUG("mod_kmsns: update table last_device for user -> ~p, error ~p.", [User, Reason])
	end,
	%% 写入mysql

	% mnesia数据库
	% % -record(kmsns_users, {user, token, last_seen, node_type, app_id, app_token}).
	% F = fun() -> mnesia:write(#kmsns_users{user={LUser, LServer}, token=Token, last_seen=TimeStamp, 
	% 	node_type=NodeType, app_id=AppID, app_token=AppToken}) end,

	% case mnesia:dirty_read(kmsns_users, {LUser, LServer}) of
	% 	[] ->
	% 		mnesia:transaction(F),
	% 		?DEBUG("mod_kmsns: New user registered ~s@~s", [LUser, LServer]);

	% 	%% Record exists, the key is equal to the one we know
	% 	[#kmsns_users{user={LUser, LServer}, token=Token}] ->
	% 		mnesia:transaction(F),
	% 		?DEBUG("mod_kmsns: Updating last_seen for user ~s@~s", [LUser, LServer]);

	% 	%% Record for this key has been found, but for another key
	% 	[#kmsns_users{user={LUser, LServer}, token=Token}] ->
	% 		mnesia:transaction(F),
	% 		?DEBUG("mod_kmsns: Updating token for user ~s@~s", [LUser, LServer])
	% 	end,
	% mnesia数据库

	IQ#iq{type=result, sub_el=[]}. %% We don't need the result, but the handler has to send something.


start(Host, _) -> 
	crypto:start(),
	ssl:start(),
	%% 改为mysql存储
	% mnesia:create_table(kmsns_users, [{disc_copies, [node()]}, {attributes, record_info(fields, kmsns_users)}]),
	% mnesia:create_table(kmsns_certs, [{disc_copies, [node()]}, {attributes, record_info(fields, kmsns_certs)}]),
	%% mysql
	gen_iq_handler:add_iq_handler(ejabberd_local, Host, <<?NS_KMSNS>>, ?MODULE, iq, no_queue),
	ejabberd_hooks:add(offline_message_hook, Host, ?MODULE, message, 49),
	?INFO_MSG("mod_kmsns Has started successfully!", []),
	ok.

stop(_) -> ok.

%% 配置选项
mod_opt_type(certinfo) -> fun iolist_to_binary/1;
mod_opt_type(apnshost) -> fun iolist_to_binary/1;
mod_opt_type(apnsport) -> fun(I) when is_integer(I) -> I end;
mod_opt_type(env) -> fun iolist_to_binary/1;
mod_opt_type(jpushhost) -> fun iolist_to_binary/1;
mod_opt_type(jpushport) -> fun(I) when is_integer(I) -> I end;
mod_opt_type(_) ->
    [certinfo, apnshost, apnshost, env, jpushhost, jpushport].


%% 将unix时间转换为YY-MM-DD hh:mm:ss字符串
unix_timestamp_to_string() ->
	{{Year, Month, Day}, {Hour, Minute, Second}} = calendar:now_to_local_time(erlang:now()),
	lists:flatten(io_lib:format("~4..0w-~2..0w-~2..0wT~2..0w:~2..0w:~2..0w",[Year,Month,Day,Hour,Minute,Second])).



