%% Google Cloud Messaging for Ejabberd
%% Created: 07/09/2015 by mrDoctorWho
%% License: MIT/X11

-module(mod_kmsns).
-author("mrDoctorWho").

-include("ejabberd.hrl").
-include("logger.hrl").
-include("jlib.hrl").

-behaviour(gen_mod).

%% user 用户jid，token是用户设备token，last_seen最后一次上线的时间，node_type推送服务类型【apns，jpush，xiaomi】
%% app_id, app_token  为客户端id, token
-record(kmsns_users, {user, token, last_seen, node_type, app_id, app_token}).

%% 缓存每个App的推送证书
-record(kmsns_certs, {app_id, apnscertkey, apnscertkeydev, jpushkey, jpushsecret, xiaomikey, xiaomisecret, updatedate}).

-define(NS_KMSNS, "https://kuaimashi.com/push"). %% 快马仕push namespace

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
      \"~p\"
    ]
  },
  \"notification\": {
    \"alert\": \"~p\",
    \"android\": {
      \"extras\": {
        \"from\": \"~p\",
        \"to\": \"~p\"
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
        		#xmlel{name = <<"apnscertkey">>, children = [{xmlcdata, ApnsCertBase64}]},
        		#xmlel{name = <<"apnscertkeydev">>, children = [{xmlcdata, ApnsCertDevBase64}]}        		
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
        			%% TODO: 存储到数据库缓存
        			%% -record(kmsns_certs, {app_id, apnscertkey, apnscertkeydev, jpushkey, jpushsecret, xiaomikey, xiaomisecret, updatedate}).
        			{MegaSecs, Secs, _MicroSecs} = erlang:timestamp(),
					TimeStamp = MegaSecs * 1000000 + Secs,
        			F = fun() -> 
        				mnesia:write(#kmsns_certs{app_id=AppID, apnscertkey=ApnsCert, apnscertkeydev=ApnsCertDev, 
        				jpushkey= <<"">>, jpushsecret= <<"">>, xiaomikey= <<"">>, xiaomisecret= <<"">>, updatedate=TimeStamp}) 
        			end,
        			case mnesia:dirty_read(kmsns_certs, AppID) of
        				[] ->
        					mnesia:transaction(F),
        					?DEBUG("mod_kmsns: New Apns cert insert for AppID: ~p", [AppID]);
        				[#kmsns_certs{app_id=AppID}] ->
        					mnesia:transaction(F),
        					?DEBUG("mod_kmsns: Update Apns cert for AppID: ~p", [AppID])
        			end, 
        			%%
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
        			%% TODO: 存储到数据库缓存
        			%% -record(kmsns_certs, {app_id, apnscertkey, apnscertkeydev, jpushkey, jpushsecret, xiaomikey, xiaomisecret, updatedate}).
        			{MegaSecs, Secs, _MicroSecs} = erlang:timestamp(),
					TimeStamp = MegaSecs * 1000000 + Secs,
        			F = fun() -> 
        				mnesia:write(#kmsns_certs{app_id=AppID, apnscertkey= <<"">>, apnscertkeydev= <<"">>, 
        				jpushkey=JPushKey, jpushsecret=JPushSecret, xiaomikey= <<"">>, xiaomisecret= <<"">>, updatedate=TimeStamp}) 
        			end,
        			case mnesia:dirty_read(kmsns_certs, AppID) of
        				[] ->
        					mnesia:transaction(F),
        					?DEBUG("mod_kmsns: New jpush key secret insert for AppID: ~p", [AppID]);
        				[#kmsns_certs{app_id=AppID}] ->
        					mnesia:transaction(F),
        					?DEBUG("mod_kmsns: Update jpush key secret for AppID: ~p", [AppID])
        			end, 
        			%%
        			{true, Alt, JPushKey, JPushSecret};
        		_ -> {false, Alt, <<"">>, <<"">>}
        	end;
    	{error, Reason} ->
      		{false, Reason, <<"">>, <<"">>}
    end.

% partially done by uwe-arzt.de
send_payload(apns, Host, Payload, Token, AppID, _) ->
	%% TODO: 读取缓存中证书文件
	Record = mnesia:dirty_read(kmsns_certs, AppID),
	{Result, Info, Cert, CertDev} = case Record of 
		[] ->
			?DEBUG("mod_kmsns: No APNS cert records found for AppID: ~p, try from http and then cached.", [AppID]),
			%%
			request_cert_for_apns(Host, AppID);
			%%
		[#kmsns_certs{app_id=AppIDCached, apnscertkey=ApnsCertCached, apnscertkeydev=ApnsCertDevCached}] -> 
			?DEBUG("mod_kmsns: Found APNS cert record for AppID: ~p.", [AppIDCached]),
			{true, "Found APNS cert from local cached", ApnsCertCached, ApnsCertDevCached}
	end,
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

			?DEBUG("mod_kmsns: APNS trying to send payload with these parameters: Address: ~s Port: ~s Cert: ~s",
				[ApnsHost, ApnsPort, FinalCert]),

			[{'Certificate', CertDER, not_encrypted}] = public_key:pem_decode(FinalCert),
			Options = [{cert, CertDER},
		             {versions, ['tlsv1.2']},
		             {ciphers, ?CIPHERSUITES},
		             {reuse_sessions, true},
		             {secure_renegotiate, true}],
		             %{verify, verify_peer},
		             %{cacertfile, CACertFile}],

			case ssl:connect(ApnsHost, ApnsPort, Options, ?Timeout) of
				{ok, Socket} ->
					PayloadBin = list_to_binary(Payload),
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
					?DEBUG("mod_kmsns: Successfully sent payload to the APNS server", []),
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
	%% 
	Record = mnesia:dirty_read(kmsns_certs, AppID),
	{Result, Info, Key, Secret} = case Record of 
		[] ->
			?DEBUG("mod_kmsns: No jpush key secret records found for AppID: ~p, try from http and then cached.", [AppID]),
			request_jpush_key_secret(Host, AppID);
		[#kmsns_certs{app_id=AppID, jpushkey=JPushKey, jpushsecret=JPushSecret}] ->
			{true, "mod_kmsns: Found jpush key secret records", JPushKey, JPushSecret}
	end,
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


create_json(List1, List2) ->
	lists:append(["{\"aps\":{", create_keyvalue(List1), "}, ", create_keyvalue(List2), "}"]).

create_keyvalue([Head]) ->
	create_pair(Head);
create_keyvalue([Head|Tail]) ->
	lists:append([create_pair(Head), ",", create_keyvalue(Tail)]).
 
create_pair({Key, Value}) ->
	lists:append([add_quotes(atom_to_list(Key)), ":", add_quotes(Value)]).
add_quotes(String) ->
	lists:append(["\"", String, "\""]).

create_playload(apns, Msg, Args) ->
	create_json(Msg, Args);
create_playload(jpush, _, _) ->
	ok;
create_playload(xiaomi, _, _) ->
	ok;
create_playload(_, _, _) ->
	ok.

message(From, To, Packet) ->
	Type = xml:get_tag_attr_s(<<"type">>, Packet),
	?DEBUG("Offline message", []),
	case Type of 
		"normal" -> ok;
		_ ->
			%% Strings
			JFrom = jlib:jid_to_string(From#jid{user = From#jid.user, server = From#jid.server, resource = <<"">>}),
			JTo = jlib:jid_to_string(To#jid{user = To#jid.user, server = To#jid.server, resource = <<"">>}),
			ToUser = To#jid.user,
			ToServer = To#jid.server,
			Body = xml:get_path_s(Packet, [{elem, <<"body">>}, cdata]),

			%% Checking subscription
			{Subscription, _Groups} = 
				ejabberd_hooks:run_fold(roster_get_jid_info, ToServer, {none, []}, [ToUser, ToServer, From]),
			case Subscription of
				both ->
					case Body of
						<<>> -> ok;
						_ ->
							Result = mnesia:dirty_read(kmsns_users, {ToUser, ToServer}),
							case Result of 
								[] ->
									?DEBUG("mod_kmsns: No such record found for ~s", [JTo]);

								[#kmsns_users{token = Token, node_type = NodeType, app_id = AppID, app_token = AppToken}] ->
									%% 查找到了记录
									%% 依据nodetype创建playload
									case NodeType of
										apns ->
											Sound = "default",
											%% TODO: Move binary_to_list to create_pair?
											%% Badges?
											Msg = [{alert, binary_to_list(Body)}, {sound, Sound}],
											Args = [{source, binary_to_list(JFrom)}, {destination, binary_to_list(JTo)}],
											Payload = create_playload(apns, Msg, Args),
											%% 发送到apns
											send_payload(apns, ToServer, Payload, Token, AppID, AppToken);
										jpush ->
											%% TODO: jpush
											Payload = string_format(?JPUSH_OBJECT, [Token, Body, JFrom, JTo]),
											send_payload(jpush, ToServer, Payload, Token, AppID, AppToken);
										xiaomi ->
											%% TODO: xiaomi
											?DEBUG("mod_kmsns: has not implement for ~s", "xiaomipush");
										_ -> ok
									end
							end
						end;
					_ -> ok
			end
	end.

%% <iq to="YourServer" type="set">
%%   <register xmlns="https://kuaimashi.com/push" >
%%    <appid>APPID</appid>
%%	<apptoken>APPTOKEN</apptoken>
%%	<node>NODE_TYPE</node>  %% 推送服务器节点类型，[apns, jpush]
%% 	<token>DEVICE_TOKEN</token>
%%   </register>
%% </iq>

iq(#jid{user = User, server = Server}, _, #iq{sub_el = SubEl} = IQ) ->
	LUser = jlib:nodeprep(User),
	LServer = jlib:nameprep(Server),

	{MegaSecs, Secs, _MicroSecs} = erlang:timestamp(),
	TimeStamp = MegaSecs * 1000000 + Secs,

	% 设备token
	Token = xml:get_tag_cdata(xml:get_subtag(SubEl, <<"token">>)),
	NodeType = xml:get_tag_cdata(xml:get_subtag(SubEl, <<"node">>)),
	AppID = xml:get_tag_cdata(xml:get_subtag(SubEl, <<"app_id">>)),
	AppToken = xml:get_tag_cdata(xml:get_subtag(SubEl, <<"app_token">>)),

	% -record(kmsns_users, {user, token, last_seen, node_type, app_id, app_token}).
	F = fun() -> mnesia:write(#kmsns_users{user={LUser, LServer}, token=Token, last_seen=TimeStamp, 
		node_type=NodeType, app_id=AppID, app_token=AppToken}) end,

	case mnesia:dirty_read(kmsns_users, {LUser, LServer}) of
		[] ->
			mnesia:transaction(F),
			?DEBUG("mod_kmsns: New user registered ~s@~s", [LUser, LServer]);

		%% Record exists, the key is equal to the one we know
		[#kmsns_users{user={LUser, LServer}, token=Token}] ->
			mnesia:transaction(F),
			?DEBUG("mod_kmsns: Updating last_seen for user ~s@~s", [LUser, LServer]);

		%% Record for this key has been found, but for another key
		[#kmsns_users{user={LUser, LServer}, token=Token}] ->
			mnesia:transaction(F),
			?DEBUG("mod_kmsns: Updating token for user ~s@~s", [LUser, LServer])
		end,
	
	IQ#iq{type=result, sub_el=[]}. %% We don't need the result, but the handler has to send something.


start(Host, _) -> 
	crypto:start(),
	ssl:start(),
	mnesia:create_table(kmsns_users, [{disc_copies, [node()]}, {attributes, record_info(fields, kmsns_users)}]),
	mnesia:create_table(kmsns_certs, [{disc_copies, [node()]}, {attributes, record_info(fields, kmsns_certs)}]),
	gen_iq_handler:add_iq_handler(ejabberd_local, Host, <<?NS_KMSNS>>, ?MODULE, iq, no_queue),
	ejabberd_hooks:add(offline_message_hook, Host, ?MODULE, message, 49),
	?INFO_MSG("mod_kmsns Has started successfully!", []),
	ok.

stop(_) -> ok.


% mod_opt_type(address) -> fun iolist_to_binary/1; %binary_to_list?
% mod_opt_type(port) -> fun(I) when is_integer(I) -> I end;
% mod_opt_type(certfile) -> fun iolist_to_binary/1;
% mod_opt_type(keyfile) -> fun iolist_to_binary/1;
% mod_opt_type(password) -> fun iolist_to_binary/1;
mod_opt_type(certinfo) -> fun iolist_to_binary/1;
mod_opt_type(apnshost) -> fun iolist_to_binary/1;
mod_opt_type(apnsport) -> fun iolist_to_binary/1;
mod_opt_type(env) -> fun iolist_to_binary/1;
mod_opt_type(jpushhost) -> fun iolist_to_binary/1;
mod_opt_type(jpushport) -> fun(I) when is_integer(I) -> I end;
mod_opt_type(_) ->
    [address, port, certfile, keyfile, password].
