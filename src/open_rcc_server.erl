%Module
-module(open_rcc_server).

%Behaviour
-behaviour(gen_server).

%Start Function
-export([start_link/1, mochiweb_loop_http/1, mochiweb_loop_https/1]).

%Gen_Server API
-export([
	init/1,
	handle_call/3,
	handle_cast/2,
	handle_info/2,
	terminate/2,
	code_change/3
]).

-record(state, {} ). %Empty for now.

%OpenACD
-include_lib("OpenACD/include/log.hrl").
-include_lib("OpenACD/include/call.hrl").
-include_lib("OpenACD/include/agent.hrl").
-include_lib("OpenACD/include/queue.hrl").
-include_lib("OpenACD/include/web.hrl").

%% HTTP routines and Responses
-define(RESP_AGENT_NOT_LOGGED, {200, [{"Content-Type", "application/json"}], encode_response(<<"false">>, <<"Agent is not logged in">>)}).
-define(RESP_SUCCESS, {200, [{"Content-Type", "application/json"}], encode_response(<<"true">>)}).
-define(RESP_FAILURE, {200, [{"Content-Type", "application/json"}], encode_response(<<"false">>)}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%% Gen_Server Stuff %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

start_link(Port) ->
	gen_server:start_link({local, ?MODULE}, ?MODULE, [Port], []).

init([Port]) ->
	start_mochiweb(Port),
	{ok, #state{}}.

handle_call({Resource, Req}, _From, State) ->
	QueryString = Req:parse_qs(),
	handle_request(Resource, QueryString, Req),
	{reply, ok, State}.

%% We need these to crash the process early if we starts using gen_cast&gen_info
%% somewhere in the code. But we cannot just remove them since the compiler
%% will show warnings abount unimplemented gen_server callbacks
handle_cast(undefined, State) ->
	{noreply, State}.
handle_info(undefined, State) ->
	{noreply, State}.

terminate(normal, _State) ->
	mochiweb_http:stop(),
	ok;
terminate(_Reason, _State) ->
	ok.

code_change(_, _, State) ->
	{ok, State}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%% Mochi-Web Stuff %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

start_mochiweb(Port) ->
	%% We need to do start_link there to link Mochiweb process into Supervision tree
	%% This process will die if Mochiweb process dies. 
	%% Thus Supervisor has an opportunity to restar boths.
	try
		case application:get_env(open_rcc, use_https) of
			{ok, true} ->
				{ok, Password} = application:get_env(open_rcc, orcc_password),
				{ok, SslCertfile} = application:get_env(open_rcc, cert_file),
				{ok, SslKeyfile} = application:get_env(open_rcc, key_file),
				
				security_manager:start_link(Password),
				mochiweb_http:start([
									{port, Port}, 
									{ssl, true},
										  {ssl_opts, [
												{certfile, SslCertfile},
												{keyfile, SslKeyfile}
											   ]},
									{loop, {?MODULE, mochiweb_loop_https}}]);
			_Else ->
				mochiweb_http:start([{port, Port}, {loop, {?MODULE, mochiweb_loop_http}}])
		end
	catch
		W:Y ->
			Trace = erlang:get_stacktrace(),
			?ERROR("Error starting OpenRCC!!! Here are the details:~n
					{~p, ~p}~n
					Stack Trace:~n
					~p", 
					[W, Y, Trace])
	end.

mochiweb_loop_http(Req) ->
	Path = Req:get(path),
	Resource = case string:str(Path, "?") of
						0 -> Path;
						N -> string:substr(Path, 1, length(Path) - (N + 1))
			   end,
	
	
	QueryString = 
	try
		mochiweb_util:parse_qs(Req:recv_body())
	catch
		_:_ ->
			""
	end,
	
	try 
		log_request(Resource, QueryString),
		handle_request(Resource, QueryString, Req)
	catch
		%% There is always a posibility that agent or call process will die just before we call it
		%% Also REST call could have invalid PID and we cannot check it for sure since there is no
		%% clear way how to check PIDs on remote node
		exit:{noproc, _Rest} ->
			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"false">>, <<"Exception thrown.">>)})
	end.

mochiweb_loop_https(Req) ->
	 
	Path = Req:get(path),
	Resource = case string:str(Path, "?") of
				   0 -> Path;
				   N -> string:substr(Path, 1, length(Path) - (N + 1))
			   end,
	
	QueryString = 
	try
		mochiweb_util:parse_qs(Req:recv_body())
	catch
		_:_ ->
			""
	end,
	
	try   
		log_request(Resource, QueryString),
		  
		case gen_server:call(security_manager, {check_credentials, list_to_integer(proplists:get_value("seconds", QueryString, "1")), 
																				   list_to_integer(proplists:get_value("microsecs", QueryString, "1")),
																				   proplists:get_value("orcc_password", QueryString, undefined)}) of
			allow -> 
				handle_request(Resource, QueryString, Req);
			deny ->
				?WARNING("INTRUSION_ATTEMPT: Mochiweb request was: ~n~p", [Req]),
				Req:respond({200, [{"Content-Type", "application/json"}], 
							encode_response(<<"false">>, <<"Invalid credentials. This incident has been logged and reported.">>)})
		end
	catch
		%% There is always a posibility that agent or call process will die just before we call it
		%% Also REST call could have invalid PID and we cannot check it for sure since there is no
		%% clear way how to check PIDs on remote node
		exit:{noproc, _Rest} ->
			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"false">>, <<"Invalid PID or Agent process has died.">>)});
		W:Y ->
			%% catch-all for all other unexpected exceptions
			Trace = erlang:get_stacktrace(),
			?ERROR("Error in OpenRCC (it is possible this error was gnerated by an intrusion attempt): {~p, ~p}~nStack Trace:~n~p", [W, Y, Trace]),

			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"false">>, <<"Unknown error.">>)})
	end.
	


log_request(Resource, QueryString) ->
	case {Resource, application:get_env(open_rcc, console_loglevel)} of
		{"/ha_status", {ok, debug}} ->
			?DEBUG("Received Parsed Request:~n{~p, ~p}", [Resource, QueryString]);
		{"/ha_status", {ok, _}} ->
			ok;
		{_, _} ->
			?INFO("Received Parsed Request:~n{~p, ~p}", [Resource, QueryString])
	end.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% REST API %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%--------------------------------------------------------------------
%% @doc
%% For testing purposes. Returns the list of previous_times that have been
%% successfuly authentecated over the past security_manager:?WINDOW/2 seconds
%%	HTTP request - <server:port>/get_previous_times
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/get_previous_times", _QueryString, Req) ->
	IntegerList = gen_server:call(security_manager, get_previous_times),
	TimesString = string:join([ erlang:integer_to_list(X) || X <- IntegerList ], ", "),
	Req:respond({200, [{"Content-Type", "application/json"}], mochijson2:encode([{success, <<"true">>}, {times, list_to_binary(TimesString)}])});

%%--------------------------------------------------------------------
%% @doc
%% Login an agent in OpenACD. The agent will be unavaible state.
%%	 HTTP request - <server:port>/login?agent=<agent name>&password=<password>&domain=<SIP domain>
%%		 <agent name> - is an agent name.
%%		 <password> - is password in plain text (Unsecured).
%%		 <SIP domain> - SIP domain name
%%	 The method can return:
%%		 200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/login", QueryString, Req) ->
	Username = proplists:get_value("agent", QueryString, ""),
	Password = proplists:get_value("password", QueryString, ""),
	Domain = proplists:get_value("domain", QueryString, "config.acd.dcf.patlive.local"),
	
	Endpointdata = [ Username, "@", Domain | [] ],
	Endpointtype = pstn,
	
	%% Testing parameter
	%% Endpointdata = Username,
	%% Endpointtype = sip_registration,

	Persistance = transient,
	Bandedness = outband,
	
	case agent_manager:query_agent(Username) of 
		false ->
			AuthResult = agent_auth:auth(Username, Password),
			Respond = handle_login(AuthResult, Username, Password, 
								   {Endpointtype, Endpointdata, Persistance}, Bandedness),
			Req:respond(Respond);
		{true, _PID} ->
			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"false">>, <<"Agent already logged in.">>)})
	end;

%%--------------------------------------------------------------------
%% @doc
%% Logout an agent from OpenACD.
%%	HTTP request - <server:port>/logout?agent=<agent name>
%%				 - <server:port>/logout?agent_pid=<agent pid>
%%		<agent name> - is an agent name.
%%		<agent pid> - is an agent pid.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/logout", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Respond = ?RESP_AGENT_NOT_LOGGED;
		Pid ->
			agent:stop(Pid),
			Respond = ?RESP_SUCCESS
	end,
	Req:respond(Respond);

%%--------------------------------------------------------------------
%% @doc
%% Adds a skill for a given agent.
%%	HTTP request - <server:port>/add_skill?agent=<agent name>&skill=<new skill>
%%				 - <server:port>/add_skill?agent_pid=<agent pid>&skill=<new skill>
%%		<agent name> - is an agent name.
%%		<agent pid> - is an agent pid.
%%			<new skill> - the new skill to be added for the given agent.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/add_skill", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			case proplists:get_value("skill", QueryString, "") of
				"" -> 
					Req:respond({200, [{"Content-Type", "application/json"}], encode_response(<<"false">>, <<"Please specify a valid skill.">>)});
				Skill ->
					try 
						SkillAtom = erlang:list_to_atom(Skill),
						agent:add_skills(Pid, [SkillAtom]),
						Req:respond(?RESP_SUCCESS)
					catch
						W:Y ->
							Respond = {200, [{"Content-Type", "application/json"}], 
											  encode_response(<<"false">>, 
															  erlang:list_to_binary("Unknown error: " ++ 
															  io_lib:format("~p", [W]) ++ 
															  ":" ++ 
															  io_lib:format("~p", [Y])))},
							Req:respond(Respond)
					end	 
			end
	end;

%%--------------------------------------------------------------------
%% @doc
%% Removes a skill for a given agent.
%%	HTTP request - <server:port>/remove_skill?username=<agent name>&skill=<skill>
%%				 - <server:port>/remove_skill?agent_pid=<agent pid>&skill=<skill>
%%		<agent name> - is an agent name.
%%		<agent pid> - is an agent pid.
%%			<new skill> - the skill to be removed from the given agent.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/remove_skill", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			case proplists:get_value("skill", QueryString, "") of
				"" -> 
					Req:respond({200, [{"Content-Type", "application/json"}], encode_response(<<"false">>, <<"Please specify a valid skill.">>)});
				Skill ->
					try 
						SkillAtom = erlang:list_to_atom(Skill),
						agent:remove_skills(Pid, [SkillAtom]),
						Req:respond(?RESP_SUCCESS)
					catch
						W:Y ->
							Respond = {200, 
									  [{"Content-Type", "application/json"}], 
									  encode_response(<<"false">>, 
													  erlang:list_to_binary("Unknown error: " ++ 
													  io_lib:format("~p", [W]) ++ 
													  ":" ++ 
													  io_lib:format("~p", [Y])))},
							Req:respond(Respond)
					end	 
			end
	end;
%%--------------------------------------------------------------------
%% @doc
%% Make an agent avaiable for calls.
%%	HTTP request - <server:port>/set_avail?agent=<agent name>
%%				   <server:port>/set_avail?agent_pid=<agent pid>
%%		<agent name> - is an agent name.
%%		<agent pid> - is an agent pid.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/set_avail", QueryString, Req) ->
	case get_agentpid(QueryString) of 
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			agent:set_state(Pid, idle),
			Req:respond(?RESP_SUCCESS)
	end;

%%--------------------------------------------------------------------
%% @doc
%% End current call on agent and put the agent into wrapup state
%%	HTTP request:
%%			 <server:port>/hangup?agent=<agent name>
%%			 <server:port>/hangup?agent_pid=<agent pid>
%%		<agent name> - is an agent name.
%%		<agent pid> - is an agent pid.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/hangup", QueryString, Req) ->
	case get_agentpid(QueryString) of 
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			%% agent:set_state will not work due to a guard in agent.erl
			#agent{connection=CPid} = agent:dump_state(Pid),
			agent_connection:set_state(CPid, wrapup),
			Req:respond(?RESP_SUCCESS)
	end;

%%--------------------------------------------------------------------
%% @doc
%% Make an agent avaiable for calls after callwork.
%%	HTTP request: 
%%			 <server:port>/hangup?agent=<agent name>
%%			 <server:port>/hangup?agent_pid=<agent pid>
%%		<agent name> - is an agent name.
%%		<agent pid> - is an agent pid.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/end_wrapup", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			%% agent:set_state will not work due to a guard in agent.erl
			#agent{connection=CPid, state=State} = agent:dump_state(Pid),
			case State of
				wrapup ->
					agent_connection:set_state(CPid, idle),
					Req:respond(?RESP_SUCCESS);
				_Other ->
					JSON = encode_response(<<"false">>, <<"Agent not in wrapup. End-wrapup failed.">>),
					Req:respond({200, [{"Content-Type", "application/json"}], JSON})
			end
	end;

%%--------------------------------------------------------------------
%% @doc
%% Returns PID of Agent
%%	HTTP request: 
%%			 <server:port>/get_pid?agent=<agent name>
%%		<agent name> - is an agent name.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/get_pid", QueryString, Req) ->
	AgentName = proplists:get_value("agent", QueryString, ""),
	case agent_manager:query_agent(AgentName) of
		false ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		{true, Pid} ->
			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"true">>, [{pid, to_binary(Pid)}])})
	end;

%%--------------------------------------------------------------------
%% @doc
%% Request information about agent's state
%%	HTTP request: 
%%			 <server:port>/get_call_state?agent=<agent name>
%%			 <server:port>/get_call_state?agent_pid=<agent pid>
%%		<agent name> - is an agent name
%%		<agent pid> - is an agent pid.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------	
handle_request("/get_call_state", QueryString, Req) ->
	case get_agentpid(QueryString) of 
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			#agent{state=State} = agent:dump_state(Pid),
			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"true">>, [{call_state, to_binary(State)}])})
	end;

%%--------------------------------------------------------------------
%% @doc
%% Make an agent unavaiable for calls.
%%	HTTP request:
%%			 <server:port>/set_released?agent=<agent name>
%%			 <server:port>/set_released?agent_pid=<agent pid>
%%		<agent name> - is an agent name.
%%		<agent pid> - is an agent pid.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/set_released", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			NewLabel = proplists:get_value("label", QueryString),
			#agent{state=State, statedata=StateData} = agent:dump_state(Pid),
			case {State, StateData} of
				{released, {Id, Label, Bias}} when Label == NewLabel ->
					JSON = encode_response(<<"true">>,[{message, to_binary(io_lib:format("Agent state already set to ~s", [Label]))}]);
				_Other ->
					Reason = get_released_reason(QueryString),
					agent:set_state(Pid, released, Reason),
					JSON = encode_response(<<"true">>, [{release_data, to_binary(io_lib:format("~w", [_Other]))}])
			end,
			Req:respond({200, [{"Content-Type", "application/json"}], JSON})										
	end;

%%--------------------------------------------------------------------
%% @doc
%% Returns Agent's release state.
%%	HTTP request:
%%			 <server:port>/get_release_state?agent=<agent name>
%%			 <server:port>/get_release_state?agent_pid=<agent pid>
%%		<agent name> - is an agent name.
%%		<agent pid> - is an agent pid.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%%				 and Released state
%% @end
%%--------------------------------------------------------------------
handle_request("/get_release_state", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			AgentState = agent:dump_state(Pid),
			case AgentState#agent.statedata of 
				{Id, Label, Bias} ->
					JSON = encode_response(<<"true">>, 
										   [
											{<<"id">>, to_binary(Id)},
											{<<"label">>, to_binary(Label)},
											{<<"bias">>, to_binary(Bias)}
											]);
				Others ->
					JSON = encode_response(<<"true">>, 
										   [{release_data, to_binary(io_lib:format("~w", [Others]))}])
			end,
			Req:respond({200, [{"Content-Type", "application/json"}], JSON})										
	end;

%%--------------------------------------------------------------------
%% @doc
%% Returns Agent's release state.
%%	HTTP request:
%%			 <server:port>/get_release_opts
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%%				 and Released state
%% @end
%%--------------------------------------------------------------------
handle_request("/get_release_opts", _QueryString, Req) ->
	JSON = encode_response(<<"true">>, [ {release_opts, 
										  lists:map( fun relase_opt_record_to_proplist/1, agent_auth:get_releases())}
									   ]),
	 Req:respond({200, [{"Content-Type", "application/json"}], JSON});

%%--------------------------------------------------------------------
%% @doc
%% Executes silent monitoring of Agent's call. 
%%	 HTTP request: 
%%			  <server:port>/spy?spy=<spy name>&target=<target name>
%%			  <server:port>/spy?spy_pid=<spy pid>&target_pid=<target pid>
%%		  <spy name> is Spy agent name
%%		  <spy pid> is Spy agent pid
%%		  <target name> is Target agent name
%%		  <target pid> is Target agent pid
%%	 The method can return: 
%%		  200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/spy", QueryString, Req) ->
	SpyPid = get_pid(QueryString, "spy_pid", "spy"),
	TargetPid = get_pid(QueryString, "target_pid", "target"),
	case {SpyPid, TargetPid} of 
		{undefined, undefined} ->
			JSON = encode_response(<<"false">>, <<"Spy and target agents are not logged in.">>);
		{undefined, _} ->
			JSON = encode_response(<<"false">>, <<"Spy agent is not logged in">>);
		{_, undefined} ->
			JSON = encode_response(<<"false">>, <<"Target agent is not logged in">>);
		_Else ->
			#agent{statedata = Callrec} = agent:dump_state(TargetPid),
			%% TODO - The operation could fail because a call is dropped just before.
			%% What we need to do there?
			gen_media:spy(Callrec#call.source, SpyPid, agent:dump_state(SpyPid)),
			JSON = encode_response(<<"true">>)
	end,
	Req:respond({200, [{"Content-Type", "application/json"}], JSON});

%%--------------------------------------------------------------------
%% @doc
%% Executes silent monitoring and whisper to Agent.
%%	 HTTP request: 
%%			  <server:port>/coach?coach=<spy name>&target=<target name>
%%			  <server:port>/couch?couch_pid=<spy pid>&target_pid=<target pid>
%%		  <spy name> is Spy agent name
%%		  <spy pid> is Spy agent pid
%%		  <target name> is Target agent name
%%		  <target pid> is Target agent pid
%%	 The method can return: 
%%		  200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/coach", QueryString, Req) ->
	CoachPid = get_pid(QueryString, "coach_pid", "coach"),
	TargetPid = get_pid(QueryString, "target_pid", "target"),
	case {CoachPid, TargetPid} of 
		{undefined, undefined} ->
			JSON = encode_response(<<"false">>, <<"Coach and target agents are not logged in.">>);
		{undefined, _} ->
			JSON = encode_response(<<"false">>, <<"Spy agent is not logged in.">>);
		{_, undefined} ->
			JSON = encode_response(<<"false">>, <<"Coach agent is not logged in.">>);
		_Else ->
			#agent{statedata = Callrec} = agent:dump_state(TargetPid),
			CoachRec = agent:dump_state(CoachPid),

			%% Executes freeswitch_media:spy_single_step in separated process 
			%% since spy_single_step will be blocked until Coach agent picks up a spy call.
			spawn(fun() ->
						  freeswitch_media:spy_single_step(Callrec#call.source, CoachRec, agent)
				  end),
			JSON = encode_response(<<"true">>)
	end,
	Req:respond({200, [{"Content-Type", "application/json"}], JSON});


%%--------------------------------------------------------------------
%% @doc
%% Allows a supervisor to join an agent's call.
%%	 HTTP request: 
%%			  <server:port>/join?coach=<spy name>&target=<target name>
%%			  <server:port>/join?couch_pid=<spy pid>&target_pid=<target pid>
%%		  <spy name> is Spy agent name
%%		  <spy pid> is Spy agent pid
%%		  <target name> is Target agent name
%%		  <target pid> is Target agent pid
%%	 The method can return: 
%%		  200 OK - JSON object contains execution result in 'success' field
%% @end
%%--------------------------------------------------------------------
handle_request("/join", QueryString, Req) ->
	CoachPid = get_pid(QueryString, "coach_pid", "coach"),
	TargetPid = get_pid(QueryString, "target_pid", "target"),
	case {CoachPid, TargetPid} of 
		{undefined, undefined} ->
			JSON = encode_response(<<"false">>, <<"Coach and target agents are not logged in.">>);
		{undefined, _} ->
			JSON = encode_response(<<"false">>, <<"Spy agent is not logged in.">>);
		{_, undefined} ->
			JSON = encode_response(<<"false">>, <<"Coach agent is not logged in.">>);
		_Else ->
			#agent{statedata = Callrec} = agent:dump_state(TargetPid),
			CoachRec = agent:dump_state(CoachPid),

			%% Executes freeswitch_media:spy_single_step in separated process 
			%% since spy_single_step will be blocked until Coach agent picks up a spy call.
			spawn(fun() ->
						  freeswitch_media:spy_single_step(Callrec#call.source, CoachRec, both)
				  end),
			JSON = encode_response(<<"true">>)
	end,
	Req:respond({200, [{"Content-Type", "application/json"}], JSON});

%%--------------------------------------------------------------------
%% @doc
%% Transfer a call from an agent to a queue. The agent will be put in wrapup state
%%	HTTP request: 
%%			 <server:port>/queue_transfer?agent=<agent name>&queue=<queue name>
%%			 <server:port>/queue_transfer?agent_pid=<agent pid>&queue=<queue name>
%%		<agent name> - is an agent name who owns the call
%%		<agent pid> - is an agent pid.
%%		<queue name> - is a queue name where the call will be transfered.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------
handle_request("/queue_transfer", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			QueueName = proplists:get_value("queue", QueryString),
			Result = agent:queue_transfer(Pid, QueueName),
			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"true">>, [
													  { return, to_binary(Result) }
													  ])})
	end;

%%--------------------------------------------------------------------
%% @doc
%% Transfer a call from one agent to another one.
%%	HTTP request:
%%			 <server:port>/agent_transfer?from=<agent name>&to=<target agent>
%%			 <server:port>/agent_transfer?from_pid=<agent pid>&to_pid=<target pid>
%%		<agent name> - is an agent name whom
%%		<agent pid> - is an agent pid
%%		<target agent> - is target agent name
%%		<target pid> - is target agent pid
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------
handle_request("/agent_transfer", QueryString, Req) ->
	FromPid = get_pid(QueryString, "from_pid", "from"),
	ToPid = get_pid(QueryString, "to_pid", "to"),
	case {FromPid, ToPid} of 
		{undefined, undefined} ->
			JSON = encode_response(<<"false">>, <<"Transferer and Transferee agents are not logged in.">>);
		{undefined, _} ->
			JSON = encode_response(<<"false">>, <<"Transferer agent is not logged in.">>);
		{_, undefined} ->
			JSON = encode_response(<<"false">>, <<"Transferee agent is not logged in.">>);
		{FromPid, FromPid} ->
			JSON = encode_response(<<"false">>, <<"Transferer and Transferee agents are equal">>);
		_Else ->
			Result = agent:agent_transfer(FromPid, ToPid),
			JSON = encode_response(<<"true">>, [
												{ return, to_binary(Result) }
											   ])
	end,
	Req:respond({200, [{"Content-Type", "application/json"}], JSON});


%%--------------------------------------------------------------------
%% @doc
%% Cancel an agent transfer.
%%	HTTP request:
%%			 <server:port>/cancel_agent_transfer?agent=<agent name>
%%		<agent name> - is an agent name who is canceling their transfer.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------
handle_request("/cancel_agent_transfer", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			#agent{statedata=Call} = agent:dump_state(Pid),
			#call{source=MPid} = Call,
			freeswitch_media:cancel_agent_transfer(MPid),
			Req:respond(?RESP_SUCCESS)
	end;


%%--------------------------------------------------------------------
%% @doc
%% Complete an agent transfer.
%%	HTTP request:
%%			 <server:port>/complete_agent_transfer?agent=<agent name>
%%		<agent name> - is an agent name who is completing their transfer.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------
handle_request("/complete_agent_transfer", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			#agent{statedata=Call,connection=AgentConnection} = agent:dump_state(Pid),
			TransferState = gen_media:call(AgentConnection, get_media_state),
			case TransferState of
				call_bridged ->
					#call{source=MPid} = Call,
					freeswitch_media:complete_agent_transfer(MPid),
					Req:respond(?RESP_SUCCESS);
				_Else ->
					Req:respond(?RESP_FAILURE)
			end
	end;

%%--------------------------------------------------------------------
%% @doc
%% Transfer a call from an agent to sip endpoint.
%%	HTTP request:
%%			 <server:port>/blind_transfer?agent=<agent name>&dest=<sip endpoint>
%%			 <server:port>/blind_transfer?agent_pid=<agent pid>&dest=<sip endpoint>
%%		<agent name> - is an agent name whom
%%		<agent pid> - is an agent pid
%%		<sip endpoint> - is the target sip endpoint
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------
handle_request("/blind_transfer", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			#agent{statedata = Callrec} = agent:dump_state(Pid),
			Dest = proplists:get_value("dest", QueryString, unspecified_destination),
			gen_media:cast(Callrec#call.source, {blind_transfer, Dest}),
			Req:respond(?RESP_SUCCESS)
	end;
%%--------------------------------------------------------------------
%% @doc
%% Put agent's call to hold/unhold state
%%	HTTP request: 
%%			 <server:port>/toggle_hold?agent=<agent name>
%%			 <server:port>/toggle_hold?agent_pid=<agent pid>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/toggle_hold", QueryString, Req) ->
	case get_agentpid(QueryString) of 
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			#agent{connection=CPid} = agent:dump_state(Pid),
			gen_server:call(CPid, toggle_hold),
			Req:respond(?RESP_SUCCESS)
	end;

%%--------------------------------------------------------------------
%% @doc
%% Dial 3rd party number
%%	HTTP request: 
%%			 <server:port>/contact_3rd_party?agent=<agent name>&dest=<3rd party number>
%%			 <server:port>/contact_3rd_party?agent_pid=<agent pid>&dest=<3rd party number>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%		<3rd party number> - a number to call
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/contact_3rd_party", QueryString, Req) ->
	case get_agentpid(QueryString) of 
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			Dest = proplists:get_value("dest", QueryString, unspecified_destination),
			Profile = proplists:get_value("profile", QueryString, "default"),
			#agent{statedata=Call} = agent:dump_state(Pid),
			#call{source=MPid} = Call,
			freeswitch_media:contact_3rd_party(MPid, Dest, '3rd_party', Profile),
			Req:respond(?RESP_SUCCESS)
	end;

%%--------------------------------------------------------------------
%% @doc
%% Merge Agent, Initial and 3rd party calls into conference
%%	HTTP request: 
%%			 <server:port>/merge_all?agent=<agent name>
%%			 <server:port>/merge_all?agent_pid=<agent pid>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/merge_all", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
		#agent{statedata=Call} = agent:dump_state(Pid),
		#call{source=MPid} = Call,
			freeswitch_media:merge_all(MPid),
			Req:respond(?RESP_SUCCESS)
	end;

%%--------------------------------------------------------------------
%% @doc
%% Merge Only 3rd Party, Place only 3rd party in conference
%%	HTTP request: 
%%			 <server:port>/merge_only_3rd_party?agent=<agent name>
%%			 <server:port>/merge_only_3rd_party?agent_pid=<agent pid>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/merge_only_3rd_party", QueryString, Req) ->
	case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			#agent{statedata=Call} = agent:dump_state(Pid),
			#call{source=MPid} = Call,
			freeswitch_media:merge_only_3rd_party(MPid),
			Req:respond(?RESP_SUCCESS)
	end;

%%--------------------------------------------------------------------
%% @doc
%% Ends a conference assotiated with the agent and drops all active calls 
%% within the conference
%%	HTTP request: 
%%			 <server:port>/end_conference?agent=<agent name>
%%			 <server:port>/end_conference?agent_pid=<agent pid>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/end_conference", QueryString, Req) ->
	case get_agentpid(QueryString) of 
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			#agent{statedata=Call} = agent:dump_state(Pid),
			#call{source=MPid} = Call,
			freeswitch_media:end_conference(MPid),
			Req:respond(?RESP_SUCCESS)
	end;

%%--------------------------------------------------------------------
%% @doc
%% Gets the status of the conference of a given agent.
%%	HTTP request: 
%%			 <server:port>/conference_status?agent=<agent name>
%%			 <server:port>/conference_status?agent_pid=<agent pid>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%%				 and the status of the conference.
%% @end
%%--------------------------------------------------------------------  
handle_request("/conference_status", QueryString, Req) ->
	case get_agentpid(QueryString) of 
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			#agent{statedata=Call} = agent:dump_state(Pid),
			#call{source=MPid} = Call,
			{ok, {_ConferenceID, ConferenceData}} = freeswitch_media:conference_status(MPid),
			NewConferenceData = [encode_status(X) || X <- ConferenceData],
			JSON = encode_response(<<"true">>, [ { return, NewConferenceData } ]),
			Req:respond({200, [{"Content-Type", "application/json"}], JSON})
	end;

%%--------------------------------------------------------------------
%% @doc
%% Kicks the given ID out of the given agent's conference.
%%	HTTP request: 
%%			 <server:port>/conference_kick?agent=<agent name>&id=<id>
%%			 <server:port>/conference_kick?agent_pid=<agent pid>&id=<id>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%		<id> - is the ID of the conference member to kick.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field and
%%					  a message describing the failure if there is one.
%% @end
%%--------------------------------------------------------------------  
handle_request("/conference_kick", QueryString, Req) ->
	case get_agentpid(QueryString) of 
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			ID = proplists:get_value("id", QueryString),
			case ID of
				undefined ->
					JSON = encode_response(<<"false">>, <<"Undefined client ID number.">>),
					Req:respond({200, [{"Content-Type", "application/json"}], JSON});
				ValidID ->
					#agent{statedata=Call} = agent:dump_state(Pid),
					#call{source=MPid} = Call,
					freeswitch_media:conference_kick(MPid, ValidID),
					Req:respond(?RESP_SUCCESS)
			end
	end;

%%--------------------------------------------------------------------
%% @doc
%% Hangs up on the third party of a conference.
%%	HTTP request: 
%%			 <server:port>/hangup_3rd_party?agent=<agent name>
%%			 <server:port>/hangup_3rd_party?agent_pid=<agent pid>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/hangup_3rd_party", QueryString, Req) ->
	 case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			#agent{statedata=Call} = agent:dump_state(Pid),
			#call{source=MPid} = Call,
			freeswitch_media:hangup_3rd_party(MPid),
			Req:respond(?RESP_SUCCESS)
	 end;

%%--------------------------------------------------------------------
%% @doc
%% Retrieves a conference for a given agent:
%%	HTTP request: 
%%			 <server:port>/retrieve_conference?agent=<agent name>
%%			 <server:port>/retrieve_conference?agent_pid=<agent pid>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/retrieve_conference", QueryString, Req) ->
	 case get_agentpid(QueryString) of
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			#agent{statedata=Call} = agent:dump_state(Pid),
	   		#call{source=MPid} = Call,
			freeswitch_media:retrieve_conference(MPid),
			Req:respond(?RESP_SUCCESS)
	 end;

%%--------------------------------------------------------------------
%% @doc
%% Starts a warm transfer for an agent.
%%	HTTP request: 
%%			 <server:port>/start_warm_transfer?agent=<agent name>&number=<number>
%%			 <server:port>/start_warm_transfer?agent_pid=<agent pid>&number=<number
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%		  <number> - is the number to be transfered to
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/start_warm_transfer", QueryString, Req) ->
	 case get_agentpid(QueryString) of
		  undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		  Pid ->
			Number = proplists:get_value("dest", QueryString, unspecified_number),
			#agent{statedata=Call} = agent:dump_state(Pid),
	   		#call{source=MPid} = Call,
			gen_media:warm_transfer_begin(MPid, Number),
			Req:respond(?RESP_SUCCESS)
	 end;

%%--------------------------------------------------------------------
%% @doc
%% Cancels a warm transfer.
%%	HTTP request: 
%%			 <server:port>/cancel_warm_transfer?agent=<agent name>
%%			 <server:port>/cancel_warm_transfer?agent_pid=<agent pid>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/cancel_warm_transfer", QueryString, Req) ->
	 case get_agentpid(QueryString) of
		  undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		  Pid ->
			#agent{statedata=StateData} = agent:dump_state(Pid),
	   		{onhold, #call{source=MPid}, _, _} = StateData,
			gen_media:warm_transfer_cancel(MPid),
			Req:respond(?RESP_SUCCESS)
	 end;

%%--------------------------------------------------------------------
%% @doc
%% Completes a warm transfer.
%%	HTTP request: 
%%			 <server:port>/complete_warm_transfer?agent=<agent name>
%%			 <server:port>/complete_warm_transfer?agent_pid=<agent pid>
%%		<agent name> - is an agent name
%%		<agent pid> - is agent pid
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/complete_warm_transfer", QueryString, Req) ->
	 case get_agentpid(QueryString) of
		  undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		  Pid ->
			#agent{statedata=StateData} = agent:dump_state(Pid),
	   		{onhold, #call{source=MPid}, _, _} = StateData,
			gen_media:warm_transfer_complete(MPid),
			Req:respond(?RESP_SUCCESS)
	 end;

%%--------------------------------------------------------------------
%% @doc
%% Kills a process ID inside of OpenACD.
%%	HTTP request: 
%%			 <server:port>/kill_process?pid=<pid>
%%		<pid> - is the process ID of the process to be killed.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/kill_process", QueryString, Req) -> 
	case proplists:get_value("pid", QueryString, undefined) of
		undefined ->
			Req:respond(?RESP_FAILURE);
		Id ->
			erlang:exit(erlang:list_to_pid(Id), kill),
			Req:respond(?RESP_SUCCESS)
	end;
	
%%--------------------------------------------------------------------
%% @doc
%% Configures OpenRCC's auto-end wrapup procedure.
%%	HTTP request: 
%%			 <server:port>/configure_auto_wrapup?autoend_wrapup=<boolean>&autoend_wrapup_time_ms=<positive_integer>
%%		<boolean> - is whether or not to use auto-end wrapup.
%%		<positive_integer> - is the amount of time to wait before aut-ending wrapup
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/configure_auto_wrapup", QueryString, Req) ->
	case {proplists:get_value("autoend_wrapup", QueryString, undefined), proplists:get_value("autoend_wrapup_time_ms", QueryString, undefined)} of
		{undefined, undefined} ->
			Req:respond(?RESP_FAILURE);
		{undefined, _} ->
			Req:respond(?RESP_FAILURE);
		{_, undefined} ->
			Req:respond(?RESP_FAILURE);
		{AutoEndWrapup, AutoEndWrapupTime} ->
			try
				application:set_env(open_rcc, autoend_wrapup, erlang:list_to_atom(AutoEndWrapup)),
				application:set_env(open_rcc, autoend_wrapup_time_ms, erlang:list_to_integer(AutoEndWrapupTime)),
				Req:respond(?RESP_SUCCESS)
			catch
				W:Y ->
					Trace = erlang:get_stacktrace(),
					?ERROR("Error in open_rcc_server:handle_request(\"/configure_auto_wrapup\", QueryString, Req): {~p, ~p}~nStack Trace:~n~p", [W, Y, Trace]),
					Req:respond(?RESP_FAILURE)
			end
	end;
%%--------------------------------------------------------------------
%% @doc
%% HA Proxy check page that returns the status of the OpenACD node
%%	HTTP request: 
%%			 <server:port>/ha_status
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/ha_status", _QueryString, Req) -> 
	Req:respond({200, [{"Content-Type", "application/json"}], encode_response(<<"true">>, 
																			  [
																			   	{message, <<"Node is up">>},
																				{node, to_binary(erlang:node(erlang:self()))}
																			  ])});

%%--------------------------------------------------------------------
%% @doc
%% Returns the leader node.
%%	HTTP request: 
%%			 <server:port>/get_leader_node
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/get_leader_node", _QueryString, Req) ->
	{ok, LeaderPID} = agent_manager:get_leader(),
	LeaderNode = erlang:node(LeaderPID),
	JSON = mochijson2:encode({struct, [{success, <<"true">>}, {node, list_to_binary(io_lib:format("~p", [LeaderNode]))}]}),
	Req:respond({200, [], JSON});


%%--------------------------------------------------------------------
%% @doc
%% Returns a non-JSON answer to whether this is the leader node.
%%	HTTP request: 
%%			 <server:port>/is_leader_node
%%	The method can return:
%%		true - this is the leader node
%%		false - this is not the leader node 
%%		undefined - the leader node cannot be determined 
%% @end
%%--------------------------------------------------------------------  
handle_request("/is_leader_node", _QueryString, Req) ->
	SelfNode = erlang:node(),
	try
		{ok, LeaderPID} = agent_manager:get_leader(),
		case erlang:node(LeaderPID) of
			SelfNode -> 
				Req:respond({200, [{"Content-Type", "text/html"}], <<"true">>});
			_Else ->
				Req:respond({200, [{"Content-Type", "text/html"}], <<"false">>})
		end
	catch
		_W:_Y ->
			Req:respond({200, [{"Content-Type", "text/html"}], <<"undefined">>})
	end;


%%--------------------------------------------------------------------
%% @doc
%% Returns a JSON string containing the IVR option of the given agent's
%% current call.
%%	HTTP request: 
%%			 <server:port>/get_ivr_options?agent=<agent name>
%%			 <server:port>/get_ivr_options?agent_pid=<agent pid>
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/get_ivr_options", QueryString, Req) ->
	 case get_agentpid(QueryString) of
		  undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		  Pid ->
			#agent{statedata=StateData} = agent:dump_state(Pid),
			case StateData of
				#call{source=MPid} ->
					MediaData = freeswitch_media:statedata(MPid),
					IVROption = proplists:get_value(ivroption, MediaData),
					JSON = encode_response(<<"true">>, [ { ivr_option, to_atom(IVROption) } ]),
					Req:respond({200, [{"Content-Type", "application/json"}], JSON});
				_Other ->
					Req:respond({200, [{"Content-Type", "application/json"}], 
								 encode_response(<<"false">>, <<"Agent not on call.">>)})
			end
	 end;
	
%%--------------------------------------------------------------------
%% @doc
%%  Gets a JSON object containing a list of call UUID's associated with
%% 	queued call priorities.
%%	HTTP request: 
%%			 <server:port>/get_call_priorities
%%		<pid> - is the process ID of the process to be killed.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%%					@TODO describe JSON call/uuid list format.
%% @end
%%--------------------------------------------------------------------  
handle_request("/get_call_priorities", _QueryString, Req) ->
	CallQueueRecordList = call_queue_config:get_queues(),
	CallQueueNameList = [CallQueue#call_queue.name || CallQueue <- CallQueueRecordList],
	QueuedCallsRecords = [{{queue_name, Q}, call_queue:get_calls(queue_manager:get_queue(Q))} || Q <- CallQueueNameList],
	QueuedCallsTupleList = [[MediaPIDTuple, Name, ID, Skills] || {MediaPIDTuple, Name, ID, Skills} <- lists:flatten(
						[[{
						   {media_pid, QueuedCall#queued_call.media},
						   {queue_name, to_atom(QueueName)},
						   {id, to_atom(QueuedCall#queued_call.id)},
						   {skills, [skill_to_json(Skill) || Skill <- QueuedCall#queued_call.skills]}} || {_Key, QueuedCall} <- QueuedCalls]
						|| {{queue_name, QueueName}, QueuedCalls} <- QueuedCallsRecords])],
	
	QueuedCallsRecordList = [ gen_media:get_call(MediaPID) ||  [{media_pid, MediaPID}, _QueueNameTuple, _ID, _Skills] <- QueuedCallsTupleList],
	UUIDandPriorityList = [ [to_atom(CallRecord#call.id), to_atom(CallRecord#call.priority)] ||  CallRecord <- QueuedCallsRecordList],
	JSON = mochijson2:encode([{success, <<"true">>}, {call_priorities, UUIDandPriorityList}]),
	Req:respond({200, [{"Content-Type", "application/json"}], JSON});

%%--------------------------------------------------------------------
%% @doc
%%  Sets the priority of the queued call with the given UUID.
%%	HTTP request: 
%%			 <server:port>/set_call_priority?call_uuid=<call uuid>&priority=<new priority>
%%		<call uuid> - is the UUID of the queued call have its priority modified.
%%		<new priority> - is the new priority of the queued call with the given UUID. 
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%%      		true: call was found and priority was set.
%%				false: call was not found and priority was not set. 
%% @end
%%--------------------------------------------------------------------  
handle_request("/set_call_priority", QueryString, Req) ->
	CallUUID = proplists:get_value("call_uuid", QueryString, undefined),
	NewPriority = proplists:get_value("priority", QueryString, undefined),
	case {CallUUID, NewPriority} of
		{undefined, _} ->
			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"false">>, <<"Undefined UUID.">>)});
		{_, undefined} ->
			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"false">>, <<"Undefined priority.">>)});
		{_, _} ->
			CallQueueRecordList = call_queue_config:get_queues(),
			CallQueueNameList = [CallQueue#call_queue.name || CallQueue <- CallQueueRecordList],
			QueuedCallsRecords = [{{queue_name, Q}, call_queue:get_calls(queue_manager:get_queue(Q))} || Q <- CallQueueNameList],
			QueuedCallsTupleList = [[MediaPIDTuple, Name, ID, Skills] || {MediaPIDTuple, Name, ID, Skills} <- lists:flatten(
								[[{
								   {media_pid, QueuedCall#queued_call.media},
								   {queue_name, to_atom(QueueName)},
								   {id, to_atom(QueuedCall#queued_call.id)},
								   {skills, [skill_to_json(Skill) || Skill <- QueuedCall#queued_call.skills]}} || {_Key, QueuedCall} <- QueuedCalls]
								|| {{queue_name, QueueName}, QueuedCalls} <- QueuedCallsRecords])],
			
			QueuedCallsRecordList = [ {gen_media:get_call(MediaPID), QueueName} ||  [{media_pid, MediaPID}, {queue_name, QueueName}, _ID, _Skills] <- QueuedCallsTupleList],
			UUIDandCallRecordList = [ {CallRecord#call.id, {CallRecord, QueueName}} ||  {CallRecord, QueueName} <- QueuedCallsRecordList],
			case proplists:get_value(CallUUID, UUIDandCallRecordList, undefined) of
				undefined ->
					Req:respond({200, [{"Content-Type", "application/json"}], 
								 encode_response(<<"false">>, <<"Could not find queued call by UUID.">>)});
				{CallRecord, QueueName} ->
					case queue_manager:get_queue(erlang:atom_to_list(QueueName)) of
						undefined ->
							Req:respond({200, [{"Content-Type", "application/json"}], 
										 encode_response(<<"false">>, <<"Internal Error: could not find queue by name.">>)});
						QueuePID ->
%% 							gen_media:set_priority(CallRecord#call.source, erlang:list_to_integer(NewPriority), QueueName, erlang:now()),
%% 							?DEBUG("~p, ~p", [QueuePID, CallRecord#call.source]),
 							call_queue:set_priority(QueuePID, CallRecord#call.source, NewPriority),
							call_queue:remove(QueuePID, CallRecord#call.source),
							call_queue:add(QueuePID, CallRecord#call.source, CallRecord),
							Req:respond(?RESP_SUCCESS)
					end
			end
	end;

%%--------------------------------------------------------------------
%% @doc
%% Puts the given agent's call on hold if it is not already.
%%	HTTP request: 
%%			 <server:port>/hold?agent=<agent name>
%%			 <server:port>/hold?agent_pid=<agent pid>
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/hold", QueryString, Req) ->
	case get_agentpid(QueryString) of 
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			#agent{connection=CPid} = agent:dump_state(Pid),
			gen_server:call(CPid, hold),
			Req:respond(?RESP_SUCCESS)
	end;
	
%%--------------------------------------------------------------------
%% @doc
%% Takes the given agent's call off hold if it is not already.
%%	HTTP request: 
%%			 <server:port>/unhold?agent=<agent name>
%%			 <server:port>/unhold?agent_pid=<agent pid>
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/unhold", QueryString, Req) ->
	case get_agentpid(QueryString) of 
		undefined ->
			Req:respond(?RESP_AGENT_NOT_LOGGED);
		Pid ->
			#agent{connection=CPid} = agent:dump_state(Pid),
			gen_server:call(CPid, unhold),
			Req:respond(?RESP_SUCCESS)
	end;
	
%%--------------------------------------------------------------------
%% @doc
%% Returns a JSON object containing the record data of all the agents
%% currently logged in.
%%	HTTP request: 
%%			 <server:port>/get_agent_list
%%	The method can return:
%%		200 OK - JSON object containing all logged in agent records
%% @end
%%--------------------------------------------------------------------  
handle_request("/get_agent_list", _QueryString, Req) ->
	JSON = get_agent_list_JSON(),
	Req:respond({200, [{"Content-Type", "application/json"}], JSON});

%%--------------------------------------------------------------------
%% @doc
%% Returns a JSON object containing the names and states of all the agents
%% currently logged in.
%%	HTTP request: 
%%			 <server:port>/get_short_agent_list
%%	The method can return:
%%		200 OK - JSON object containing all logged in agent names and states
%% @end
%%--------------------------------------------------------------------  
handle_request("/get_short_agent_list", _QueryString, Req) ->
	AvailabilityList = agent_manager:list(),
	NameList = [AgentName || {AgentName, _} <- AvailabilityList],
	AgentRecords = [agent:dump_state(cpx:get_agent(Name)) || Name <- NameList],
	UnencodedJSON = [{short_agent_list, [[{login, to_atom(Record#agent.login)}, {state, to_atom(Record#agent.state)}] || Record <- AgentRecords]}],
	Req:respond({200, [{"Content-Type", "application/json"}], mochijson2:encode(UnencodedJSON)});

%%--------------------------------------------------------------------
%% @doc
%%  Kicks the call with the given UUID.
%%	HTTP request: 
%%			 <server:port>/kick_call?call_uuid=<call uuid>
%%		<call uuid> - is the UUID of the call to be kicked
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%%      		true: call was found and kicked
%%				false: call was not found and was not kicked 
%% @end
%%--------------------------------------------------------------------  
handle_request("/kick_call", QueryString, Req) ->
	CallUUID = proplists:get_value("call_uuid", QueryString, undefined),
	case CallUUID of
		undefined ->
			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"false">>, <<"Undefined UUID.">>)});
		_ ->
			CallQueueRecordList = call_queue_config:get_queues(),
			CallQueueNameList = [CallQueue#call_queue.name || CallQueue <- CallQueueRecordList],
			QueuedCallsRecords = [{{queue_name, Q}, call_queue:get_calls(queue_manager:get_queue(Q))} || Q <- CallQueueNameList],
			QueuedCallsTupleList = [[MediaPIDTuple, Name, ID, Skills] || {MediaPIDTuple, Name, ID, Skills} <- lists:flatten(
								[[{
								   {media_pid, QueuedCall#queued_call.media},
								   {queue_name, to_atom(QueueName)},
								   {id, to_atom(QueuedCall#queued_call.id)},
								   {skills, [skill_to_json(Skill) || Skill <- QueuedCall#queued_call.skills]}} || {_Key, QueuedCall} <- QueuedCalls]
								|| {{queue_name, QueueName}, QueuedCalls} <- QueuedCallsRecords])],
			
			QueuedCallsRecordList = [ {gen_media:get_call(MediaPID), QueueName} ||  [{media_pid, MediaPID}, {queue_name, QueueName}, _ID, _Skills] <- QueuedCallsTupleList],
			UUIDandCallRecordList = [ {CallRecord#call.id, {CallRecord, QueueName}} ||  {CallRecord, QueueName} <- QueuedCallsRecordList],
			case proplists:get_value(CallUUID, UUIDandCallRecordList, undefined) of
				undefined ->
					Req:respond({200, [{"Content-Type", "application/json"}], 
								 encode_response(<<"false">>, <<"Could not find queued call by UUID.">>)});
				{CallRecord, _QueueName} ->
					MPID = CallRecord#call.source,
					cpx:kick_call(MPID),
					Req:respond(?RESP_SUCCESS)
			end
	end;

%%--------------------------------------------------------------------
%% @doc
%%  Kicks the given agent.
%%	HTTP request: 
%%			 <server:port>/kick_agent?agent=<agent name>
%%		<agent name> - is the name of the agent to be kicked
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field
%%      		true: agent was found and kicked
%%				false: agent was not found and was not kicked 
%% @end
%%--------------------------------------------------------------------  
handle_request("/kick_agent", QueryString, Req) ->
	 case get_agentpid(QueryString) of
		  undefined ->
			  Req:respond(?RESP_AGENT_NOT_LOGGED);
		  Pid ->
			  cpx:kick_agent(Pid),
			  Req:respond(?RESP_SUCCESS)
	 end;

%%--------------------------------------------------------------------
%% @doc
%%  Starts recording for a conference. Places the recording in the given
%%  filename in the /tmp folder.
%%	HTTP request: 
%%			 <server:port>/start_conference_recording?agent=<agent name>&filename=<filename>
%%		<agent name> - is the agent who started the conference to be recorded.
%%		<filename> - is the name of the file in the /tmp folder to store the .wav data
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/start_conference_recording", QueryString, Req) ->
	
	try
		case get_agentpid(QueryString) of
			undefined ->
				Req:respond(?RESP_AGENT_NOT_LOGGED);
			Pid ->
				#agent{statedata=StateData} = agent:dump_state(Pid),
				case StateData of
					#call{source=MPid} ->
						MediaData = freeswitch_media:statedata(MPid),
						FSNode = proplists:get_value(cnode, MediaData),
						ConferenceID = proplists:get_value(conference_id, MediaData),
						case ConferenceID of
							undefined ->
								Req:respond({200, [{"Content-Type", "application/json"}], 
										encode_response(<<"false">>, <<"Agent not in conference.">>)});
							_ ->
								case proplists:get_value("filename", QueryString, undefined) of
									undefined ->
										Req:respond({200, [{"Content-Type", "application/json"}], 
												encode_response(<<"false">>, <<"File name not specified.">>)});
									ConferenceFile ->
										freeswitch:api(FSNode, conference, ConferenceID ++ " record /tmp/" ++ ConferenceFile),
										Req:respond(?RESP_SUCCESS)
								end
						end;
					_Other ->
						Req:respond({200, [{"Content-Type", "application/json"}], 
								encode_response(<<"false">>, <<"Agent not on call.">>)})
				end
		end
	catch
		_W:_Y ->
			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"false">>, <<"Internal error.">>)})
	end;

%%--------------------------------------------------------------------
%% @doc
%%  Starts recording for a agent. Places the recording in the given
%%  filename in the /tmp folder.
%%	HTTP request: 
%%			 <server:port>/start_agent_recording?agent=<agent name>&filename=<filename>
%%		<agent name> - is the agent who is currently oncall
%%		<filename> - is the path of the file to store the .wav data
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/start_agent_recording", QueryString, Req) ->
	try
		case get_agentpid(QueryString) of
			undefined ->
				Req:respond(?RESP_AGENT_NOT_LOGGED);
			Pid ->
				#agent{statedata=StateData} = agent:dump_state(Pid),
				case StateData of
					#call{source=MPid} ->
						MediaData = freeswitch_media:statedata(MPid),
						FSNode = proplists:get_value(cnode, MediaData),
						AgentRingChannel = proplists:get_value(ringchannel, MediaData),
						case AgentRingChannel of
							undefined ->
								Req:respond({200, [{"Content-Type", "application/json"}], 
										encode_response(<<"false">>, <<"Agent has no ring channel.">>)});
							_ ->
								AgentUUID = freeswitch_ring:get_uuid(AgentRingChannel),
								case proplists:get_value("filename", QueryString, undefined) of
									undefined ->
										Req:respond({200, [{"Content-Type", "application/json"}], 
												encode_response(<<"false">>, <<"File name not specified.">>)});
									RecordingFile ->
										%%(the call will be hungup if creating the recording file fails)
										freeswitch:api(FSNode, uuid_record, AgentUUID ++ " start " ++ RecordingFile),
										Req:respond(?RESP_SUCCESS)
								end
						end;
					_Other ->
						Req:respond({200, [{"Content-Type", "application/json"}], 
								encode_response(<<"false">>, <<"Agent not on call.">>)})
				end
		end
	catch
		_W:_Y ->
			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"false">>, <<"Internal error.">>)})
	end;
  
%%--------------------------------------------------------------------
%% @doc
%%  Stops recording for a agent.
%%	HTTP request: 
%%			 <server:port>/start_agent_recording?agent=<agent name>&filename=<filename>
%%		<agent name> - is the agent who is currently oncall
%%		<filename> - is the path of the file to store the .wav data
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%--------------------------------------------------------------------  
handle_request("/stop_agent_recording", QueryString, Req) ->
	try
		case get_agentpid(QueryString) of
			undefined ->
				Req:respond(?RESP_AGENT_NOT_LOGGED);
			Pid ->
				#agent{statedata=StateData} = agent:dump_state(Pid),
				case StateData of
					#call{source=MPid} ->
						MediaData = freeswitch_media:statedata(MPid),
						FSNode = proplists:get_value(cnode, MediaData),
						AgentRingChannel = proplists:get_value(ringchannel, MediaData),
						case AgentRingChannel of
							undefined ->
								Req:respond({200, [{"Content-Type", "application/json"}], 
										encode_response(<<"false">>, <<"Agent has no ring channel.">>)});
							_ ->
								AgentUUID = freeswitch_ring:get_uuid(AgentRingChannel),
								case proplists:get_value("filename", QueryString, undefined) of
									undefined ->
										Req:respond({200, [{"Content-Type", "application/json"}], 
												encode_response(<<"false">>, <<"File name not specified.">>)});
									RecordingFile ->
										freeswitch:api(FSNode, uuid_record, AgentUUID ++ " stop " ++ RecordingFile),
										Req:respond(?RESP_SUCCESS)
								end
						end;
					_Other ->
						Req:respond({200, [{"Content-Type", "application/json"}], 
								encode_response(<<"false">>, <<"Agent not on call.">>)})
				end
		end
	catch
		_W:_Y ->
			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"false">>, <<"Internal error.">>)})
	end;

%%--------------------------------------------------------------------
%% @doc
%%  Returns the list of skills available for weighting.
%%	HTTP request: 
%%			 <server:port>/get_skill_list
%%	The method can return:
%%					@TODO describe JSON skill list format.
%% @end
%%--------------------------------------------------------------------  
handle_request("/get_skill_list", _QueryString, Req) ->
	JSON = get_skill_list_json(),
	Req:respond({200, [{"Content-Type", "application/json"}], JSON});

%%--------------------------------------------------------------------
%% @doc
%%  Returns the default skill weight.
%%	HTTP request: 
%%			 <server:port>/get_default_skill_weight
%%	The method can return:
%%					@TODO describe JSON default skill weight format.
%% @end
%%-------------------------------------------------------------------- 
handle_request("/get_default_skill_weight", _QueryString, Req) ->
	DefaultSkillWeight = agent_manager:get_default_skill_weight(),
	JSON = mochijson2:encode([{default_skill_weight, DefaultSkillWeight}]),
	Req:respond({200, [{"Content-Type", "application/json"}], JSON});

%%--------------------------------------------------------------------
%% @doc
%%  Sets the default skill weight.
%%	HTTP request: 
%%			 <server:port>/set_default_skill_weight
%%	The method can return:
%%					@TODO describe JSON default skill weight format.
%% @end
%%-------------------------------------------------------------------- 
%handle_request("/set_default_skill_weight", QueryString, Req) ->
% @TODO write this function.. Must modify app.config for perminant reset.

%%--------------------------------------------------------------------
%% @doc
%%  Returns the list of skills associated with a particular agent.
%%	HTTP request: 
%%			 <server:port>/get_agent_skills?agent=<agent name>
%%		<agent name> - is the agent to get skills for.
%%	The method can return:
%%					@TODO describe JSON agent skills list format.
%% @end
%%-------------------------------------------------------------------- 
handle_request("/get_agent_skills", QueryString, Req) ->
	case proplists:get_value("agent", QueryString, undefined) of
		undefined ->
			Req:respond({200, [{"Content-Type", "application/json"}], 
						 encode_response(<<"false">>, <<"Agent name not given.">>)});
		AgentName ->
			AgentAuthRecordList = agent_auth:get_agents(),
			AgentInList = [Agent || Agent <- AgentAuthRecordList, Agent#agent_auth.login == AgentName],
			case erlang:length(AgentInList) of
				1 ->
					[AgentAuth] = AgentInList,
					SkillsList = AgentAuth#agent_auth.skills,
					UnencodedJSON = [{skills, [erlang:list_to_atom(term_to_string(Skill)) || Skill <- SkillsList]}],
					JSON = mochijson2:encode(UnencodedJSON),
					Req:respond({200, [{"Content-Type", "application/json"}], JSON});
				_ ->
					Req:respond({200, [{"Content-Type", "application/json"}], 
								 encode_response(<<"false">>, <<"Ambiguous [#agent_auth{}] found.">>)})
			end
	end;

%%--------------------------------------------------------------------
%% @doc
%%  Returns the list of weights of the skills associated with a particular agent.
%%	HTTP request: 
%%			 <server:port>/get_agent_skill_weights?agent=<agent name>
%%		<agent name> - is the agent to get skill weights for.
%%	The method can return:
%%					@TODO describe JSON agent skills list format.
%% @end
%%-------------------------------------------------------------------- 
handle_request("/get_agent_skill_weights", QueryString, Req) ->
	case get_agentpid(QueryString) of
			undefined ->
				Req:respond(?RESP_AGENT_NOT_LOGGED);
			Pid ->
				AllSkills = (agent:dump_state(Pid))#agent.skills,
				WeightedSkills = agent:get_skill_weights(Pid),
				DefaultSkillWeight = agent_manager:get_default_skill_weight(),
				UnencodedJSON = [{success, <<"true">>}, {weights, [{to_atom(Skill), to_atom(proplists:get_value(Skill, WeightedSkills, DefaultSkillWeight))} || Skill <- AllSkills]}],
				Req:respond({200, [{"Content-Type", "application/json"}], mochijson2:encode(UnencodedJSON)})
	end;

%%--------------------------------------------------------------------
%% @doc
%%  Sets the weight of the skills for the given agent. Any skills the 
%%  agent has, as given by "/get_agent_skills", that do not have their
%%  weight modified by this method stay at the default weight, as 
%%  given by "/get_default_skill_weight". THIS DOES NOT WORK ON MAGIC SKILLS.
%%	Even though the values supplied as skill names in the skill_weights_json 
%%  field should be surrounded by quotes, the word in the quotes must be 
%%	equal to the atom of the skill being modified.
%%	HTTP request: 
%%			 <server:port>/set_agent_skill_weights?agent=<agent name>&skill_weights_json=<new weights>
%%		<agent name> - is the agent to set skill weights for.
%%		<new weights> - is a json string with the new skill weights.
%%					EXAMPLE:
%%						agent=200&skill_weights_json={"english":"100","german":"101"}
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%-------------------------------------------------------------------- 
handle_request("/set_agent_skill_weights", QueryString, Req) ->
	case get_agentpid(QueryString) of
			undefined ->
				Req:respond(?RESP_AGENT_NOT_LOGGED);
			Pid ->
				case proplists:get_value("skill_weights_json", QueryString) of
					undefined ->
						Req:respond({200, [{"Content-Type", "application/json"}], 
									 encode_response(<<"false">>, <<"No skill weight json provided.">>)});
					JSONParameter ->
						try
							{struct, SkillWeightStruct} = mochijson2:decode(JSONParameter),
							[agent:set_particular_skill_weight(Pid,
															   erlang:list_to_atom(erlang:binary_to_list(Skill)), 
												   			   erlang:list_to_integer(erlang:binary_to_list(Weight)))
															   || {Skill, Weight} <- SkillWeightStruct],
							Req:respond(?RESP_SUCCESS)
						catch
							_W:_Y ->
								Req:respond({200, [{"Content-Type", "application/json"}], 
											 encode_response(<<"false">>, <<"Could not read provided skill weight JSON.">>)})
						end
				end
	end;

%%--------------------------------------------------------------------
%% @doc
%%	Just prints an 'INFO' level event to the logs. This was to test the
%%	mochiweb POST argument parser.
%%			<server:port>/info?message=<message>
%%		<message> - is the message to print.
%%	The method can return:
%%		200 OK - JSON object contains execution result in 'success' field 
%% @end
%%-------------------------------------------------------------------- 
handle_request("/info", QueryString, Req) ->
	?INFO("Message received: ~p", [proplists:get_value("message", QueryString, "\"/info\" has been called (with no message provided).")]),
	Req:respond(?RESP_SUCCESS);

%%--------------------------------------------------------------------
%% @doc
%%	Returns the number of erlang processes currently running.
%%			<server:port>/num_erl_processes
%%	The method can return:
%%		A plain-text integer indicating the number of erlang processes running
%% @end
%%-------------------------------------------------------------------- 
handle_request("/num_erl_processes", _QueryString, Req) ->
	Req:respond({404, [{"Content-Type", "text/html"}], erlang:list_to_binary(erlang:integer_to_list(erlang:length(erlang:processes())))});

handle_request(_Path, _QueryString, Req) ->
	Req:respond({404, [{"Content-Type", "text/html"}], <<"Not Found.">>}).

%%%===================================================================
%%% Internal functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Checks a authorization result and tries to login an agent into OpenACD
%% @end
%%--------------------------------------------------------------------
handle_login({allow, Id, Skills, Security, Profile}=_AuthResult, 
			 Username, Password, {Endpointtype, Endpointdata, Persistance}=Endpoint, 
			 Bandedness) ->
	Agent = #agent{
	  id = Id, 
	  defaultringpath = Bandedness, 
	  login = Username, 
	  skills = Skills, 
	  profile=Profile, 
	  password=Password,
	  endpointtype = Endpointtype,
	  endpointdata = Endpointdata,
	  security_level = Security
	 },
	{ok, Pid} = agent_connection:start(Agent),
	Node = erlang:node(Pid),
	?INFO("~s logged in with endpoint ~p", [Username, Endpoint]),
	agent_connection:set_endpoint(Pid, {Endpointtype, Endpointdata}, Persistance),
	AgentPid = agent_connection:get_agentpid(Pid),
	{200, [{"Content-Type", "application/json"}], encode_response(<<"true">>, 
										[
										 {node, to_binary(Node)}, 
										 {pid, to_binary(AgentPid)}
									   ])};
handle_login(_AuthResult, _Username, _Password, _Endpoint, _Bandedness) ->
	{200, [{"Content-Type", "application/json"}], encode_response(<<"false">>, <<"Invalid username and/or password.">>)}.


%%--------------------------------------------------------------------
%% @doc
%% Extracts AgentPID from HTTP Query string.
%% @end
%%--------------------------------------------------------------------
get_agentpid(QueryString) ->
	get_pid(QueryString, "agent_pid", "agent").


%%--------------------------------------------------------------------
%% @doc
%% Extracts PID from Query string. If 'pid' parameter is not defined 
%% when 'agent' will be used to get Agent PID registered in agent_manager
%% @end
%%--------------------------------------------------------------------
get_pid(QueryString, Pid, Name) ->
	case proplists:get_value(Pid, QueryString) of 
		undefined ->
			get_pid(Name, QueryString);
		Value ->
			%% erlang:is_process_alive will not work with remote nodes
			%% So we need another way to check Pid validity
			to_pid(Value)
	end.
get_pid(Name, QueryString) ->
	Value = proplists:get_value(Name, QueryString, ""),
	case agent_manager:query_agent(Value) of
		false ->
			undefined;
		{true, Pid} ->
			Pid
	end.

%%--------------------------------------------------------------------
%% @doc
%% Extract and format Release reason
%% @end
%%--------------------------------------------------------------------
get_released_reason(QueryString) ->
	Id = proplists:get_value("id", QueryString),
	Label = proplists:get_value("label", QueryString),
	Bias = proplists:get_value("bias", QueryString),
	get_released_reason(Id, Label, Bias).

get_released_reason(undefined, _, _) ->
	default;
get_released_reason(_, undefined, _) ->
	default;
get_released_reason(_, _, undefined) ->
	default;
get_released_reason(Id, Label, Bias) ->
	{Id, Label, list_to_integer(Bias)}.

%%--------------------------------------------------------------------
%% @doc
%% Encode responce in JSON format
%% @end
%%--------------------------------------------------------------------
encode_response(Result) ->
	mochijson2:encode([{success, Result}]).

encode_response(Result, Message) when is_binary(Message) ->
	mochijson2:encode([{success, Result}, {message, Message}]);
encode_response(Result, Rest) when is_list(Rest) ->
	mochijson2:encode([{success, Result} | Rest]).

% Utility functions for converting a #release_opt record (located in agent.hrl) into a property list. 
% These functions are used to convert a list of #release_opt's into a JSON string.
relase_opt_record_to_proplist(#release_opt{} = Rec) ->
  lists:zip(record_info(fields, release_opt), lists:map(fun to_binary/1, tl(tuple_to_list(Rec)))).

%%--------------------------------------------------------------------
%% @doc
%% Convert terms into binary format. 
%% List, Atom, Pid, Integer and Binary are supported for now
%% @end
%%--------------------------------------------------------------------
to_binary(Var) when is_list(Var) ->
	list_to_binary(Var);
to_binary(Var) when is_atom(Var) ->
	atom_to_binary(Var, latin1);
to_binary(Var) when is_pid(Var) ->
	list_to_binary(pid_to_list(Var));
to_binary(Var) when is_binary(Var) ->
	Var;
to_binary(Var) when is_integer(Var) ->
	list_to_binary(integer_to_list(Var)).
%%--------------------------------------------------------------------
%% @doc
%% Convert List or Binary to Pid
%% @end
%%--------------------------------------------------------------------
to_pid(Var) when is_binary(Var) ->
	list_to_pid(binary_to_list(Var));
to_pid(Var) when is_list(Var) ->
	list_to_pid(Var);
to_pid(Var) when is_pid(Var) ->
	Var.

%%--------------------------------------------------------------------
%% @doc
%% Returns a JSON object containing the names of all possible skills.
%% @end
%%--------------------------------------------------------------------
get_skill_list_json() -> 
	SkillRecordsList = call_queue_config:get_skills(),
	UnencodedJSON = [{skill_list, [SkillRecord#skill_rec.atom || SkillRecord <- SkillRecordsList]}],
	mochijson2:encode(UnencodedJSON).

%%--------------------------------------------------------------------
%% @doc
%% Returns a JSON object containing the record data of all agents
%% currently logged in.
%% @end
%%--------------------------------------------------------------------
get_agent_list_JSON() ->
	AvailabilityList = agent_manager:list(),
	NameList = [AgentName || {AgentName, _} <- AvailabilityList],
	AgentRecords = [agent:dump_state(cpx:get_agent(Name)) || Name <- NameList],
	UnencodedJSON = [{agent_list, [agent_record_to_json(Record) || Record <- AgentRecords]}],
	mochijson2:encode(UnencodedJSON).
%%--------------------------------------------------------------------
%% @doc
%% Formats the fields of an individual #agent record into a JSON object
%% @end
%%--------------------------------------------------------------------
agent_record_to_json(AgentRecord) ->
	StateData = case AgentRecord#agent.state of
		ringing ->
			call_to_json(AgentRecord#agent.statedata);
		oncall ->
			call_to_json(AgentRecord#agent.statedata);
		outgoing ->
			call_to_json(AgentRecord#agent.statedata);
		wrapup ->
			call_to_json(AgentRecord#agent.statedata);
		released ->
			[{release_data, release_to_json(AgentRecord#agent.statedata)}];
		warmtransfer ->
			{onhold, Call, calling, _SomeString} = AgentRecord#agent.statedata,
			call_to_json(Call);
		_ ->
			[]
	end,
	[{login, to_atom(AgentRecord#agent.login)},
	 {id, to_atom(AgentRecord#agent.id)},
	 {skills, [skill_to_json(S) || S <- AgentRecord#agent.skills]},
	 {profile, to_atom(AgentRecord#agent.profile)},
	 {state, to_atom(AgentRecord#agent.state)}]
	 ++ StateData.
%%--------------------------------------------------------------------
%% @doc
%% Formats the fields of an individual #call record into a JSON object
%% @end
%%--------------------------------------------------------------------
call_to_json(Call) ->
	[{ call, [
		{id, to_atom(Call#call.id)},
		{type, to_atom(Call#call.type)},
		{caller_id, [
			{name, to_atom(element(1, Call#call.callerid))},
			{data, to_atom(element(2, Call#call.callerid))}]},
		{dnis, to_atom(Call#call.dnis)},
		{client, client_to_json(Call#call.client)},
		{ring_path, to_atom(Call#call.ring_path)},
		{media_path, to_atom(Call#call.media_path)},
		{direction, to_atom(Call#call.direction)},
		{node, to_atom(node(Call#call.source))}
	]}].

%%--------------------------------------------------------------------
%% @doc
%% Formats an OpenACD 'skills' element into mochijson2:encode/1-compatible
%% term.
%% @end
%%--------------------------------------------------------------------
skill_to_json({Atom, Expanded}) when is_list(Expanded) ->
	[Atom, erlang:list_to_atom(Expanded)];
skill_to_json({Atom, Expanded}) ->
	[Atom, erlang:list_to_atom(term_to_string(Expanded))];
skill_to_json(Atom) when is_atom(Atom) ->
	Atom.

%%--------------------------------------------------------------------
%% @doc
%% Formats an OpenACD 'client' element into mochijson2:encode/1-compatible
%% term.
%% @end
%%--------------------------------------------------------------------
client_to_json(Client) ->
  	IsDefault = case Client#client.id of undefined -> true; _ -> false end,
	Label = case erlang:is_list(Client#client.label) of true -> erlang:list_to_atom(Client#client.label); _ -> Client#client.label end,
	ID = case erlang:is_list(Client#client.id) of true -> erlang:list_to_atom(Client#client.id); _ -> Client#client.id end, 
	[[is_default, IsDefault], [name, Label], [id, ID]].

%%--------------------------------------------------------------------
%% @doc
%% Formats an OpenACD 'release state' element into mochijson2:encode/1-compatible
%% term.
%% @end
%%--------------------------------------------------------------------
release_to_json(default) ->
	[{id, default}, {label, default}, {bias, '0'}];
release_to_json(R) when is_record(R, release_opt) ->
	release_to_json({R#release_opt.id, R#release_opt.label, R#release_opt.bias});
release_to_json({Id, RawLabel, Bias}) ->
	[{id, to_atom(Id)}, {label, to_atom(RawLabel)}, {bias, to_atom(Bias)}].

%%--------------------------------------------------------------------
%% @doc
%% Encode conference status. Used by handle_request/3
%% @end
%%--------------------------------------------------------------------
encode_status(ConferenceStatus) ->
  [{X,erlang:list_to_binary(Y)} || {X, Y} <- ConferenceStatus].


to_atom(Term) ->
	case io_lib:printable_list(Term) of
		true ->
			erlang:list_to_atom(Term);
		_ ->
			to_atom2(Term)
	end.

to_atom2(Term) when erlang:is_atom(Term) ->
	Term;
to_atom2(Term) when erlang:is_integer(Term) ->
	erlang:list_to_atom(erlang:integer_to_list(Term));
to_atom2(Term) when erlang:is_pid(Term) ->
	erlang:list_to_atom(erlang:pid_to_list(Term));
to_atom2(Term) ->
	erlang:list_to_atom(term_to_string(Term)).

term_to_string(Term)->
	re:replace(lists:flatten(io_lib:format("~1000000p", [Term])), "\\n ", "", [global, {return, list}]).