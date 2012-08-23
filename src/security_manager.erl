-module(security_manager).

-export([start_link/1]).

%Behaviour
-behaviour(gen_server).

%Gen_Server API
-export([
    init/1,
    handle_call/3,
    handle_cast/2,
    handle_info/2,
    terminate/2,
    code_change/3
]).

-define(WINDOW, 60000000).

-record(state, { 
				previous_times = [] :: [integer()],
				password = "" :: any() 
}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%% Gen_Server Stuff %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

start_link(Password) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Password], []).

init([Password]) ->
	InitialState = #state{previous_times = [], password = Password},
    {ok, InitialState}.


%% Checks to see if the supplied credentials are sufficient.
handle_call({check_credentials, TimeSeconds, TimeMicroseconds, Password}, _From, State) ->

	%%First, check to see if the supplied password matches the real password:
	case Password == State#state.password of
		false ->
			{reply, deny, State};
		true ->
			{MegaSecs, Secs, Micro} = erlang:now(),
			CurrentMicrosecondsLocal = MegaSecs*1000000000000+Secs*1000000+Micro,
			CurrentMicrosecondsRemote = TimeSeconds*1000000+TimeMicroseconds,
			
			%% Second, check to see if the timestamp arrived within a ?WINDOW 
			%% microsecond window:
			case erlang:abs(CurrentMicrosecondsLocal - CurrentMicrosecondsRemote) < ?WINDOW/2 of
				false -> 
					{reply, deny, State};
				true ->
					%% Third, check to see if the timestamp has already arrived 
					%% in the last ?WINDOW microseconds. If it has, deny it:
					EqualityFun = fun(X) -> X =:= CurrentMicrosecondsRemote end,
					case lists:any(EqualityFun, State#state.previous_times) of
						true -> 
							{reply, deny, State};
						false ->
							%% Finally, add the time to State#state.previous_times, and remove 
							%% any times from State#state.previous_times older than ?WINDOW 
							%% microseconds.
							NewTimes = [X || X <- State#state.previous_times, CurrentMicrosecondsLocal - X < ?WINDOW],
							NewState = #state{previous_times = NewTimes++[CurrentMicrosecondsRemote]},
							{reply, allow, NewState}
					end
			end
	end;

%% For testing purposes. Returns the list of previous_times that have been
%% successfuly authentecated over the past ?WINDOW/2 seconds
handle_call(get_previous_times, _From, State) ->
	{reply, State#state.previous_times, State}.
	
handle_cast(_, State) ->
    {noreply, State}.
handle_info(_, State) ->
    {noreply, State}.
terminate(_, _State) ->
    ok.
code_change(_, _, State) ->
    {ok, State}.