<?php

namespace BlueNest\Laravel\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\Response;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\App;

class IpRestrictionMiddleware
{
    const CONFIG_ENUM_ALLOW_ACCESS = "ALLOW";
    const CONFIG_ENUM_DENY_ACCESS = "DENY";
    const DEFAULT_HTTP_DENIAL_STATUS = 403;

    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @param  string|null  $guard
     * @return mixed
     */
    public function handle($request, Closure $next, $guard = null)
    {
        $allowOrDenyAccessByDefault = env('IP_ACCESS_ALLOW_DENY_DEFAULT', "DENY");

        if(!in_array($allowOrDenyAccessByDefault, [static::CONFIG_ENUM_ALLOW_ACCESS, static::CONFIG_ENUM_DENY_ACCESS])) {
            if (config('app.debug', false)) {
                throw new \Exception("Improper configuration for package middleware: IP_ACCESS_ALLOW_DENY_DEFAULT: " . $allowOrDenyAccessByDefault);
            } else {
                Log::error("Improper configuration for package middleware: IP_ACCESS_ALLOW_DENY_DEFAULT: " . $allowOrDenyAccessByDefault);
                throw new \Exception("Middlware error - please see log for error details");
            }
        }

        $ipWhiteList = env('IP_ACCESS_WHITELIST', null);
        $ipBlackList = env('IP_ACCESS_BLACKLIST', null);
        $ipDenyResponseMessage = env('IP_ACCESS_DENY_MESSAGE', null);
        $ipDenyResponseHttpStatusCode = env('IP_ACCESS_DENY_HTTP_STATUS_CODE', static::DEFAULT_HTTP_DENIAL_STATUS);

        if($ipBlackList !== null) {
            $ipBlackListArray = explode(',', trim($ipBlackList));

            if(in_array($request->ip(), $ipBlackListArray)) {
                if(env("IP_ACCESS_LOG_DENIALS", true)) {
                    Log::info(get_class($this) . ': Access denied for ip (due to blacklist): ' . $request->ip());
                }
                return Response::make($ipDenyResponseMessage, $ipDenyResponseHttpStatusCode);
            }
        }

        if($ipWhiteList !== null) {
            $ipWhiteListArray = explode(',', trim($ipWhiteList));

            if(in_array($request->ip(), $ipWhiteListArray)) {
                return $next($request);
            }
        }

        if($allowOrDenyAccessByDefault === static::CONFIG_ENUM_ALLOW_ACCESS) {
            return $next($request);
        } else {
            if(env("IP_ACCESS_LOG_DENIALS", true)) {
                Log::info(get_class($this) . ': Access denied for ip (by default): ' . $request->ip());
            }
            return Response::make($ipDenyResponseMessage, $ipDenyResponseHttpStatusCode);
        }
    }
}
