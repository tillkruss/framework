<?php

namespace Illuminate\Auth\Middleware;

use Closure;
use Carbon\Carbon;

class Reauthenticate
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        $reauthenticatedAt = Carbon::createFromTimestamp(
            $request->session()->get('reauthenticated_at', 0)
        )->diffInMinutes();

        if ($reauthenticatedAt > config('auth.reauth')) {
            return redirect()->guest(route('reauth'));
        }

        return $next($request);
    }
}
