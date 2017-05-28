<?php

namespace Illuminate\Foundation\Auth;

use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

trait ReauthenticatesUsers
{
    use RedirectsUsers, ThrottlesLogins;

    /**
     * Show the application's reauth form.
     *
     * @return \Illuminate\Http\Response
     */
    public function showReauthForm()
    {
        return view('auth.reauth');
    }

    /**
     * Handle a reauthentication request to the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Http\Response
     */
    public function reauthenticate(Request $request)
    {
        $this->validateReauth($request);

        if ($this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);

            return $this->sendLockoutResponse($request);
        }

        if ($this->attemptReauth($request)) {
            return $this->sendReauthResponse($request);
        }

        $this->incrementLoginAttempts($request);

        return $this->sendFailedReauthResponse($request);
    }

    /**
     * Validate the user reauth request.
     *
     * @param \Illuminate\Http\Request $request
     *
     * @return void
     */
    protected function validateReauth(Request $request)
    {
        $this->validate($request, [
            'password' => 'required',
        ]);
    }

    /**
     * Attempt to log the user into the application.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    protected function attemptReauth(Request $request)
    {
        return Hash::check(
            $request->input('password'),
            $this->guard()->user()->getAuthPassword()
        );
    }

    /**
     * Send the response after the user was authenticated.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    protected function sendReauthResponse(Request $request)
    {
        $request->session()->set('reauthenticated_at', Carbon::now()->timestamp);

        $this->clearLoginAttempts($request);

        return $this->reauthenticated($request, $this->guard()->user())
            ?: redirect()->intended($this->redirectPath());
    }

    /**
     * The user has been reauthenticated.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  mixed  $user
     * @return mixed
     */
    protected function reauthenticated(Request $request, $user)
    {
        //
    }

    /**
     * Get the failed login response instance.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     */
    protected function sendFailedReauthResponse(Request $request)
    {
        $errors = ['password' => trans('auth.failed')];

        if ($request->expectsJson()) {
            return response()->json($errors, 422);
        }

        return redirect()->back()->withErrors($errors);
    }

    /**
     * Get the guard to be used during authentication.
     *
     * @return \Illuminate\Contracts\Auth\StatefulGuard
     */
    protected function guard()
    {
        return Auth::guard();
    }
}
