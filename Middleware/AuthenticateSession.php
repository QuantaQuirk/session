<?php

namespace QuantaQuirk\Session\Middleware;

use Closure;
use QuantaQuirk\Auth\AuthenticationException;
use QuantaQuirk\Contracts\Auth\Factory as AuthFactory;
use QuantaQuirk\Contracts\Session\Middleware\AuthenticatesSessions;
use QuantaQuirk\Http\Request;

class AuthenticateSession implements AuthenticatesSessions
{
    /**
     * The authentication factory implementation.
     *
     * @var \QuantaQuirk\Contracts\Auth\Factory
     */
    protected $auth;

    /**
     * Create a new middleware instance.
     *
     * @param  \QuantaQuirk\Contracts\Auth\Factory  $auth
     * @return void
     */
    public function __construct(AuthFactory $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \QuantaQuirk\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, Closure $next)
    {
        if (! $request->hasSession() || ! $request->user()) {
            return $next($request);
        }

        if ($this->guard()->viaRemember()) {
            $passwordHash = explode('|', $request->cookies->get($this->guard()->getRecallerName()))[2] ?? null;

            if (! $passwordHash || $passwordHash != $request->user()->getAuthPassword()) {
                $this->logout($request);
            }
        }

        if (! $request->session()->has('password_hash_'.$this->auth->getDefaultDriver())) {
            $this->storePasswordHashInSession($request);
        }

        if ($request->session()->get('password_hash_'.$this->auth->getDefaultDriver()) !== $request->user()->getAuthPassword()) {
            $this->logout($request);
        }

        return tap($next($request), function () use ($request) {
            if (! is_null($this->guard()->user())) {
                $this->storePasswordHashInSession($request);
            }
        });
    }

    /**
     * Store the user's current password hash in the session.
     *
     * @param  \QuantaQuirk\Http\Request  $request
     * @return void
     */
    protected function storePasswordHashInSession($request)
    {
        if (! $request->user()) {
            return;
        }

        $request->session()->put([
            'password_hash_'.$this->auth->getDefaultDriver() => $request->user()->getAuthPassword(),
        ]);
    }

    /**
     * Log the user out of the application.
     *
     * @param  \QuantaQuirk\Http\Request  $request
     * @return void
     *
     * @throws \QuantaQuirk\Auth\AuthenticationException
     */
    protected function logout($request)
    {
        $this->guard()->logoutCurrentDevice();

        $request->session()->flush();

        throw new AuthenticationException(
            'Unauthenticated.', [$this->auth->getDefaultDriver()], $this->redirectTo($request)
        );
    }

    /**
     * Get the guard instance that should be used by the middleware.
     *
     * @return \QuantaQuirk\Contracts\Auth\Factory|\QuantaQuirk\Contracts\Auth\Guard
     */
    protected function guard()
    {
        return $this->auth;
    }

    /**
     * Get the path the user should be redirected to when their session is not autheneticated.
     *
     * @param  \QuantaQuirk\Http\Request  $request
     * @return string|null
     */
    protected function redirectTo(Request $request)
    {
        //
    }
}
