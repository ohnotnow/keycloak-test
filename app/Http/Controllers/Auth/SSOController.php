<?php

namespace App\Http\Controllers\Auth;

use App\Models\User;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Laravel\Socialite\Facades\Socialite;
use Illuminate\Support\Facades\Auth;

class SSOController extends Controller
{
    public function login()
    {
        if (config('sso.enabled', true)) {
            return Socialite::driver('keycloak')->with(['OAUTH2_PROXY_INSECURE_OIDC_ALLOW_UNVERIFIED_EMAIL' => true])->redirect();
        }

        return view('auth.login');
    }

    public function doLocalLogin(Request $request)
    {
        if (config('sso.enabled', true)) {
            abort(403, 'SSO is enabled');
        }

        $request->validate([
            'username' => 'required',
            'password' => 'required',
        ]);

        if (auth()->attempt($request->only('username', 'password'))) {
            return redirect()->intended('/home');
        }

        return redirect()->back()->withErrors(['username' => 'Invalid credentials']);
    }

    public function handleProviderCallback()
    {
            $ssoUser = Socialite::driver('keycloak')->user();

            if (!config('sso.allow_students', true) && $this->isStudent($ssoUser)) {
                abort(403, 'Students are not allowed to login');
            }

            $ssoDetails = $this->getSSODetails($ssoUser);

            $user = $this->getUser($ssoDetails);

            if (config('sso.admins_only', false) && !$user->is_admin) {
                abort(403, 'Only admins can login');
            }

            Auth::login($user, true);
            return redirect('/home');

    }

    private function getSSODetails(\Laravel\Socialite\Contracts\User $ssoUser): array
    {
        return [
            'email' => strtolower($ssoUser->email),
            'username' => strtolower($ssoUser->nickname),
            'surname' => $ssoUser->user['family_name'],
            'forenames' => $ssoUser->user['given_name'],
            'is_staff' => $this->isStaff($ssoUser),
        ];
    }

    private function getUser(array $ssoDetails): User
    {
        if (config('sso.autocreate_new_users', false)) {
            return User::updateOrCreate(
                ['email' => $ssoDetails['email']],
                [
                    'password' => bcrypt(Str::random(64)),
                    'username' => $ssoDetails['username'],
                    'email' => $ssoDetails['email'],
                    'surname' => $ssoDetails['surname'],
                    'forenames' => $ssoDetails['forenames'],
                    'is_staff' => $ssoDetails['is_staff'],
                ]
            );
        }
        return User::where('email', '=', $ssoDetails['email'])->firstOrFail();
    }

    private function isStudent(\Laravel\Socialite\Contracts\User $ssoUser): bool
    {
        return $this->looksLikeMatric($ssoUser->nickname);
    }

    private function isStaff(\Laravel\Socialite\Contracts\User $ssoUser): bool
    {
        return !$this->looksLikeMatric($ssoUser->nickname);
    }

    private function looksLikeMatric(string $username): bool
    {
        return preg_match('/^[0-9]+[a-z]?$/', $username) === 1;
    }
}
