<?php

namespace App\Http\Controllers\Auth;

use App\Models\User;
use Illuminate\Support\Str;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Laravel\Socialite\Facades\Socialite;

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

            dump($ssoUser);

            if (!config('sso.allow_students', true) && $this->isStudent($ssoUser)) {
                abort(403, 'Students are not allowed to login');
            }

            $email = strtolower($ssoUser->getEmail());

            if (config('sso.autocreate_new_users', false)) {
                $user = User::updateOrCreate(
                    ['email' => $email],
                    [
                        'password' => bcrypt(Str::random(64)),
                        'username' => strtolower($ssoUser->getNickname() ?? $ssoUser->getName()),
                        'email' => $email,
                        'surname' => $ssoUser->user['family_name'],
                        'forenames' => $ssoUser->user['given_name'],
                        'is_staff' => $this->isStaff($ssoUser),
                    ]
                );
            } else {
                $user = User::where('email', '=', $email)->firstOrFail();
            }

            if (config('sso.admins_only', false) && !$user->is_admin) {
                if ($user->wasRecentlyCreated) {
                    $user->delete();
                }
                abort(403, 'Only admins can login');
            }

            auth()->login($user, true);
            return "Hello";
            return redirect('/home');

    }

    private function extractSurname($ssoUser)
    {
        return $ssoUser->user['family_name'] ??
               $ssoUser->user['surname'] ??
               $this->parseFromName($ssoUser->getName(), 'surname');
    }

    private function extractForenames($ssoUser)
    {
        return $ssoUser->user['given_name'] ??
               $ssoUser->user['forenames'] ??
               $this->parseFromName($ssoUser->getName(), 'forenames');
    }

    private function isStudent($ssoUser)
    {
        $username = $ssoUser->getNickname() ?? $ssoUser->getName();

        return $this->looksLikeMatric($username);
    }

    private function isStaff($ssoUser)
    {
        $username = $ssoUser->getNickname() ?? $ssoUser->getName();

        return !$this->looksLikeMatric($username);
    }

    private function looksLikeMatric($username)
    {
        return preg_match('/^[0-9]+[a-z]?$/', $username);
    }

    private function parseFromName($fullName, $part)
    {
        if (empty($fullName)) {
            return null;
        }

        $nameParts = explode(' ', trim($fullName));

        if ($part === 'forenames') {
            // Everything except the last part
            return count($nameParts) > 1 ? implode(' ', array_slice($nameParts, 0, -1)) : $fullName;
        } elseif ($part === 'surname') {
            // The last part
            return count($nameParts) > 1 ? end($nameParts) : null;
        }

        return null;
    }
}
