<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Support\Str;
use Laravel\Socialite\Facades\Socialite;

class SSOController extends Controller
{
    public function redirectToProvider()
    {
        return Socialite::driver('keycloak')->with(['OAUTH2_PROXY_INSECURE_OIDC_ALLOW_UNVERIFIED_EMAIL' => true])->redirect();
    }

    public function handleProviderCallback()
    {
        try {
            $ssoUser = Socialite::driver('keycloak')->user();

            info('SSO User Data', [
                'user' => $ssoUser->user,
                'name' => $ssoUser->getName(),
                'email' => $ssoUser->getEmail(),
                'nickname' => $ssoUser->getNickname(),
            ]);

            $user = User::updateOrCreate(
                ['email' => strtolower($ssoUser->getEmail())],
                [
                    'password' => bcrypt(Str::random(64)),
                    'username' => strtolower($ssoUser->getNickname() ?? $ssoUser->getName()),
                    'email' => strtolower($ssoUser->getEmail()),
                    'surname' => $this->extractSurname($ssoUser),
                    'forenames' => $this->extractForenames($ssoUser),
                    'is_staff' => $this->determineStaffStatus($ssoUser),
                ]
            );

            auth()->login($user, true);

            return redirect('/home');

        } catch (\Exception $e) {
            return redirect('/login')->with('error', 'SSO authentication failed');
        }
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

    private function determineStaffStatus($ssoUser)
    {
        $username = $ssoUser->getNickname() ?? $ssoUser->getName();

        return $this->looksLikeMatric($username);
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
