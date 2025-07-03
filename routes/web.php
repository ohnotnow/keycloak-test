<?php

use Illuminate\Support\Facades\Route;

Route::get('/login', function() {
    return redirect()->route('sso.redirect');
})->name('login');

Route::get('/auth/sso', [\App\Http\Controllers\Auth\SSOController::class, 'redirectToProvider'])->name('sso.redirect');
Route::get('/auth/sso/callback', [\App\Http\Controllers\Auth\SSOController::class, 'handleProviderCallback'])->name('sso.callback');

Route::get('/home', function () {
    dd(auth()->user());
});

