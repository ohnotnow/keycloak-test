<?php

use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Auth;

Route::get('/login', [\App\Http\Controllers\Auth\SSOController::class, 'login'])->name('login');
Route::post('/login', [\App\Http\Controllers\Auth\SSOController::class, 'doLocalLogin'])->name('login.do');
Route::get('/auth/callback', [\App\Http\Controllers\Auth\SSOController::class, 'handleProviderCallback'])->name('sso.callback');

// Route::get('/auth/sso', [\App\Http\Controllers\Auth\SSOController::class, 'redirectToProvider'])->name('sso.redirect');

Route::group(['middleware' => 'auth'], function () {
    Route::get('/home', function () {
        dd(Auth::user());
    });
});
