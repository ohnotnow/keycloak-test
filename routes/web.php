<?php

use Illuminate\Support\Facades\Route;

Route::get('/login', [\App\Http\Controllers\Auth\SSOController::class, 'login'])->name('login');
Route::post('/login', [\App\Http\Controllers\Auth\SSOController::class, 'doLocalLogin'])->name('login.do');
Route::get('/auth/callback', [\App\Http\Controllers\Auth\SSOController::class, 'handleProviderCallback'])->name('sso.callback');

// Route::get('/auth/sso', [\App\Http\Controllers\Auth\SSOController::class, 'redirectToProvider'])->name('sso.redirect');

Route::get('/home', function () {
    dd(auth()->user());
});
