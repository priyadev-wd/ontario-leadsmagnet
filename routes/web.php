<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\GoogleOAuthController;

Route::get('/home', function () {
    return view('calendar.success');  // This is the view you'd like to return
})->name('home');
Route::get('', function () {
    return view('dashboard');
})->name('dashboard');

Route::get('redirect', [GoogleOAuthController::class, 'redirectToGoogle'])->name('redirect');
Route::get('google/callback', [GoogleOAuthController::class, 'handleGoogleCallback']);
