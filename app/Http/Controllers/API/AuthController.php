<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    public function register(Request $request)
{
    $validated = $request->validate([
        'name' => 'required|string|max:255',
        'email' => 'required|string|email|max:255|unique:users',
        'password' => 'required|string|min:8|confirmed',
    ]);

    $user = User::create([
        'login_type' => 'common',
        'name' => $validated['name'],
        'email' => $validated['email'],
        'password' => Hash::make($validated['password']),
    ]);

    return response()->json(['message' => 'User registered successfully'], 201);
}
public function login(Request $request)
    {
        if ($request->has('uid')) {
            // Login via Google
            $request->validate([
                'email' => 'required|email',
                'name' => 'required|string',
                'uid' => 'required|string',
                'photo_url' => 'required|string',
            ]);

            $email = $request->email;
            $name = $request->name;
            $uid = $request->uid;
            $photo_url = $request->photo_url;

            // Cari pengguna berdasarkan email
            $user = User::where('email', $email)->first();

            if (!$user) {
                // Jika pengguna belum ada, buat pengguna baru
                $user = User::create([
                    'name' => $name,
                    'login_type' => "google",
                    'email' => $email,
                    'uid' => $uid,
                    'photo_url' => $photo_url,
                    'password' => bcrypt(uniqid()),
                ]);
            } else {
                // Update google_id jika belum ada
                if (!$user->google_id) {
                    $user->update(['uid' => $uid]);
                }
            }

            // Generate JWT token
            $token = JWTAuth::fromUser($user);

            return response()->json([
                'access_token' => $token,
                'token_type' => 'Bearer',
                'expires_in' => auth('api')->factory()->getTTL() * 60,
                'user' => $user,
            ]);
        } else {
            // Login via email dan password
            $credentials = $request->only('email', 'password');

            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'Invalid credentials'], 401);
            }

            return response()->json([
                'access_token' => $token,
                'token_type' => 'Bearer',
                'expires_in' => auth('api')->factory()->getTTL() * 60,
            ]);
        }
    }
public function logout()
{
    auth()->logout();
    return response()->json(['message' => 'Logged out successfully']);
}
public function me()
{
    return response()->json(auth()->user());
}
}
