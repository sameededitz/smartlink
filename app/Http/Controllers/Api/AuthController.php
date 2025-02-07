<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function signup(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255|min:3|unique:users,name|regex:/^\S*$/',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|min:8|confirmed'
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'message' => $validator->errors()->all()
            ], 400);
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'role' => 'normal'
        ]);

        /** @var \App\Models\User $user **/
        $user->assignFreeTrial();

        $user->sendEmailVerificationNotification();

        Auth::login($user);

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            'status' => true,
            'message' => 'Account created successfully! Verify your Email',
            'user' => $user,
            'access_token' => $token,
            'token_type' => 'Bearer',
        ]);
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'password' => 'required|min:8',
            'device_name' => 'required',
            'device_token' => 'nullable',
            'device_id' => 'required',
            'platform' => 'required',
        ]);

        if ($validator->fails()) {
            return response()->json([
                'status' => false,
                'message' => $validator->errors()->all()
            ], 400);
        }

        $loginType = filter_var($request->name, FILTER_VALIDATE_EMAIL) ? 'email' : 'name';
        $user = User::where($loginType, $request->name)->first();
        if (!$user) {
            return response()->json([
                'status' => false,
                'message' => "We couldn't find an account with that " . ($loginType == 'email' ? 'email' : 'username') . "."
            ], 400);
        }

        $credentials = [
            $loginType => $request->name,
            'password' => $request->password,
        ];
        $remember = $request->has('remember');

        if (Auth::attempt($credentials, $remember)) {
            /** @var \App\Models\User $user **/
            $user = Auth::user();

            if (!$user->hasVerifiedEmail()) {
                return response()->json([
                    'status' => false,
                    'message' => 'Please verify your email address.',
                    'user' => $user
                ], 400);
            }

            $deviceId = $request->device_id;
            $devicedetails = [
                'device_name' => $request->device_name,
                'device_id'   => $deviceId,
                'device_token' => $request->device_token,
                'ip_address'  => $request->ip(),
                'platform'    => $request->platform,
            ];

            if ($user->canRegisterDevice($deviceId)) {
                $result = $user->registerDevice($deviceId, $devicedetails);

                if ($result === 'already_registered') {
                    return response()->json([
                        'status' => true,
                        'message' => 'Device is already registered.',
                    ], 200);
                }

                if ($result === 'device_limit_exceeded') {
                    return response()->json([
                        'status' => false,
                        'message' => 'You have reached the maximum number of devices allowed. Please remove a device to add a new one.'
                    ], 403);
                }
                return response()->json([
                    'status' => true,
                    'message' => 'Device registered successfully.',
                ], 200);
            } else {
                return response()->json([
                    'status' => false,
                    'message' => 'You have reached the maximum number of devices allowed. Please remove a device to add a new one.'
                ], 403);
            }

            $token = $user->createToken('auth_token')->plainTextToken;

            return response()->json([
                'status' => true,
                'message' => 'User logged in successfully!',
                'user' => $user,
                'access_token' => $token,
                'token_type' => 'Bearer',
            ], 200);
        }

        return response()->json([
            'status' => false,
            'message' => 'The provided credentials do not match our records.'
        ], 400);
    }

    public function logout(Request $request)
    {
        $user = Auth::user();
        /** @var \App\Models\User $user **/
        $user->unregisterDevice($request->device_id);
        $user->tokens()->delete();

        return response()->json([
            'status' => true,
            'message' => 'User logged out successfully!'
        ], 200);
    }

    public function user()
    {
        $user = Auth::user();
        /** @var \App\Models\User $user **/
        return response()->json([
            'status' => true,
            'user' => $user,
            'device_limit' => $user->getSubscriptionDeviceLimit()
        ], 200);
    }
}
