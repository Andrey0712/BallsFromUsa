<?php

namespace App\Http\Controllers;
use Illuminate\Http\Request;

use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Validator;


class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct() {
        $this->middleware('auth:api', ['except' => ['login', 'register']]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    /**
     * @OA\Post (
     *     path="/api/auth/login",
     *     tags={"Auth"},
     *     summary="Login",
     *     operationId="Login",
     *     @OA\Parameter (
     *      name="email",
     *      in="query",
     *      required=true,
     *      @OA\Schema (
     *          type="string"
     *      )
     *     ),
     *     @OA\Parameter (
     *      name="password",
     *      in="query",
     *     required=true,
     *     @OA\Schema (
     *     type="string"
     *      )
     *      ),
     *   @OA\Response(
     *      response=200,
     *       description="Success",
     *      @OA\MediaType(
     *           mediaType="application/json",
     *      )
     *   ),
     *   @OA\Response(
     *      response=401,
     *       description="Unauthenticated"
     *   ),
     *   @OA\Response(
     *      response=400,
     *      description="Bad Request"
     *   ),
     *   @OA\Response(
     *      response=404,
     *      description="not found"
     *   ),
     *      @OA\Response(
     *          response=403,
     *          description="Forbidden"
     *      )
     * )
     */
    public function login(Request $request){
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        if (! $token = auth()->attempt($validator->validated())) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->createNewToken($token);
    }


    /**
     * @OA\Post(
     *     path="/api/auth/register",
     *     summary="Register",
     *     tags={"Auth"},
     *     operationId="Register",
     *      @OA\RequestBody(
     *         @OA\MediaType(
     *             mediaType="multipart/form-data",
     *             @OA\Schema(
     *                 @OA\Property(
     *                     property="name",
     *                     type="string"
     *                 ),
     *                 @OA\Property(
     *                     property="email",
     *                     type="string"
     *                 ),
     *                 @OA\Property(
     *                     property="password",
     *                     type="string"
     *                 ),
     *                 @OA\Property(
     *                     property="password_confirmation",
     *                     type="string"
     *                 ),
     *                  @OA\Property(
     *                     property="Image",
     *                     type="file"
     *                 ),
     *             )
     *         )
     *     ),
     *
     *     @OA\Response(
     *     response="200",
     *     description="ok"
     * )
     * )
     */
    /**
     * Register a User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request) {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|between:2,100',
            'email' => 'required|string|email|max:100|unique:users',
            'password' => 'required|string|confirmed|min:6',
        ]);

        if($validator->fails()){
            return response()->json($validator->errors()->toJson(), 400);
        }

        $filename = "";
        if(!empty($_FILES))
        {
            $extension = pathinfo($_FILES['Image']['name'], PATHINFO_EXTENSION);
            $filename = uniqid() . ".{$extension}";

            $dir = $_SERVER['DOCUMENT_ROOT'] . '/images/' . $filename;
            move_uploaded_file($_FILES['Image']['tmp_name'], $dir);
        }

        $user = User::create(array_merge(
            $validator->validated(),
            ['password' => bcrypt($request->password),'image' => $filename]
        ));

        return response()->json([
            'message' => 'User successfully registered',
            'user' => $user,

        ], 201);
    }


    /**
     * Log the user out (Invalidate the token).
     *
     * @return \Illuminate\Http\JsonResponse
     */
    /**
     * @OA\Post (
     *     path="/api/auth/logout",
     *     summary="Logout",
     *     tags={"Auth"},
     *     operationId="Logout",
     *     security={{"bearerAuth": {}}},
     *     @OA\Response (
     *     response="200",
     *     description="Logout good"
     * @OA\MediaType (
     *     mediaType="application/json"
     * )
     * )
     */
    public function logout() {
        auth()->logout();

        return response()->json(['message' => 'User successfully signed out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    /**
     * @OA\Post (
     *     path="/api/auth/refresh",
     *     summary="Refresh",
     *     tags={"Auth"},
     *     operationId="Refresh",
     *     security={{"bearerAuth": {}}},
     *     @OA\Response (
     *     response="200",
     *     description="Logout refresh"
     * )
     * )
     */
    public function refresh() {
        return $this->createNewToken(auth()->refresh());
    }

    /**
     *
     * @OA\Get(
     *     path="/api/auth/user-profile",
     *     tags={"Auth"},
     *     security={{"bearerAuth":{}}},
     *     @OA\Response(response="200", description="Display a listing of projects."),
     *     @OA\Response(
     *     response="401",
     *     description="Unauthorized"
     * )
     * )
     */
    /**
     * Get the authenticated User.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function userProfile(Request $request) {
        return response()->json(auth()->user());
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function createNewToken($token){
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'user' => auth()->user()
        ]);
    }

}
