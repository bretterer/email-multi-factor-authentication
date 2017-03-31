<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Mail\LoginCode;
use App\User;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = '/home';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest', ['except' => 'logout']);
    }

	/**
	 * Handle a login request to the application.
	 *
	 * @param  \Illuminate\Http\Request  $request
	 * @return \Illuminate\Http\RedirectResponse|\Illuminate\Http\Response
	 */
	public function login(Request $request)
	{
		$this->validateLogin($request);

		if ($this->hasTooManyLoginAttempts($request)) {
			$this->fireLockoutEvent($request);

			return $this->sendLockoutResponse($request);
		}

		$credentials = $this->credentials($request);
		$loginCheck = $this->guard()->validate(
			$credentials
		);

		if ($loginCheck) {
			$code = $this->createOneTimeUseCode($credentials);
			$this->emailOneTimeUseCode($credentials, $code);

			return redirect('/login/challenge');
		}

		$this->incrementLoginAttempts($request);

		return $this->sendFailedLoginResponse($request);
	}

	public function challenge()
	{
		return view('auth/challenge');
	}

	public function validateChallenge(Request $request)
	{
		$code = $request->get('code');
		$codeEntry = DB::table('mfaCodes')->where('code', $code)->where('expires', '>', time())->first();

		if($codeEntry) {
			$this->guard()->loginUsingId($codeEntry->user_id);
			return $this->sendLoginResponse($request);
		}

		DB::table('mfaCodes')->where('expires', '<', time())->delete();

		return redirect()->back()->withErrors(['code' => 'That code is not valid']);
	}

	private function createOneTimeUseCode($credentials)
	{
		$randomNumber = random_int(100000,999999);

		$user = User::where('email', $credentials['email'])->first();

		DB::table('mfaCodes')->insert(
			['user_id' => $user->id, 'code' => $randomNumber, 'expires' => time() + 300]
		);

		return $randomNumber;
	}

	private function emailOneTimeUseCode($credentials, $code)
	{
		Mail::to($credentials['email'])->send(new LoginCode($code));
	}

}
