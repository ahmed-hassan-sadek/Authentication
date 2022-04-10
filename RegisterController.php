<?php

namespace App\Http\Controllers\Web;

use App\Http\Controllers\Controller;
use App\Models\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;

class RegisterController extends Controller
{

    private $userModel , $dataModel;

    public function __construct(User $user , DB $datatable)
    {
        $this->dataModel = $datatable;
        $this->userModel = $user;
    }


    public function loginPage()
    {
        return view('web.register.login');
    }

    public function register()
    {
        return view('web.register.register');
    }

    public function forgetPasswordPage()
    {
        return view('web.register.forgot-password');
    }

    public function doctorRegister()
    {
        return view('web.register.doctor-register');
    }

    public function changepassword()
    {
        return view('web.register.change-password');
    }


    /**
     * get request from form
     * request validation
     * check if type is patient or doctor
     * create a patient or doctor with hash password
     * get data of this user with using function attempt
     * check if return data go to home page
     * else stay at same page with massage
     */

    public function signup(Request $request)
    {
        $request->validate([
            'name' => 'required|max:25',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:6'
        ]);


        if ($request->type == "doctor") {
            $this->userModel::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
                'role_id' => 2,
            ]);
        }
        else
        {
            $this->userModel::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
                'role_id' => 3,
            ]);
        }

        $userData = $request->only('email', 'password');

        if(auth()->attempt($userData))
        {
            return redirect(route('home'));
        }

        session()->flash('error','Please the valid data');
        return redirect()->back();
    }

    /**
     * get request from form
     * request validation
     * get data of this user with using function attempt
     * check if return data go to home page
     * else stay at same page with massage
     */


    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required',
            'password' => 'required'
        ]);

        $userData = $request->only('email', 'password');

        if (auth()->attempt($userData)) {

            return redirect(route('home'));
        }
        session()->flash('error','Email Or Password Is Wrong');
        return redirect()->back();
    }


    /**
     * validate if mail is at user table or not
     * get a token random value
     * insert a data at table password_resets
     * send mail to mail that you input and found at DB
     * return redurect back with message
     */

    public function forget_password(Request $request)
    {
        $request->validate([
            'email' => 'required|email|exists:users',
        ]);

        $token = Str::random(64);

        $this->dataModel::table('password_resets')->insert([
            'email' => $request->email,
            'token' => $token,
            'created_at' => Carbon::now('Africa/Cairo')
          ]);

          Mail::send('web.register.email', ['token' => $token], function($message) use($request){
            $message->to($request->email);
            $message->subject('Reset Password');
        });

        return back()->with('message', 'We have e-mailed your password reset link!');

    }

    /**
     * get token value from url
     * redierict to page change password with token value
     */
    public function showResetPasswordForm($token) {
        return view('web.register.change-password', ['token' => $token]);
    }

    /**
     * get request form
     * get valudation
     * get the value of email and token from table password_reset
     * chek if equal to value of request
     * check if mail input is for admin or not
     * inseret new value of password at user table with function hash
     * delete all row from table password_reset where email equail $request->email
     * redirect with message to login page
     */

    public function submitResetPasswordForm(Request $request)
      {
        $request->validate([
            'email' => 'required|email|exists:users',
            'password' => 'required|string|min:6|confirmed',
            'password_confirmation' => 'required'
        ]);

        $updatePassword = $this->dataModel::table('password_resets')
                            ->where([
                            'email' => $request->email,
                            'token' => $request->token
                            ])
                            ->first();

        if(!$updatePassword){
            return back()->withInput()->with('error', 'Invalid token!');
        }

        $data = $this->userModel::where('email', $request->email)->where('role_id' , 1)->first();

        if ($data) {
            return back()->withInput()->with('error', 'Invalid mail');
        }
        else
        {
            $this->userModel::where('email' , $request->email)->update(['password' => Hash::make($request->password)]);
            $this->dataModel::table('password_resets')->where(['email'=> $request->email])->delete();

            return redirect('/login')->with('message', 'Your password has been changed!');
        }


      }


    /**
     * delete all session
     * and get out of function Auth
     * return to home page
    */
    public function logout()
    {
        Session::flush();
        Auth::logout();
        return redirect(route('home'));
    }
}
