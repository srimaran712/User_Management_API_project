import React from 'react'
import {useState} from 'react'
import Axios from 'axios'
import { useNavigate,NavLink} from 'react-router-dom'


function LoginOtp() {
  const [email,setEmail]=useState('')
  const navigate=useNavigate()
  
  const handlersubmit= async(e)=>{

    e.preventDefault()
    try {
      const response = await Axios.post('http://localhost:8080/send-otp', { email });
      console.log('Response:', response.data.textmessage);
      navigate('/api/login')
      
    } catch (error) {
      console.error('Error:', error.response ? error.response.data : error.textmessage);
    }
   }  
  
  return (
    <div className="m-96 w-auto ">
      <h1 className="text-3xl text-black space-x-2 center m-3 ml-60 "> Enter your Email</h1>
       <form className="space-y-6 w-1/2 ml-48"  method="POST" onSubmit={handlersubmit}>
                                 <input type="text" className="w-96 p-3 text-2xl text-gray-800 bg-slate-200 border-none shadow-neutral-50" value={email} onChange={(e)=>{
                                    e.preventDefault()
                                    setEmail(e.target.value)
                                 }} /> <br></br>
                                 <button type="submit" className="w-96 p-2 bg-indigo-500 text-white font-medium text-1xl">Send OTP</button>

    </form>
    <NavLink to='/api/login'className="text-indigo-700 font-light ml-80 text-1xl m-5">Go to Login </NavLink>
    </div>
  )
}

export default LoginOtp
