import React from 'react'
import {useState} from 'react'
import Axios from 'axios'

import {useNavigate} from 'react-router-dom'

///confirmation otp after successful signup
function SendOtp() {
    const [otpgen,setOtpgen]=useState('')
    const[message,setMessage]=useState('')
  const navigate=useNavigate()
    async function handlersubmit(e){
        e.preventDefault()
        
        try {
            const response = await Axios.post('http://localhost:8080/api/otp', {otpgen});
            console.log(response.data.message)
            setMessage(response.data.message)
            navigate('/send-otp')
          } catch (error) {
            console.log(error.response ? error.response.data.message : 'error')
            setMessage(error.response ? error.response.data.message : 'error')
          }


    }
  return (
    <div>
        <h1 className="text-3xl text-black space-x-2 text-center m-3 ">confirm Your email by entering OTP here</h1>
       <form className="space-y-6 ml-96 mt-10"  method="POST" onSubmit={handlersubmit}>
                                 <input type="text" className="w-96 p-3 ml-60 text-2xl text-gray-800 bg-slate-200 border-none shadow-neutral-50" value={otpgen} onChange={(e)=>{
                                    e.preventDefault()
                                    setOtpgen(e.target.value)
                                 }} /> <br></br>
                                 <button type="submit" className="w-96 p-3 ml-60 bg-violet-500 text-white font-medium text-1xl">Enter here</button>
    </form>
    <h3 className="text-2xl text-gray-600 font-medium ml-60 mt-10">{message}</h3>
    </div>
  )
}

export default SendOtp
