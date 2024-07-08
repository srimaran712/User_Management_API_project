import React from 'react'
import Axios from 'axios'
import {useState} from 'react'
import { useNavigate,NavLink} from 'react-router-dom'

function Register() {
  const [username,setUserName]=useState('')
  const [email,setEmail]=useState('')
  const [password,setPassword]=useState('')
  const [notification,setNotification]=useState('')
 const navigate=useNavigate() 

 //await Axios.post('http://localhost:3000/api/register',{"email":email,"password":password})
 const handlersubmit= async(e)=>{
     
  e.preventDefault();
  try {
    const response = await Axios.post('http://localhost:8080/api/register', { username,email, password });
    console.log('Response:', response.data);
    setNotification(response.data)
    navigate('/api/otp')
  } catch (error) {
    console.error('Error:', error.response ? error.response.data : error.message);
    navigate('/api/register')
  }
 }

 
  return (
    <div> 
      <div className="flex min-h-full flex-col justify-center px-6 py-12 lg:px-8">
  <div className="sm:mx-auto sm:w-full sm:max-w-sm">
    
    <h2 className="mt-10 text-center text-2xl font-bold leading-9 tracking-tight text-gray-900">Sign Up your account</h2>
  </div>

  <div className="mt-10 sm:mx-auto sm:w-full sm:max-w-sm">
    <form className="space-y-6"  method="POST" onSubmit={handlersubmit}>

    <div>
        <label htmlFor="UserName" className="block text-sm font-medium leading-6 text-gray-900">User Name</label>
        <div className="mt-2">
          <input type="text" value={username} onChange={(e)=>{
        
            setUserName(e.target.value)
          }} required className="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"/>
        </div>
      </div>





      <div>
        <label htmlFor="email" className="block text-sm font-medium leading-6 text-gray-900">Email address</label>
        <div className="mt-2">
          <input type="email" value={email} onChange={(e)=>{
        
            setEmail(e.target.value)
          }} required className="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"/>
        </div>
      </div>

      <div>
        <div class="flex items-center justify-between">
          <label htmlFor="password" className="block text-sm font-medium leading-6 text-gray-900">Password</label>
         
        </div>
        <div className="mt-2">
          <input  type="password" value={password} onChange={(e)=>{
         
            setPassword(e.target.value)
          }}   required className="block w-full rounded-md border-0 py-1.5 text-gray-900 shadow-sm ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"/>
        </div>
      </div>

      <div>
        <button type="submit" className="flex w-full justify-center rounded-md bg-indigo-600 px-3 py-1.5 text-sm font-semibold leading-6 text-white shadow-sm hover:bg-indigo-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600">Register</button>
      </div>
    </form>
    <NavLink to='/api/register'className="text-indigo-800 font-medium ml-36 text-1xl mt-4 p-3">Already a user? </NavLink>
    <h3 className="mt-5 ml-48 font-medium font-mono text-2xl text-indigo-800">{notification}</h3>
  
  </div>
</div>
    </div>
  )
}

export default Register
