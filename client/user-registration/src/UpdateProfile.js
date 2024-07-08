import React from 'react'
import {useState} from 'react'
import Axios from 'axios'
import {useNavigate} from 'react-router-dom'

function UpdateProfile() {
    const [updateusername,setUpdateUserName]=useState('')
    const [currentusername,setCurrentUserName]=useState('')
    const [currentemail,setCurrentEmail]=useState('')
    const [updateuseremail,setUpdateUserEmail]=useState('')
    const [backmessage,setBackmessage]=useState('')
    const navigate=useNavigate()

    const updatechange= async (e)=>{

     e.preventDefault();   
     try {
        const response = await Axios.put('http://localhost:8080/user/profile', { updateusername,updateuseremail,currentemail,currentusername });
        console.log('Response:', response.data);
        setBackmessage(response.data.message)
        navigate('/user/profile')
        
      } catch (error) {
        console.error('Error:', error.response ? error.response.data : error.message);
       
    }
}

  return (
    <div className="ml-60">
             <h1 className="text-4xl text-gray-700 font-medium ml-96 mt-32 ">Update Changes </h1>

<form className="space-y-6 ml-96 mt-32"  method="PUT" onSubmit={updatechange}>

<div>
    <label htmlFor="UserName" className="block text-md font-medium leading-6 text-gray-900">Enter your User Name</label>
    <div className="mt-2">
      <input type="text" value={currentusername} onChange={(e)=>{
    
    setCurrentUserName(e.target.value)
      }} required className="block w-96 rounded-md border-0 py-1.5 text-gray-800 shadow-md ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"/>
    </div>
  </div>

<div>
    <label htmlFor="UserName" className="block text-md font-medium leading-6 text-gray-900">Set your updated User Name</label>
    <div className="mt-2">
      <input type="text" value={updateusername} onChange={(e)=>{
    
    setUpdateUserName(e.target.value)
      }} required className="block w-96 rounded-md border-0 py-1.5 text-gray-800 shadow-md ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"/>
    </div>
  </div>

  <div>
    <label htmlFor="email" className="block text-md font-medium leading-6 text-gray-800">Enter your current Email address</label>
    <div className="mt-2">
      <input type="email" value={currentemail} onChange={(e)=>{
    
    setCurrentEmail(e.target.value)
      }} required className="block w-96 rounded-md border-0 py-1.5 text-gray-900 shadow-md ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"/>
    </div>
  </div>



  <div>
    <label htmlFor="email" className="block text-md font-medium leading-6 text-gray-800">Set your updated Email address</label>
    <div className="mt-2">
      <input type="email" value={updateuseremail} onChange={(e)=>{
    
    setUpdateUserEmail(e.target.value)
      }} required className="block w-96 rounded-md border-0 py-1.5 text-gray-900 shadow-md ring-1 ring-inset ring-gray-300 placeholder:text-gray-400 focus:ring-2 focus:ring-inset focus:ring-indigo-600 sm:text-sm sm:leading-6"/>
    </div>
  </div>
  <button className="bg-violet-500 text-white text-md p-2 mt-3  w-96" type="submit">Click Update</button>
    </form>  
         <h3 className="text-sm text-black font-light ml-32">{backmessage}</h3>

    </div>
  )
}

export default UpdateProfile
