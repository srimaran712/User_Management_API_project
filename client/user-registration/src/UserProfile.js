import React from 'react'
import Axios from 'axios'
import {useNavigate,NavLink} from 'react-router-dom'

function UserProfile() {
    const [users,setUsers]=React.useState([])
    const navigate=useNavigate()
    const getprofile=async()=>{
      try{
   
       const response= await Axios.get('http://localhost:8080/user/profile',{withCredentials:true})
 
       setUsers([response.data]);
       
      }catch (error){
        
     
        console.log('Profile fetch error:', error)
    
            navigate('/api/login');
        
      } 
       }
       React.useEffect(()=>{
         getprofile()  
        },[]) 

    const logout=async (e)=>{
     e.preventDefault()
   try{
    const status=await Axios.post('http://localhost:8080/api/logout',{withCredentials:true})
    console.log(status.data)
   
    navigate('/api/login')
   } catch (error){
    console.log(error)
   }

    }


  return (
    <div>

      <h1 className="text-3xl mt-4 ml-96 ">You are logged in </h1>
       <form className="space-y-6"  method="POST" onSubmit={logout}>
                                
                                 <button type="submit" className="w-60 p-2 mt-10 bg-indigo-600 text-white font-medium text-1xl ml-96">Logout</button>

                                 <h1 className='text-4xl font-medium text-gray-600 font-mono ml-96' >Your Profile</h1>
    </form>
      



      {users.map((userslist)=>{
        return(
            <div key={userslist._id} className="m-10">
            
                <h1 className="text-3xl text-gray-900 font-bold mt-10 ml-96">{userslist.email}</h1>
                <h1 className="text-3xl text-gray-900 font-bold mt-10 ml-96">{userslist.username}</h1>
            </div>
        )
      })}

<NavLink className="bg-violet-500 text-white text-md p-2 mt-28 ml-96 w-96" to='/user/update'>Want to update your Profile</NavLink>
    </div>
  )
}

export default UserProfile
