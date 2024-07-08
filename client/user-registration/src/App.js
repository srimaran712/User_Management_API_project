import Register from './Register'
import Login from './Login'
import SendOtp from './Sendotp'
import LoginOtp from './LoginOtp'
import UserProfile from './UserProfile'

import UpdateProfile from './UpdateProfile'

import {BrowserRouter,Routes,Route} from 'react-router-dom'


function App() {
 
  return (
    <div className="App">

                <BrowserRouter>
               
                <Routes>

                  <Route path='/api/register' element={<Register/>}></Route>
                  <Route path='/api/login' element={<Login/>}></Route>

                   <Route path='/api/otp' element={<SendOtp/>}></Route>
                   <Route path='/send-otp' element={<LoginOtp/>}></Route>
                   <Route path="/user/profile"  element={<UserProfile/>}  />
                   <Route path="/user/update"  element={<UpdateProfile/>}  />



                </Routes>
             
                
                </BrowserRouter>
                
              
    </div>
  );
}

export default App;
