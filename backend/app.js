const Express=require('express')
const nodemailer=require('nodemailer')//for sending emails
const Bcrypt=require('bcryptjs')//converting passwords into the hashed passwords

const bodyparser=require('body-parser')
const jwt=require('jsonwebtoken')
//session
const session = require('express-session')
//const Session=require('express-session')

//const mongodbsession=require('connect-mongodb-session')///this is the module where used to connect our session with mongodb database
////connecting mongodb session
//const connectsession=mongodbsession(Session)

//connecting to database by giving their database address,databas name and collection
//const mongosessioncollecteddata=new connectsession({
 //   uri:"mongodb://127.0.0.1:27017",
  //  databaseName:"usersdatabase",
    //collection:"session-data"
//})





const Mongoose=require('mongoose')//for the database
const Otp=require('otp-generator')// for generating otp

const Cors=require('cors')////middleware the communication tool between the client and server

//creating a express server
const app=Express()

const connectMongoDBSession=require('connect-mongodb-session')(session)
const mongoDBSession = new connectMongoDBSession({
    uri: 'mongodb://127.0.0.1:27017',
    databaseName: 'usersdatabase',
    collection: 'session-data'
});

app.use(session({  //telling my express to create a session 
    secret: 'HJQkloyi12#8**)',
    resave: true,
    saveUninitialized: false,
    store: mongoDBSession,
    cookie: { secure: false, maxAge: 2 * 60 * 1000 }
}));

app.use(bodyparser.json())///will able read the json data also
app.use(Express.urlencoded())////for form collection the server has not have power to collect detaila directly so this module can be implemented mainly for using template engines
app.use(Cors({
    origin: 'http://localhost:3000',
    credentials: true
}))




///connecting to the database
Mongoose.connect("mongodb://127.0.0.1:27017/usersdatabase")

//creating the schema
const UserSchema=Mongoose.Schema({//data sctructure
    username:{type:String,required:true,unique:true},
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    otp: String,
    otpExpires: Date
})

//creating a collection
const User=Mongoose.model('usersdata',UserSchema)




//creeting a transport for sending mails

const transport=nodemailer.createTransport({
    host:"smtp-mail.outlook.com",
    port:587,
    secure:false,
    auth:{
        user:'srinivasan712@outlook.com',
        pass:'Maransjc123^6'
    }
})

const sendConfirmationMail = (toEmail,otp) => {
    const mailOptions = {
        from: '"Lucidity" <srinivasan712@outlook.com>',
        to: toEmail,
        subject: 'Verify your account',
        html: `<h1 style="text-align:center;">confirm your email ${toEmail} your otp is ${otp}</html>`
    };

    transport.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log('Error sending email:', error);
        } else {
            console.log('Check your inbox:', info.response);
        }
    });
};

///creating a register form
app.post('/api/register',async function(req,res){
    const {username,email,password}=req.body
   

    const existingUser= await User.findOne({email})
    if(existingUser){
        return res.status(200).json({message:'Existing user'})
    }
   const hashedpassword= await Bcrypt.hash(password,10)////this will convert plained password into a hashed password
   const otp=Otp.generate(6, { digits: true, alphabets: false, upperCase: false, specialChars: false });// this will generate the otp 
   const otpExpires = Date.now() + 3600000; // 1 hour
   const user = new User({
    username,
    email,
    password: hashedpassword,
    otp,
    otpExpires
});
await user.save()

res.status(200).json('Account created successfully')

 
    sendConfirmationMail(email,otp)
 })
 
app.post('/api/otp',async function(req,res){
    const{otpgen}=req.body
  const rightotp=  await User.findOne({otp:otpgen})
  if(rightotp){
    res.status(400).json({message:'confirmation succeed'})
  }



})


////send otp for verification

app.post('/send-otp',async function(req,res){
   const{email}= req.body

  const verifyemail= await User.findOne({email:email})
  if(!verifyemail){
    res.status(400).json({textmessage:'not a valid user'})
  }
  const verifyotp=Otp.generate(6, { digits: true, alphabets: false, upperCase: false, specialChars: false });

  verifyemail.otp= verifyotp
 await verifyemail.save()
 sendConfirmationMail(email,verifyotp)
})

//otp based login verification here
app.post('/api/login',async function(req,res){
    const{email,otp}=req.body

    try {
        const validemail = await User.findOne({ email: email, otp: otp });

        if (!validemail) {
            return res.status(400).json({ message: 'Wrong OTP or email' });
        }

        req.session.user = { email: validemail.email, _id: validemail._id };
        return res.status(200).json({ message: 'Login successful' });

    } catch (error) {
        console.error('Error during login:', error);
        return res.status(500).json({ message: 'Internal server error' });
    }

   // const validemail= await User.findOne({email:email,otp:otp})
   // if(!validemail){
  //      res.status(400).json({textemail:'wrong otp or or wrong email'})
  //  }

   
   // req.session.user = {email:email}; 
  //  res.status(200).json({textemail:'Login successful'})
})


/////middleware










///log out 
app.post('/api/logout',function(req,res){
   req.session.destroy();
    res.clearCookie('connect.sid');
    res.status(200).json({message:'Logged  out successfully'})


})

////collecting the user from session by finding the Id
app.get('/user/profile',async function(req,res){

    if (!req.session.user) {
        return res.status(401).json({ message: 'Unauthorized' });
      }
    
      try {
        const user = await User.findById(req.session.user._id);
        if (!user) {
          return res.status(404).json({ message: 'User not found' });
        }
    
      
        res.status(200).json(user)
      } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
      }
    })
    //if (req.session.user || req.session.user.email) {
     //   const userdata= await User.find()
     //   res.status(200).json(userdata)
   // }
     // try {
      //  const data = await User.find()
     ///   res.status(200).json(data);
   // } catch (error) {
       // res.status(500).json({ message: 'Internal server error' });
    //}
   // else{
        //res.status(401).json({ message: 'Unauthorized' });
   // }

app.put('/user/profile',async function(req,res){
 const { updateusername,updateuseremail,currentemail,currentusername }=req.body


try {
    const user = await User.findOne({email:updateuseremail});
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }

    user.username = updateusername;
    user.email = updateuseremail;

    await user.save();

    res.status(200).json({ message: 'Profile updated successfully', user });
} catch (error) {
    console.error('Error during profile update:', error);
    res.status(500).json({ message: 'Internal server error' });
}
});



app.listen(8080)