const express= require('express');
const jwt= require('jsonwebtoken');

const app= express();
app.use(express.json());

const users=[
    {
        id:1,
        username:"username1",
        password:"password",
        isAdmin:true
    },
    {
        id:2,
        username:"username2",
        password:"password2",
        isAdmin:false
    },
]

let refreshTokens=[];

const secretKey="A Very secure secret key";
const refreshTokenSecretKey="A Very secure secret key";

const generateAcessToken=(user)=>{
    console.log(user);
    return jwt.sign({id:user.id,isAdmin:user.isAdmin},secretKey,{
        expiresIn:'2m',
});
}

const generateRefreshToken=(user)=>{
    console.log(user);
    return jwt.sign({id:user.id,isAdmin:user.isAdmin},refreshTokenSecretKey);
}

app.post("/api/login",(req,res)=>{
    const {username,password}=req.body;
    const user=users.find((u)=>{
        return u.username===username && u.password===password;
    });
    if(user){
        // res.json("It works")
        const acessToken=generateAcessToken(user);
        const refreshToken=generateRefreshToken(user);

        refreshTokens.push(refreshToken);

        res.status(200).json({
            id:user.id,
            isAdmin:user.isAdmin,
            acessToken:acessToken,
            refreshToken:refreshToken
        });
    }
    else{
        res.status(400).json("Username or password incorrect.");
    }
});


app.post("/api/refresh",(req,res)=>{
    // Take the refresh token from the user
    const refreshToken=req.body.token;
    
    // Send error if invalid
    if(!refreshToken) return res.status(401).json("You are not authenticated");
    if(!refreshTokens.includes(refreshToken)){
        return res.status(403).json("Refresh Token is not valid");
    }
    jwt.verify(refreshToken,refreshTokenSecretKey,(err,user)=>{
        err && console.log(err);
        refreshTokens=refreshTokens.filter((token)=>token!==refreshToken);
        
        const newAccessToken=generateAcessToken(user);
        const newRefreshToken=generateAcessToken(user);
        
        refreshTokens.push(newRefreshToken);
        
        res.status(200).json({
            username:user.username,
            isAdmin:user.isAdmin,
            newAccessToken,
            newRefreshToken
        });
        
    });
    // If all is okay, create new acess token, refresh token and send it to user
    
})

const verify=(req,res,next)=>{
    const authHeader=req.headers.authorization;
    if(authHeader){
        const token=authHeader.split(" ")[1];
        jwt.verify(token,secretKey,(err,user)=>{
            if(err){
                return res.status(403).json("Token is not valid.");
            }
            
            req.user=user;
            next();
            
        });
    }
    else{
        res.status(401).json("You are not authenticated");
    }
}

app.delete("/api/users/:userId",verify,(req,res)=>{
    
    if(req.user.id===req.params.userId || req.user.isAdmin){
        res.status(200).json("User has been deleted.");
    }
    else{
        res.status(403).json("You are not allowed to delete this user.");
    }
});

app.post("/api/logout",verify,(req,res)=>{
    const refreshToken= req.body.token;
    refreshTokens=refreshTokens.filter((token)=>token!==refreshToken);
    res.status(200).json("You logged out sucessfully");
})

app.listen(8080,()=>console.log("Backend server is running"));
