import express from "express";
import {dirname} from 'path';
import { fileURLToPath } from "url";
import pg from 'pg'
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import {Strategy} from "passport-local";
const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const port = 4000;
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
 
app.use(session({
    secret : "this-is-secret-string-used-to-encrypt",
    resave: false,
    saveUninitialized : true,
    cookie : {maxAge : 1000*60*60*24}
}));
app.use(passport.initialize());
app.use(passport.session());

const saltRounds = 10;
const db = new pg.Client({
    user: "postgres",
    host: "localhost",
    database: "EGP",
    password: "Anuj@123",
    port: 5432,
  });
  db.connect();

app.get("/login" ,(req , res)=>{
    res.sendFile(__dirname + "/public/html/login.html");
})
app.get("/register" , (req , res)=>{
    res.sendFile(__dirname + "/public/html/register.html");
});
app.post("/register" ,async (req , res)=>{
    const {username , email , password , confirmpassword} = req.body;
    try{
        var stored = await db.query("select * from account_details where email = $1" , [email]);
        if(stored.rowCount != 0){
            res.status(400).send("User already exists, try logging in");
        }
        else{
            if(password !== confirmpassword){
                res.status(400).send("Passwords do not match");
            }
            else{
                try{
                    console.log(new Date().toISOString());
                    const currDate = new Date().toISOString().split('T')[0];
                    bcrypt.hash(password , saltRounds , async(err , hash)=>{
                        if(err){
                            console.log("Error in hashing password");
                        }
                        else{
                            console.log(hash);
                            console.log(currDate);
                            var storing = await db.query("insert into account_details(name , email , password , creation_date) values($1 , $2 , $3 , $4) returning *" , [username , email , hash , currDate]);
                            const user = storing.rows[0];
                            req.login(user , (err)=>{
                                res.redirect("/secrets");
                            })
                        }
                    });
                    
                }
                catch(err){
                    res.status(500).send("Error checking user existence");
                }
            }
        }
    }
    catch(err){
        console.log(err);
    }
})

// app.post("/login" , async(req , res)=>{
//     try{
//         var {accountType , email , password} = req.body;
//         console.log(req.body);
//         var stored = await db.query("select * from account_details where email = $1 and account_type = $2" , [email , accountType]);
//         if(stored.rowCount == 0){
//             res.status(400).send("User doesn't exist!");
//         }
//         else{
//             const user = stored.rows[0];
//             bcrypt.compare(password , user.password , (err , valid)=>{
//                 if(err){
//                     console.log("Error comparing passwords");
//                 }
//                 else{
//                     if(valid){
//                         res.status(400).send("User Found :)");
//                     }
//                     else{
//                         res.status(400).send("Incorrect password");
//                     }
//                 }
//             })
//         }
//     }
//     catch(e){
//         console.log(e);
//     }
// });
app.post("/login", passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login"
}));
app.get("/secrets" , (req , res)=>{
    if(req.isAuthenticated()){
        res.sendFile(__dirname + "/public/html/secret.html");
    }
    else{
        res.redirect("/login");
    }
})

app.get("/logout", (req, res) => {
    req.logout(function (err) {
      if (err) {
        return next(err);
      }
      res.redirect("/login");
    });
  });

passport.use(new Strategy(
    { usernameField: 'email',
        passwordField: 'password',
        passReqToCallback: true
    },
    async function verify(req , email , password , callback){
    try{
        // console.log("I am called");
        const accountType = req.body.accountType;
        const result = await db.query("select * from account_details where email = $1 and account_type = $2" , [email , accountType]);
        if(result.rowCount > 0){
            const user = result.rows[0];
            const storedHashedPassword = user.password;
            bcrypt.compare(password , storedHashedPassword , (err , result)=>{
                if(err){
                    callback(err);
                }
                else{
                    if(result){
                        callback(null , user);
                    }
                    else{
                        
                        callback(null , false);
                    }
                }
            });
        }
        else{
            callback("User not found");
        }
    }
    catch(err){
        console.log(err);
    }
}));
passport.serializeUser((user , callback)=>{
    callback(null , user);
  });
  passport.deserializeUser((user , callback)=>{
    callback(null , user);
  });
app.listen(port,()=>{
    console.log("Server is up and running on port " + port);
});