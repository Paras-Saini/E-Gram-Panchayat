import express from "express";
import {dirname} from 'path';
import { fileURLToPath } from "url";
const __dirname = dirname(fileURLToPath(import.meta.url));
const app = express();
const port = 3000;

app.use(express.static("public"));

app.get("/" , (req , res)=>{
    res.sendFile(__dirname + "/ public/html/login.html");
})
app.listen(port,()=>{
    console.log("Server is up and running on port " + port);
});