const express = require("express");
const app = express();
const path = require("path");
const cookiesparser = require("cookie-parser");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

mongoose.connect("mongodb://localhost:27017",{
    dbName: "backend"
})

const userSchema = new mongoose.Schema(
    {
        name: String,
        email: String,
        number: Number,
        password: String
    }
)

const User = mongoose.model("dummny", userSchema);
app.use(cookiesparser());
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({extended:true}));
app.set("view engine","ejs");


const isAuthentication = async(req,res,next)=>{
    const token = req.cookies.token;
    if(token){
        const decoded = jwt.verify(token, "Mohitb");
        req.user = await User.findById(decoded._id)
        next();
    }else{
        res.redirect("/login")
    }
}

app.post("/register", async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const userData = {
            name: req.body.name,
            email: req.body.email,
            number: req.body.number,
            password: hashedPassword,
        };

        const findUser = await User.findOne({ email: req.body.email });
        if (findUser) {
            return res.redirect("/login");
        }

        const user = await User.create(userData);
        const token = jwt.sign({ _id: user._id }, "Mohitb");
        res.cookie("token", token, {
            httpOnly: true,
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 1 week
            secure: true,
        });

        res.redirect("/");
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    }
});


app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        let findUser = await User.findOne({ email });
        if (!findUser) {
            return res.redirect("/register");
        }
        const isMatch = await bcrypt.compare(password, findUser.password);
        if (!isMatch) {
            return res.render("login", { email, message: "Incorrect Password" });
        }
        const token = jwt.sign({ _id: findUser._id }, "Mohitb");
        res.cookie("token", token, {
            httpOnly: true,
            expires: new Date(Date.now() + 60 * 1000),
        });
        res.redirect("/");
    } catch (error) {
        console.error(error);
        res.status(500).send("Internal Server Error");
    }
});


app.get("/logout", (req, res) => {
    res.clearCookie("token", {
        httpOnly: true,
        expires: new Date(0),
    });
    res.redirect("/");
});


app.get("/register", (req,res)=>{
    res.render("register.ejs")
})

app.get("/login", (req,res)=>{
    res.render("login.ejs")
})

app.get("/", isAuthentication, (req,res)=>{
    console.log(req.user)
    res.render("logout", {name: req.user.name})
})


app.listen(5000, ()=>{
    console.log("Server has been started")
})