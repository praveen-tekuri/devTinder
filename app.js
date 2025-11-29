const express = require("express");
const app = express();
const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const cors = require("cors");

require('dotenv').config();

app.use(
    cors({
        origin: "http://localhost:5173",
        credentials: true,
    })
)
app.use(express.json());
app.use(cookieParser());

const SAFE_DATA = ["firstName", "lastName", "photoUrl", "about", "age", "gender", "skills"]

// schema models
const userSchema = new mongoose.Schema({
    firstName: {
        type: String, required: true, minLength: 3, 
    },
    lastName: {
        type: String, required: true, 
    },
    age: {
        type: Number,
    },
    gender: {
        type: String, 
        validate(value){
            if(!["male", "female", "others"].includes(value)){
                throw new Error("Please enter valid gender type")
            }
        }
    },
    emailId: {
        type: String, required: true,  lowercase: true, trim: true,
        unique: true,
        validate: (value) => {
            if(!validator.isEmail(value)){
                throw new Error("Please enter valid email")
            }
        }
    },
    password: {
        type: String, required: true, 
    },
    skills: {
        type: [String],
    },
    photoUrl: {
        type: String,
        default: "https://geographyandyou.com/images/user-profile.png",
        validate(value){
            if(!validator.isURL(value)){
                throw new Error("Please enter valid photo url")
            }
        }
    },
    about: {
        type: String, 
        default: "This is default about the user"
    }
}, {timestamps: true})

const User = mongoose.model("User", userSchema);

const connectionSchema = new mongoose.Schema({
    fromUserId: {
        type: mongoose.Schema.ObjectId, ref:"User", required: true
    },
    toUserId: {
        type: mongoose.Schema.ObjectId, ref:"User", required: true,
    },
    status: {
        type: String, required: true,
        enum: {
            values: ["interested", "ignored", "accepted", "rejected"],
            message: "{VALUE} is not valid status."
        }
    }
})

const UserConnection = mongoose.model("UserConnection", connectionSchema);

app.post("/signup", async (req, res) => {
    try {
        const {firstName, lastName, age, gender, emailId, password, skills, photoUrl, about} = req.body;
        // validations
        if(!firstName || !lastName){
            return res.status(401).send("FirstName & lastName are required")
        }
        if(!validator.isEmail(emailId)){
            return res.status(401).send("Please enter valid email address")
        }
        if(!validator.isStrongPassword(password)){
            return res.status(401).send("Please enter strong password")
        }
        if(skills && skills.length > 5){
            return res.status(401).send("Skills should not be more than 5")
        }
        // Encrypting the password
        const passwordHash = await bcrypt.hash(password, 10);
        // new instance
        const user = new User({firstName, lastName, age, gender, emailId, password: passwordHash, skills, photoUrl, about})
        const data = await user.save();
        res.json({message: "Registration successful", data});
        
    } catch (error) {
        res.status(400).send("ERR: " + error.message)
    }

})

app.post("/login", async(req, res) => {
    try {
        const {emailId, password} = req.body;
         // Find the user in db with emailId
         const user = await User.findOne({emailId});
         if(!user){
            return res.status(401).send("Invalid credentials");
         }
        //  Comparing the password
         const isPasswordValid = await bcrypt.compare(password, user.password);
         if(isPasswordValid){
            // if password is valid, send the token
            const token = await jwt.sign({_id: user._id}, process.env.JWT_SECRETE_KEY, {expiresIn: "1d"})
            res.cookie("token", token, {expires: new Date(Date.now() + 8 * 360000)});
            res.json({message: "Login Successful, Welcome " + user.firstName, data: user})
         }else{
            return res.status(401).send("Invalid credentials")
         }
    } catch (error) {
        res.status(400).send("ERR: " + error.message)
    }
})

const userAuth = async (req, res, next) => {
    try {
        // Token validation
        const {token} = req.cookies;
        if(!token){
            return res.status(401).send("Invalid token or expired")
        }
        const {_id} = await jwt.verify(token, process.env.JWT_SECRETE_KEY);
        const user = await User.findById(_id);
        if(!user){
            return res.status(401).send("User does not exists");
        }
        req.user = user;
        next();
    } catch (error) {
        res.status(400).send("ERR: userAuth " + error.message);
    }
}

app.get("/profile/view/", userAuth, async(req, res) => {
    try {
        // Get the loggedIn user from the userAuth / token
        const loggedInUser = req.user;
        res.send(loggedInUser);
    } catch (error) {
        res.status(400).send("ERR: " + error.message)
    }
})

app.patch("/profile/edit", userAuth, async(req, res) => {
    try {
        const loggedInUser = req.user;
        // Fields allowed to update
        const isAllowed = Object.keys(req.body).every((key) => ["age", "gender", "password", "skills", "photoUrl", "about"].includes(key));
        if(!isAllowed){
            throw new Error("This field is not allowed to update");
        }
        // Update loggedInUser in database with new data
        for(let key of Object.keys(req.body)){
            if(key === "password"){
                loggedInUser.password = await bcrypt.hash(req?.body?.password, 10); 
            } else{
                loggedInUser[key] = req.body[key];
            }
        }
        const data = await loggedInUser.save();
        res.json({message: "Profile has been updated", data});
    } catch (error) {
        res.status(400).send("ERR: " + error.message)
    }
})

app.post("/logout", userAuth, async(req, res) => {
    try {
        res.cookie("token", null, {expires: new Date(Date.now())});
        return res.json({message: "Logout successful"})
    } catch (error) {
        res.status(400).send("ERR: " + error.message)
    }
})

app.post("/request/send/:status/:userId", userAuth, async(req, res) => {
    try {
        const loggedInUser = req.user;
        const {status, userId} = req.params;
        const fromUserId = loggedInUser._id;
        const toUserId = userId;
        
        // Check if the toUser exists in db or not
        const toUser = await User.findById(toUserId);
        if(!toUser){
            return res.status(401).send("userId is not found in the database or invalid")
        }

        // Status should be interested or ignored
        if(!["interested", "ignored"].includes(status)){
            return res.status(401).send("Status should be either interested or ignored");
        }

        // Don't allow the user to send the connection to self.
        if(fromUserId.toString() === toUserId.toString()){
            return res.status(401).send("You can't send the connection request to yourself!")
        }

        // Check if connection request already sent from fromUserId to toUserId or toUserId to fromUserId
        const isExistingConnection = await UserConnection.findOne({
            $or: [
                {fromUserId, toUserId},
                {fromUserId: toUserId, toUserId: fromUserId}
            ]
        })
        if(isExistingConnection){
            return res.status(401).send("Connection request already exists!")
        }

        // new instance of UserConnection
        const userConnection = new UserConnection({fromUserId, toUserId, status})
        const data = await userConnection.save();
        res.json({message: `${loggedInUser.firstName} ${status} in ${toUser.firstName}`, data})

    } catch (error) {
        res.status(400).send("ERR: " + error.message)
    }
})

app.get("/profile/requests", userAuth, async(req, res) => {
    try {
        const loggedInUser = req.user;
        // find all the pending requests to the toUserId:loggedInUser and status should be interested.
        const requests = await UserConnection.find({
            toUserId: loggedInUser._id, status: "interested"
        }).populate("fromUserId", SAFE_DATA)
        if(requests.length === 0){
            return res.status(400).json({message: "No Requests found"})
        }
        res.json({message: `${requests.length} Pending requests`, requests})
    } catch (error) {
        res.status(400).send("ERR: " + error.message)
    }
})

app.post("/request/review/:status/:requestId", userAuth, async(req, res) => {
    try {
        const loggedInUser = req.user;
        const {status, requestId} = req.params;
        // Check if the requestId is present or not in the database
        if(!requestId){
            return res.status(401).send("requestId is not present in the database")
        }

        // ALLOW status as accepted or rejected
        if(!["accepted", "rejected"].includes(status)){
            return res.status(401).send("status should be either accepted or rejected " + status);
        }

        // find the Request with requestId, toUserId will be loggedInUser and status should be interested
        const connectionRequest = await UserConnection.findOne({
            _id: requestId,
            toUserId: loggedInUser._id,
            status: "interested"
        })

        // assign the status 
        connectionRequest.status = status;

        const data = await connectionRequest.save()
        res.json({message: `Connection request ${status}`, data})

    } catch (error) {
        res.status(400).send("ERR: " + error.message)
    }
})

app.get("/profile/connections", userAuth, async(req, res) => {
    try {
        const loggedInUser = req.user;
        // find all the connections where loggedInUser sent or received the request and accepted.
        // Praveen => Naveen => "accepted"
        // Naveen => Praveen => "accepted"
        const connections = await UserConnection.find({
            $or: [
                {fromUserId: loggedInUser._id, status: "accepted"},
                {toUserId: loggedInUser._id, status: "accepted"},
            ]
        }).populate("fromUserId", SAFE_DATA).populate("toUserId", SAFE_DATA);

        // if the fromUserId is same as the loggedInUserId then return toUserId
     
        const newConnections = connections.map((connection) => {
            if(connection.fromUserId._id.toString() === loggedInUser._id.toString()){
                return connection.toUserId
            }else{
                return connection.fromUserId;
            }
        })

        res.json({message: `${connections.length} Connections`, newConnections})
    } catch (error) {
        res.status(400).send("ERR: " + error.message)
    }
})

app.get("/feed", userAuth, async(req, res) => {
    try {
        // Pagination
        const page = parseInt(req.query.page) || 1;
        let limit = parseInt(req.query.limit) || 10;
        limit = limit > 50 ? 50: limit;
        const skip = (page-1) * limit;
        const loggedInUser = req.user;
        // find all the connections / requests
        const connections = await UserConnection.find({
            $or: [
                {fromUserId: loggedInUser._id},
                {toUserId: loggedInUser._id}
            ]
        }).select("fromUserId toUserId");

        // Hide from feed
        const hideFromFeed = new Set();
        connections.forEach((connection) => {
            hideFromFeed.add(connection.fromUserId.toString());
            hideFromFeed.add(connection.toUserId.toString());
        })

        const users = await User.find({
            $and: [
                {_id: {$nin: Array.from(hideFromFeed)} },
                {_id: {$ne: loggedInUser._id} },
            ]
        }).select(SAFE_DATA).skip(skip).limit(limit);
       res.json({message: `Feed ${users.length}`, users})

    } catch (error) {
        res.status(400).send("ERR: ", error.message)
    }
})

const connectDB = async () => await mongoose.connect(process.env.DB_CONNECTION_KEY)

connectDB().then(() => {
    console.log("Database connection established!")
    app.listen(process.env.PORT, () => console.log("server listening on port 7780!!"));
}).catch((err) => {
    console.log("Database can't be connected " + err);
})
