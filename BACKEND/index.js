const express = require('express');
const app = express();
const mongoose = require('mongoose');
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
require('dotenv').config();
const crypto = require("crypto");
const cors = require("cors");

app.use(express.json());

app.use(cors());



// MongoDB setup
mongoose.connect(process.env.MONGO_URL)
.then(()=> {
    console.log("MongoDB connected")
})
.catch((err)=> {
    console.log(err);
})

const transporter = nodemailer.createTransport({
    // host: "sandbox.smtp.mailtrap.io",
    // port: 2525,
    // auth: {
    //     user: "be849cae7b3c1d",
    //     pass: "5603a987ff5526"
    // }
    host: process.env.MAIL_HOST,
    port: process.env.MAIL_PORT,
    auth: {
        user: process.env.MAIL_USER,
        pass: process.env.MAIL_PASS
    }
})


// Schema creating for user model

const Users = new mongoose.model('Users', {
    email: {
        type: String,
        unique: true,
    },
    password: {
        type: String
    },
    resetPasswordToken: String,
    resetPasswordExpire:  Date,
},
    // {
    //     timestamps: true,
    // }
)
// const User = new mongoose.Schema(
//     {
//         email: {
//             type: String,
//             unique: true,
//     },
//         password: {
//             type: String
//     },
//         resetPasswordToken: String,
//         resetPasswordExpire:  Date,
//     },
//     {
//         timestamps: true,
//     }
// )
// module.exports = mongoose.model('Users', userSchema)

app.post('/api/auth/register', async (req, res) => {
    try{
        let check = await Users.findOne({email: req.body.email})
        if(check) {
            return res.status(400).json({success: false, errors: "Existing User found with same email address"})
        }
        const hashedPassword = await bcrypt.hash(req.body.password, 10);

        const user = new Users({
            email: req.body.email,
            password: hashedPassword,
        })
    
        await user.save();
    
        res.status(201).json({
            success: true,
            message: "User saved"
        });

    } catch (error) {
        console.log(error)
        res.status(500).json({
            success: false,
            message: "Server error"
        })
    }

    const data = {
        user: {
            id: user.id
        }
    }
    const token = jwt.sign(data, 'secret_ecom');
        res.json({success:true, token})
})

app.post('/api/auth/login', async (req, res)=> {


    try {
        let user = await Users.findOne({email: req.body.email});
        if (!user) {
            return res.json({ success: false, errors: "Wrong Email"})
        }

        const access = await bcrypt.compare(req.body.password, user.password)
        if(!access) {
            return res.json({success: false, errors: "Wrong password"});
        }
        const data = {
            user: {
                id: user.id
            }
        };

        const token = jwt.sign(data, 'secret_ecom');
        res.json({success: true, token, message: "User LoggedIn"})
    } catch(error) {
        console.log(error)
        res.status(500).json({message: "Server error"})
    }

})

const fecthUser = async (req, res, next) => {
    const token = req.header('auth-token');
    if (!token) {
        res.status(401).send({errors: "Please authenticate using valid token"})
    } 
    else {
        try {
            const data = jwt.verify(token, 'secret_ecom');
            req.user = data.user;
            next();
        } catch (error) {
            res.status(401).send({errors: "Please authenticate using a valid token"})
        }
    }
}

app.get('/getuser', fecthUser, async (req, res)=> {
    try {
        const users = await Users.find().select('-password');
        res.json(users);
    } catch (err) {
        console.log(err);
        res.status(500).json({ error: 'Server error'})
    }
})

app.post('/forget-password', async (req, res)=> {
    try {
        const user = await Users.findOne({email: req.body.email });

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "user not found",
            })
        }
        
        //generate token
        const resetToken = crypto.randomBytes(20).toString("hex");

        user.resetPasswordToken = resetToken;
        user.resetPasswordExpire = Date.now() + 15*60*1000; //15min

        await user.save();
        
        
        const resetLink = `http://localhost:3000/reset-password/${resetToken}`

        await transporter.sendMail({
            from: '"Auth App" <no-reply@yourapp.com>',
            to: user.email,
            subject: "Password Reset",
            html: ` 
                <h3>Password Reset Request</h3>
                <p>Click the link below to reset your password:</p>
                <a href="${resetLink}">${resetLink}</a>
                <p>This link expire in 15 minutes.</p>
            `,
        })

        res.json({
            success: true,
            message: "Reset email sent",
        })
    } catch (error) {
        console.log(error);
        res.status(500).json({
            success:false,
            message: "server error"
        });
    }
})

app.put("/reset-password/:token", async(req, res)=> {
    try{
        const user = await Users.findOne({
            resetPasswordToken: req.params.token,
            resetPasswordExpire: { $gt: Date.now() },
        });

        if (!user) {
            return res.status(400).json({
                success: false,
                message: "Invalid or expired token",
            });
        }

        // hash new password
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        

        user.password = hashedPassword;

        // clear reset fields
        user.resetPasswordToken = undefined;
        user.resetPasswordExpire = undefined;

        await user.save();

        res.json({
            success: true,
            message: "Password reset successful"
        });
    } catch (error) {
        console.log(error);
        res.status(500).json({
            success: false,
            message: "Server error"
        })
    }
})
// 4f73866f3358f34bb48201b27cb9942b
app.get("/", (req, res)=> {
    res.send("Running ")
})


const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on ${PORT}`))