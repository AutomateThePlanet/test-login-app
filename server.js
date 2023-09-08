import fetch from 'node-fetch';
import express from 'express';
import passport from 'passport';
import session from 'express-session';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as FacebookStrategy } from 'passport-facebook';
import path from 'path';
import dotenv from 'dotenv';
import sgMail from '@sendgrid/mail';
import { fileURLToPath } from 'url';
import fs from 'fs';
import https from 'https';
import twilio from 'twilio';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';
import { v4 as uuidv4 } from 'uuid';
import { Router } from 'express';
import bodyParser from 'body-parser';
import speakeasy from 'speakeasy';
import QRCode from 'qrcode';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const newUuid = uuidv4();
const DB_FILE = path.join(__dirname, 'db.json');

dotenv.config();
const app = express();

const PORT = 3000;
app.use(express.json());
app.use(bodyParser.json());
// app.use(bodyParser.urlencoded({ extended: true }));

const secret = 'd#IryuziNby|$z(E<+SW>Gl*Elg{|%';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const FACEBOOK_APP_ID = process.env.FACEBOOK_APP_ID;
const FACEBOOK_APP_SECRET = process.env.FACEBOOK_APP_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET;
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
const TWILLIO_AccountSid = process.env.TWILLIO_AccountSid; // Your Twilio Account SID
const TWILLIO_AUTH_TOKEN = process.env.TWILLIO_AUTH_TOKEN; // Your Twilio Auth Token
const SENDGRID_SENDER_EMAIL = process.env.SENDGRID_SENDER_EMAIL;
const DEFAULT_TEST_PHONE_NUMBER = process.env.DEFAULT_TEST_PHONE_NUMBER;
const TWILLIO_FROM_PHONE = process.env.TWILLIO_FROM_PHONE;

const defaultUsers = [
    {
        id: 1,
        username: 'johnDoe',
        email: 'john@example.com',
        password: 'password123',  // NOTE: In real scenarios, this would be a hashed password.
        role: 'admin',
        loginMethod: 'local',
        provider: 'LOCAL',
        status: 'active',  // new status property
        phone: DEFAULT_TEST_PHONE_NUMBER,
        twoFA: {
            secret: null, // will hold the 2FA secret
            enabled: false
        }
    },
    {
        id: 2,
        username: 'janeDoe',
        email: 'jane@example.com',
        password: 'password456',  // NOTE: In real scenarios, this would be a hashed password.
        role: 'user',
        loginMethod: 'local',
        provider: 'LOCAL',
        status: 'tobeactivated',  // new status property
        phone: DEFAULT_TEST_PHONE_NUMBER,
        twoFA: {
            secret: null, // will hold the 2FA secret
            enabled: false
        }
    }
];

let users;

// Load database from file at startup
if (fs.existsSync(DB_FILE)) {
    const rawData = fs.readFileSync(DB_FILE);
    users = JSON.parse(rawData);
} else {
    // If no DB file exists, initialize it with default data.
    users = defaultUsers;
}

process.on('SIGINT', () => {
    fs.writeFileSync(DB_FILE, JSON.stringify(users, null, 2));
    process.exit();
});

const twilioClient = twilio(TWILLIO_AccountSid, TWILLIO_AUTH_TOKEN);
const twilioRouter = Router();

sgMail.setApiKey(SENDGRID_API_KEY);

// Initialize Passport and session
app.use(cookieParser());
app.use(session({ secret: SESSION_SECRET, resave: true, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Serialize and deserialize user information
passport.serializeUser(function (user, done) {
    done(null, user);
});

passport.deserializeUser(function (obj, done) {
    done(null, obj);
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Google Strategy
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: "https://localhost:3000/auth/google/callback"
},
    function (accessToken, refreshToken, profile, done) {
        // Save the access token here
        profile.token = accessToken;
        return done(null, profile);
    }));


// var FacebookStrategy = require('passport-facebook').Strategy;

passport.use(new FacebookStrategy({
    clientID: FACEBOOK_APP_ID,
    clientSecret: FACEBOOK_APP_SECRET,
    callbackURL: "https://localhost:3000/auth/facebook/callback", // Make sure to update this URL
    profileFields: ['id', 'displayName', 'emails'],
},
    function (accessToken, refreshToken, profile, done) {
        // Here, instead of looking up or creating a user in a database, we're just passing the profile info directly
        // Attach the access token if needed
        profile.accessToken = accessToken;
        return done(null, profile);
    }));

app.get('/reset-db', (req, res) => {
    users = defaultUsers;
    if (fs.existsSync(DB_FILE)) {
        fs.unlinkSync(DB_FILE);  // Delete the database file
    }
    res.send('Database reset successful!');
});

app.get('/auth/facebook',
    passport.authenticate('facebook', { scope: 'email' }));

app.use((req, res, next) => {
    if (req.session.user) {
        res.locals.user = req.session.user;
    }
    next();
});

app.get('/logout', (req, res) => {
    req.session.destroy(function (err) {
        res.cookie('auth', '', { expires: new Date(0) });
        res.cookie('userId', '', { expires: new Date(0) });
        res.redirect('/'); // Redirect back to the homepage or login page
    });
});


app.get('/profile', requireLogin, (req, res) => {
    res.render('profile', { user: req.session.user });
});

app.get('/api/profile', (req, res) => {
    // Here, you would fetch the user's information from your authentication
    // library or database based on their session or authentication token
    if (req.session.user) {
        res.json({
            displayName: req.session.user.displayName,
            provider: req.session.user.provider
        });
    } else {
        res.status(401).send(); // Not authorized
    }
});


// Revoke Google Access
app.get('/revoke-google', (req, res) => {
    const token = req.session.user.googleToken; // Retrieve the Google token from the session
    console.log("Access Token: ", token); // Log the token
    fetch('https://accounts.google.com/o/oauth2/revoke?token=' + token) // Removed { method: 'POST' }
        .then(response => {
            if (!response.ok) {
                return response.text().then(text => Promise.reject(text));
            }

            // Handle success (e.g., log out the user or clear the token)
            req.session.user = null; // Or use req.session.destroy();
            res.redirect('/'); // Redirect or send a response as needed
        })
        .catch(error => {
            // Handle errors
            console.error(error);
            res.status(500).send('An error occurred while revoking access');
        });
});


// Revoke Facebook Access
app.get('/revoke-facebook', (req, res) => {
    const userId = req.session.user.facebookUserId; // Retrieve the Facebook user ID from the session
    const accessToken = req.session.user.facebookAccessToken; // Retrieve the Facebook access token from the session
    console.log("Access Token: ", accessToken); // Log the token
    fetch('https://graph.facebook.com/' + userId + '/permissions?access_token=' + accessToken, { method: 'DELETE' })
        .then(response => {
            if (!response.ok) {
                return response.text().then(text => Promise.reject(text));
            }

            // Handle success (e.g., log out the user or clear the token)
            req.session.user = null;
            res.redirect('/'); // Redirect or send a response as needed
        })
        .catch(error => {
            // Handle errors
            console.error(error);
            res.status(500).send('An error occurred while revoking access');
        });
});

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    function (req, res) {
        console.log('Google profile:', req.user);

        let email = req.user.emails ? req.user.emails[0].value : req.user.email;

        const user = registerOrRetrieveUser({
            provider: 'google',
            id: req.user.id,  // Use the provided ID
            displayName: req.user.displayName,
            email: email
        });

        req.session.user = user;
        req.session.user.googleToken = req.user.token;

        const payload = {
            displayName: user.username,
            password: user.password,
            userId: user.id.toString(),
        };

        res.cookie('auth', generateHash(payload));
        res.cookie('userId', user.id.toString());
        res.redirect('/profile');
    }
);

app.get('/auth/facebook/callback',
    passport.authenticate('facebook', { failureRedirect: '/' }),
    function (req, res) {
        console.log('Facebook profile:', req.user);

        // let email = req.user.emails ? req.user.emails[0].value : req.user.email;
        // let displayName = email.substring(0, email.indexOf('@'));

        // const user = registerOrRetrieveUser({
        //     provider: 'facebook',
        //     id: req.user.id,  // Use the provided ID
        //     displayName: displayName,
        //     email: email
        // });

        req.session.user = req.user;
        req.session.user.facebookAccessToken = req.user.accessToken;

        const payload = {
            displayName: req.user.displayName,
            password: req.user.password,
            userId: req.user.id.toString(),
        };

        res.cookie('auth', generateHash(payload));
        res.cookie('userId', req.user.id.toString());
        res.redirect('/profile');
    }
);

app.get('/auth/passwordless', (req, res) => {
    // Generate a random code
    const code = Math.floor(Math.random() * 1000000);

    // Store the code in the user's session
    req.session.passwordlessCode = code;

    // Register or retrieve the user based on the email
    const user = registerOrRetrieveUser({ email: req.query.email, provider: 'Passwordless' });
    req.session.tempUserId = user.id;  // Store the user ID in session for retrieval after verification

    // Define email content
    const msg = {
        to: user.email,
        from: SENDGRID_SENDER_EMAIL, // Update this to your sender email address
        subject: 'Your login code',
        text: `Your login code is: ${code}`
    };

    // Send the email
    sgMail.send(msg)
        .then(() => {
            res.json({ success: true }); // Responding with JSON
        })
        .catch(error => {
            console.error(error);
            res.status(500).send('Error sending code');
        });

});

app.post('/auth/verify-code', (req, res) => {
    console.log('verify: req.body.code ' + req.body.code);
    console.log('verify: passwordlessCode ' + req.session.passwordlessCode);

    if (req.body.code == req.session.passwordlessCode) {
        // Retrieve the user's data from our in-memory database using the ID stored in the session
        const user = users.find(u => u.id === req.session.tempUserId);
        console.log('verify: req.session.tempUserId ' + req.session.tempUserId);
        // If, for any reason, the user isn't found (which shouldn't happen), return an error
        // if (!user) {
        //     return res.status(500).json({ success: false, message: 'User not found' });
        // }

        // Authentication successful, create user session
        req.session.user = {
            displayName: user.username || 'Unknown User',
            provider: 'Passwordless',
            id: user.id
        };

        const payload = {
            displayName: user.username,
            password: user.password,
            userId: user.id.toString(),
        };

        res.cookie('auth', generateHash(payload));
        res.cookie('userId', user.id.toString());
        res.json({ success: true, redirectUrl: '/profile' }); // Include redirect URL in the response
    } else {
        res.status(401).json({ success: false, message: 'Invalid code' });
    }
});


app.get('/logoutpasswordless', (req, res) => {
    req.session.destroy(); // Destroying the session
    res.redirect('/'); // Redirecting to the homepage or login page
});

// verify that we are logged in
function requireLogin(req, res, next) {
    if (!req.cookies || !req.cookies.auth || !req.cookies.userId) {
        return res.redirect('/'); // Redirecting to login if cookies are missing
    }

    const authCookie = req.cookies.auth;
    const userId = req.cookies.userId;

    const user = users.find(u => u.id.toString() === userId);
    req.session.user = user;
    if (!user) {
        return res.redirect('/'); // Redirecting to login if user is not found
    }

    const payload = {
        displayName: user.username,
        password: user.password,
        userId: user.id.toString(),
    };

    if (authCookie && authCookie === generateHash(payload)) {
        next(); // Proceed to the next middleware or route handler
    } else {
        res.redirect('/'); // Redirecting to login if auth verification fails
    }
}

app.get('/profile', requireLogin, (req, res) => {
    res.render('profile', { user: req.session.user });
});


app.use(express.static(path.join(__dirname)));

// Define a route handler for the default home page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/send-verification-code', (req, res) => {
    const phoneNumber = req.body.phoneNumber;
    const verificationCode = Math.floor(Math.random() * 1000000).toString().padStart(6, '0');

    req.session.verificationCode = verificationCode;
    req.session.phoneNumber = phoneNumber;  // Store phone number in session for later retrieval

    twilioClient.messages.create({
        body: `Your verification code is: ${verificationCode}`,
        from: TWILLIO_FROM_PHONE,
        to: phoneNumber,
    }).then(() => {
        res.json({ success: true });
    }).catch(error => {
        console.error(error);
        res.status(500).send('An error occurred while sending the verification code');
    });
});

app.post('/verify-sms-code', (req, res) => {
    const userCode = req.body.code;
    if (userCode === req.session.verificationCode) {
        // Get or register the user based on the phone number
        const user = registerOrRetrieveUser({
            phone: req.session.phoneNumber,
            email: `${Math.random().toString(36).substring(7)}@example.com`,  // Random email
            displayName: `User${Math.floor(Math.random() * 1000)}`,          // Random username
            provider: 'sms'
        });

        // Log the user in
        req.session.user = user;

        const payload = {
            displayName: user.username,
            password: user.password,
            userId: user.id.toString(),
        };

        res.cookie('auth', generateHash(payload));
        res.cookie('userId', user.id.toString());
        res.json({ success: true, redirectUrl: '/profile' });
    } else {
        res.status(400).json({ success: false, message: 'Invalid code. Please try again.' });
    }
});

app.post('/login', (req, res) => {
    const { usernameOrEmail, password, rememberMe } = req.body;

    const user = users.find(u => (u.username === usernameOrEmail || u.email === usernameOrEmail) && u.password === password);  // NOTE: This is a simplistic way and not safe. In real scenarios, you'd want to hash and salt your passwords.
    console.log('Remember Me Value:', rememberMe);
    console.log('Email:', user.email);
    console.log('Id:', user.id);
    console.log('Status:', user.status);
    if (user) {
        if (user.twoFA && user.twoFA.enabled) {
            // If the user has 2FA enabled and hasn't provided a 2FA token yet
            if (!req.body.twoFaToken) {
                return res.json({ success: false, twoFaRequired: true });
            } else if (!verifyTwoFaToken(user, req.body.twoFaToken)) {
                return res.status(401).json({ success: false, message: 'Invalid 2FA token' });
            }
        }

        switch (user.status) {
            case 'active':
                req.session.user = {
                    displayName: user.username,
                    provider: 'LOCAL'
                };

                const payload = {
                    displayName: user.username,
                    password: user.password,
                    userId: user.id.toString(),
                };

                res.cookie('auth', generateHash(payload));
                res.cookie('userId', user.id.toString());

                if (rememberMe) {
                    req.session.cookie.maxAge = 30 * 24 * 60 * 60 * 1000;  // Set cookie expiration to 30 days
                } else {
                    req.session.cookie.expires = false;  // Cookie will be removed when browser is closed
                }

                console.log('SUCCESSFULL LOGIN');

                return res.json({ success: true, redirectUrl: '/profile' });

            case 'passwordreset':
                return res.status(403).json({ success: false, message: 'Password reset in progress. Please check your email or reset your password.' });

            case 'inactive':
                return res.status(403).json({ success: false, message: 'Your account is inactive. Contact support for more information.' });

            case 'tobeactivated':
                return res.status(403).json({ success: false, message: 'Your account is not activated. Please check your email for an activation code.' });

            case 'bot':
                return res.status(403).json({ success: false, message: 'Bot accounts are not allowed to login.' });

            default:
                return res.status(401).json({ success: false, message: 'Invalid login credentials' });
        }
    } else {
        return res.status(401).json({ success: false, message: 'Invalid login credentials' });
    }
});

function verifyTwoFaToken(user, token) {
    return speakeasy.totp.verify({
        secret: user.twoFA.secret,
        encoding: 'base32',
        token: token
    });
}

// registration
app.post('/register', (req, res) => {
    const { username, email, password, confirmPassword, phone } = req.body; // Added phone

    // Check if passwords match
    if (password !== confirmPassword) {
        return res.status(400).json({ success: false, message: 'Passwords do not match!' });
    }

    // Check if user already exists
    const existingUser = users.find(u => u.username === username || u.email === email);
    if (existingUser) {
        return res.status(400).json({ success: false, message: 'User already exists!' });
    }

    const usernameRegex = /^[a-zA-Z0-9]{4,16}$/;
    if (!usernameRegex.test(username)) {
        return res.status(400).json({ success: false, message: 'Username must be 4-16 characters long and contain only alphanumeric characters.' });
    }

    // Check for valid email
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({ success: false, message: 'Invalid email format.' });
    }

    // Check for valid phone number - let's assume a simple regex for this.
    const phoneRegex = /^\+?[0-9]{10,15}$/; // This is a very basic phone number regex. You may need to adjust depending on your requirements.
    if (!phoneRegex.test(phone)) {
        return res.status(400).json({ success: false, message: 'Invalid phone number format. Please include only numbers and it should be 10-15 digits long.' });
    }

    // Check if passwords match and for their strength (8-32 characters, at least one uppercase, one lowercase, one number)
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.{8,32})/;
    if (password !== confirmPassword) {
        return res.status(400).json({ success: false, message: 'Passwords do not match!' });
    } else if (!passwordRegex.test(password)) {
        return res.status(400).json({ success: false, message: 'Password must be 8-32 characters long and contain at least one uppercase letter, one lowercase letter, and one number.' });
    }

    // Create a new user
    const newUser = {
        id: users.length + 1,
        username: username,
        email: email,
        phone: phone, // Added phone
        password: password,
        status: 'pending',
        activationCode: Math.random().toString(36).substr(2, 6).toUpperCase()  // Simple code generation.
    };

    users.push(newUser);

    // Now, send an email with the activation code to the user.
    const msg = {
        to: newUser.email,
        from: SENDGRID_SENDER_EMAIL,
        subject: 'Your Activation Code',
        text: `Your activation code is: ${newUser.activationCode}`
    };

    sgMail.send(msg)
        .then(() => {
            res.json({ success: true });
        })
        .catch(error => {
            console.error(error);
            res.status(500).send('Error sending activation code');
        });
});

app.get('/2fa/generate-token/:userId', (req, res) => {
    const userId = parseInt(req.params.userId, 10);
    const user = users.find(u => u.id === userId);
    // Check if user exists and has a secret (i.e., 2FA is set up)
    if (user && user.twoFA.secret) {
        // Generate the token
        const token = speakeasy.totp({
            secret: user.twoFA.secret,
            encoding: 'base32'
        });

        // For testing purposes
        // res.json({
        //     token: token
        // });
        res.send(token);
    } else {
        res.status(404).json({ error: 'User not found or 2FA not set up' });
    }
});


// password reset

app.post('/request-password-reset', (req, res) => {
    const { email } = req.body;

    const user = users.find(u => u.email === email);

    if (!user) {
        return res.status(404).json({ success: false, message: 'Email not found.' });
    }

    // Generate a reset token (in real scenarios, make this more secure!)
    user.resetToken = Math.random().toString(36).substr(2);
    user.status = 'passwordreset';

    // Create the reset link
    const resetLink = `https://localhost:3000/index.html#passwordReset?token=${user.resetToken}`;

    // Define email content
    const msg = {
        to: email,
        from: SENDGRID_SENDER_EMAIL,
        subject: 'Password Reset',
        text: `Click the following link to reset your password: ${resetLink}`
    };

    // Send the email
    sgMail.send(msg)
        .then(() => {
            res.json({ success: true, message: 'Password reset email sent!' });
        })
        .catch(error => {
            console.error(error);
            res.status(500).send('Error sending password reset email');
        });
});

app.post('/password-reset', (req, res) => {
    const { token, newPassword } = req.body;

    const user = users.find(u => u.resetToken === token);

    if (!user) {
        return res.status(400).json({ success: false, message: 'Invalid reset token.' });
    }

    // Reset the password (in real scenarios, hash this!)
    user.password = newPassword;
    user.resetToken = null;
    user.status = 'active';  // Reactivate the user

    res.json({ success: true, message: 'Password reset successfully!' });
});

// change user status
app.post('/set-status', (req, res) => {
    const { email, status } = req.body;

    // Find the user by email
    const user = users.find(u => u.email === email);

    if (!user) {
        return res.status(400).json({ success: false, message: 'User not found!' });
    }

    // Update the user's status
    user.status = status;

    res.json({ success: true, message: 'User status updated successfully!' });
});

// generate authentication cookie for automated tests
app.post('/generate-auth-cookie', (req, res) => {
    const { displayName, password, userid } = req.body;

    // Validate input (you should implement more comprehensive validation)
    if (!displayName || !password) {
        return res.status(400).send('Invalid input.');
    }

    const payload = {
        displayName: displayName,
        password: password,
        userId: userid,
    };

    res.cookie('auth', generateHash(payload));
    res.send('Auth cookie generated!');
});


app.get('/api/verify-auth-cookie', (req, res) => {
    if (!req.cookies || !req.cookies.auth) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const authCookie = req.cookies.auth;
    const userId = req.cookies.userId;

    console.log('auth cookie = ' + authCookie);
    console.log('userId cookie = ' + userId);

    if (!userId) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const user = users.find(u => u.id.toString() === userId);

    if (!user) {
        console.log('user not found');
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const payload = {
        displayName: user.username,
        password: user.password,
        userId: userId,
    };

    console.log('before checks');
    if (authCookie && authCookie === generateHash(payload)) {
        const payload1 = {
            displayName: user.username,
            provider: user.provider,
            userId: userId,
        };

        res.json(payload1);
    } else {
        res.status(401).send('Unauthorized');
    }
});

app.post('/update-profile', (req, res) => {
    const { username, email, phoneNumber, password } = req.body;

    // Check if user ID exists in the cookie
    const userId = parseInt(req.cookies.userId, 10); // Parsing the userId to an integer

    // Fetch user data (this is a simulated in-memory example)
    const user = users.find(u => u.id === userId); // users is the same array as in the previous example

    if (!user) {
        return res.status(404).send('User not found');
    }

    // Email validation
    const emailPattern = /^\S+@\S+\.\S+$/;
    if (!emailPattern.test(email)) {
        return res.status(400).send('Invalid email format');
    }

    // Phone number validation (for 10 to 13 digit numbers)
    const phonePattern = /^[0-9]{10,13}$/;
    if (!phonePattern.test(phoneNumber)) {
        return res.status(400).send('Invalid phone number format');
    }

    // Password length validation (only if provided)
    if (password && password.trim() !== '' && password.length < 8) {
        return res.status(400).send('Password should be at least 8 characters long');
    }

    // Update user logic
    user.username = username;
    user.email = email;
    user.phone = phoneNumber;

    if (password && password.trim() !== '') {
        user.password = password; // NOTE: In a real scenario, please hash and salt the password before storing!
    }

    res.send('Profile updated successfully');
});


function generateHash(payload) {
    console.log('generateHash: ' + JSON.stringify(payload));

    return crypto.createHmac('sha256', secret)
        .update(JSON.stringify(payload))
        .digest('hex');
}

function registerOrRetrieveUser(providerData) {
    let existingUser;

    // If phone number is provided, use it for lookup
    if (providerData.phone) {
        existingUser = users.find(u => u.phone === providerData.phone);
    }

    // If email is provided and no user was found by phone, use email for lookup
    if (providerData.email && !existingUser) {
        existingUser = users.find(u => u.email === providerData.email);
    }

    // If the user doesn't exist, create a new user entry for them
    if (!existingUser) {
        const newUser = {
            id: users.length + 1,
            username: providerData.displayName || `User${Math.floor(Math.random() * 1000)}`, // Fallback to random username if none provided
            email: providerData.email || `${Math.random().toString(36).substring(7)}@atp.com`, // Fallback to random email if none provided
            phone: providerData.phone || null,
            password: newUuid,
            status: 'active',
            provider: providerData.provider,
            activationCode: null,
            twoFA: {
                secret: null,
                enabled: false
            }
        };
        users.push(newUser);
        existingUser = newUser;
    }

    return existingUser;
}

app.get('/get-profile', (req, res) => {
    // Assuming req.user contains the user data after successful authentication
    const userId = parseInt(req.cookies.userId, 10); // Parsing the userId to an integer

    // Fetch user data (this is a simulated in-memory example)
    const user = users.find(u => u.id === userId); // users is the same array as in the previous example

    console.log('Request for profile of user with ID:', userId);

    // Logging all the users for troubleshooting
    console.log('All users in the system:');
    users.forEach(u => {
        console.log(`ID: ${u.id}, Username: ${u.username}, Email: ${u.email}`);
    });

    if (!user) {
        return res.status(404).send('User not found');
    }

    // Send user data without the password
    const { password, ...userData } = user;

    console.log('Server retrieved profile:', userData);

    res.json(userData);
});

app.get('/2fa/status', (req, res) => {
    const user = getUserFromSession(req); // implement this according to your session management

    if (!user) {
        return res.status(401).send({ error: 'Unauthorized' });
    }

    return res.send({ enabled: user.twoFA.enabled });
});

app.get('/2fa/initiate', (req, res) => {
    const user = getUserFromSession(req);

    if (!user) {
        return res.status(401).send({ error: 'Unauthorized' });
    }

    const secret = speakeasy.generateSecret();

    // Temporarily save this secret (don't enable 2FA yet)
    user.twoFA.tempSecret = secret.base32;

    QRCode.toDataURL(secret.otpauth_url, (err, dataURL) => {
        if (err) {
            return res.status(500).send({ error: 'Unable to generate QR code' });
        }
        res.send({ qrcode: dataURL });
    });
});

app.post('/2fa/verify', (req, res) => {
    const user = getUserFromSession(req);
    const token = req.body.token;
    console.log('verify user: ' + user);
    console.log('verify token: ' + token);
    console.log('verify tempSecret: ' + user.twoFA.tempSecret);
    console.log('Received body:', req.body);
    console.log('Received body token:', req.body.token);
    if (!user || !token) {
        return res.status(401).send({ error: 'Unauthorized or invalid token' });
    }

    const verified = speakeasy.totp.verify({
        secret: user.twoFA.tempSecret,
        encoding: 'base32',
        token: token
    });

    if (verified) {
        user.twoFA.secret = user.twoFA.tempSecret;
        user.twoFA.enabled = true;
        delete user.twoFA.tempSecret;
        return res.send({ verified: true });
    } else {
        return res.send({ verified: false });
    }
});

app.post('/2fa/disable', (req, res) => {
    const user = getUserFromSession(req);

    if (!user) {
        return res.status(401).send({ error: 'Unauthorized' });
    }

    user.twoFA.secret = null;
    user.twoFA.enabled = false;

    res.send({ disabled: true });
});

function getUserFromSession(req) {
    const userId = parseInt(req.cookies.userId, 10);
    const user = users.find(u => u.id === userId);
    return user; 
}

const options = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('certificate.pem'),
};

https.createServer(options, app).listen(3000, () => {
    console.log('Server running on https://localhost:3000');
});