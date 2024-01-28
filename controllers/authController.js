const passport = require('passport');
const bcryptjs = require('bcryptjs');
const nodemailer = require('nodemailer');
const { google } = require("googleapis");
const OAuth2 = google.auth.OAuth2;
const jwt = require('jsonwebtoken');
const JWT_KEY = "jwtactive987";
const JWT_RESET_KEY = "jwtreset987";

//------------ User Model ------------//
const User = require('../models/User');

//------------ Register Handle ------------//
exports.registerHandle = (req, res) => {
    const { name, email, password, password2 } = req.body;
    let errors = [];

    //------------ Checking required fields ------------//
    if (!name || !email || !password || !password2) {
        errors.push({ msg: 'Please enter all fields' });
    }

    //------------ Checking password mismatch ------------//
    if (password != password2) {
        errors.push({ msg: 'Passwords do not match' });
    }

    //------------ Checking password length ------------//
    if (password.length < 8) {
        errors.push({ msg: 'Password must be at least 8 characters' });
    }

    if (errors.length > 0) {
        res.render('register', {
            errors,
            name,
            email,
            password,
            password2
        });
    } else {
        //------------ Validation passed ------------//
        User.findOne({ email: email }).then(user => {
            if (user) {
                //------------ User already exists ------------//
                errors.push({ msg: 'Email ID already registered' });
                res.render('register', {
                    errors,
                    name,
                    email,
                    password,
                    password2
                });
            } else {

                const oauth2Client = new OAuth2(
                    "276532424410-tm5dsvb6fi7tmja1ehvttvg3altppcg8.apps.googleusercontent.com", // ClientID
                    "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", // Client Secret
                    "https://developers.google.com/oauthplayground" // Redirect URL
                );
//ya29.a0AfB_byBtmqof1LzgisUSioPCb9yWN1ajFngVPnTeZnL1lMIVYlhQwRV4qwIMSco91qkO1kD_1mYpGiq1Hfi92kgq60ez2nxzMqTj2QlhijqDr83zP2LS7FpOHbTzY2EdaWZc5ojcgKTraGzOuga0xTzvaIh90nghyS1CaCgYKAVsSARASFQHGX2MiHtPGgU69iQEaN24Kr-qDzg0171
                oauth2Client.setCredentials({
                    refresh_token: "1//04NfWmLyG4UFtCgYIARAAGAQSNwF-L9IrHMWLkYkN8iWA2ldQ-zt8xsiy5hghBjAX4l7G2JJMsgq0Q9Et5nDYnqK2mK5bg0-pJU0"
                });
                const accessToken = oauth2Client.getAccessToken()

                const token = jwt.sign({ name, email, password }, JWT_KEY, { expiresIn: '30m' });
                const CLIENT_URL = 'http://' + req.headers.host;

                const output = `
                <h2>Hi ${name},</h2>
                <p>Thank you for registering with our service.</p>
                <p>Please click on the following link to activate your account:</p>
                <a href="${CLIENT_URL}/auth/activate/${token}">Activate Account</a>
                <p><b>NOTE:</b> The activation link expires in 30 minutes.</p>
                <p>If you didn't sign up for our service, please ignore this email.</p>
                <p>Best regards,</p>
                <p>The Node js Auth</p>
                
                `;

                const transporter = nodemailer.createTransport({
                    service: 'gmail',
                    auth: {
                        type: "OAuth2",
                        user: "saipriya922000@gmail.com",
                        clientId: "276532424410-tm5dsvb6fi7tmja1ehvttvg3altppcg8.apps.googleusercontent.com",
                        clientSecret: "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",
                        refreshToken: "1//04NfWmLyG4UFtCgYIARAAGAQSNwF-L9IrHMWLkYkN8iWA2ldQ-zt8xsiy5hghBjAX4l7G2JJMsgq0Q9Et5nDYnqK2mK5bg0-pJU0",
                        accessToken: accessToken
                    },
                });

                // send mail with defined transport object
                const mailOptions = {
                    from: '"NodeJS Auth" <saipriya922000@gmail.com>', // sender address
                    to: email, // list of receivers
                    subject: "Account Verification", // Subject line
                    generateTextFromHTML: true,
                    html: output, // html body
                };

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.log(error);
                        req.flash(
                            'error_msg',
                            'Something went wrong on our end. Please register again.'
                        );
                        res.redirect('/auth/login');
                    }
                    else {
                        console.log('Mail sent : %s', info.response);
                        req.flash(
                            'success_msg',
                            'Activation link sent to email ID. Please activate to log in.'
                        );
                        res.redirect('/auth/login');
                    }
                })

            }
        });
    }
}

//------------ Activate Account Handle ------------//
exports.activateHandle = (req, res) => {
    const token = req.params.token;
    let errors = [];
    if (token) {
        jwt.verify(token, JWT_KEY, (err, decodedToken) => {
            if (err) {
                req.flash(
                    'error_msg',
                    'Incorrect or expired link! Please register again.'
                );
                res.redirect('/auth/register');
            }
            else {
                const { name, email, password } = decodedToken;
                User.findOne({ email: email }).then(user => {
                    if (user) {
                        //------------ User already exists ------------//
                        req.flash(
                            'error_msg',
                            'Email ID already registered! Please log in.'
                        );
                        res.redirect('/auth/login');
                    } else {
                        const newUser = new User({
                            name,
                            email,
                            password
                        });

                        bcryptjs.genSalt(10, (err, salt) => {
                            bcryptjs.hash(newUser.password, salt, (err, hash) => {
                                if (err) throw err;
                                newUser.password = hash;
                                newUser
                                    .save()
                                    .then(user => {
                                        req.flash(
                                            'success_msg',
                                            'Account activated. You can now log in.'
                                        );
                                        res.redirect('/auth/login');
                                    })
                                    .catch(err => console.log(err));
                            });
                        });
                    }
                });
            }

        })
    }
    else {
        console.log("Account activation error!")
    }
}

//------------ Forgot Password Handle ------------//
exports.forgotPassword = (req, res) => {
    const { email } = req.body;

    let errors = [];

    //------------ Checking required fields ------------//
    if (!email) {
        errors.push({ msg: 'Please enter an email ID' });
    }

    if (errors.length > 0) {
        res.render('forgot', {
            errors,
            email
        });
    } else {
        User.findOne({ email: email }).then(user => {
            if (!user) {
                //------------ User already exists ------------//
                errors.push({ msg: 'User with Email ID does not exist!' });
                res.render('forgot', {
                    errors,
                    email
                });
            } else {

                const oauth2Client = new OAuth2(
                    "276532424410-tm5dsvb6fi7tmja1ehvttvg3altppcg8.apps.googleusercontent.com", // ClientID
                    "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", // Client Secret
                    "https://developers.google.com/oauthplayground" // Redirect URL
                );

                oauth2Client.setCredentials({
                    refresh_token: "1//04NfWmLyG4UFtCgYIARAAGAQSNwF-L9IrHMWLkYkN8iWA2ldQ-zt8xsiy5hghBjAX4l7G2JJMsgq0Q9Et5nDYnqK2mK5bg0-pJU0"
                });
                const accessToken = oauth2Client.getAccessToken()

                const token = jwt.sign({ _id: user._id }, JWT_RESET_KEY, { expiresIn: '30m' });
                const CLIENT_URL = 'http://' + req.headers.host;
                const output = `
                <h2>Hi ${user.name},</h2>
                <p>We received a request to reset your account password.</p>
                <p>Please click on the following link to reset your password:</p>
                <a href="${CLIENT_URL}/auth/forgot/${token}">Reset Password</a>
                <p><b>NOTE:</b> The reset link expires in 30 minutes.</p>
                <p>If you didn't request this password reset, please ignore this email.</p>
                <p>Best regards,</p>
                <p>The Node Js Auth</p>
                `;

                User.updateOne({ resetLink: token }, (err, success) => {
                    if (err) {
                        errors.push({ msg: 'Error resetting password!' });
                        res.render('forgot', {
                            errors,
                            email
                        });
                    }
                    else {
                        const transporter = nodemailer.createTransport({
                            service: 'gmail',
                            auth: {
                                type: "OAuth2",
                                user: "saipriya922000@gmail.com",
                                clientId: "276532424410-tm5dsvb6fi7tmja1ehvttvg3altppcg8.apps.googleusercontent.com",
                                clientSecret: "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",
                                refreshToken: "1//04NfWmLyG4UFtCgYIARAAGAQSNwF-L9IrHMWLkYkN8iWA2ldQ-zt8xsiy5hghBjAX4l7G2JJMsgq0Q9Et5nDYnqK2mK5bg0-pJU0",
                                accessToken: accessToken
                            },
                        });

                        // send mail with defined transport object
                        const mailOptions = {
                            from: '"Node js Auth" <saipriya922000@gmail.com>', // sender address
                            to: email, // list of receivers
                            subject: "Account Password Reset", // Subject line
                            html: output, // html body
                        };

                        transporter.sendMail(mailOptions, (error, info) => {
                            if (error) {
                                console.log(error);
                                req.flash(
                                    'error_msg',
                                    'Something went wrong on our end. Please try again later.'
                                );
                                res.redirect('/auth/forgot');
                            }
                            else {
                                console.log('Mail sent : %s', info.response);
                                req.flash(
                                    'success_msg',
                                    'Password reset link sent to email ID. Please follow the instructions.'
                                );
                                res.redirect('/auth/login');
                            }
                        })
                    }
                })

            }
        });
    }
}

//------------ Redirect to Reset Handle ------------//
exports.gotoReset = (req, res) => {
    const { token } = req.params;

    if (token) {
        jwt.verify(token, JWT_RESET_KEY, (err, decodedToken) => {
            if (err) {
                req.flash(
                    'error_msg',
                    'Incorrect or expired link! Please try again.'
                );
                res.redirect('/auth/login');
            }
            else {
                const { _id } = decodedToken;
                User.findById(_id, (err, user) => {
                    if (err) {
                        req.flash(
                            'error_msg',
                            'User with email ID does not exist! Please try again.'
                        );
                        res.redirect('/auth/login');
                    }
                    else {
                        res.redirect(`/auth/reset/${_id}`)
                    }
                })
            }
        })
    }
    else {
        console.log("Password reset error!")
    }
}


exports.resetPassword = (req, res) => {
    var { password, password2 } = req.body;
    const id = req.params.id;
    let errors = [];

    //------------ Checking required fields ------------//
    if (!password || !password2) {
        req.flash(
            'error_msg',
            'Please enter all fields.'
        );
        res.redirect(`/auth/reset/${id}`);
    }

    //------------ Checking password length ------------//
    else if (password.length < 8) {
        req.flash(
            'error_msg',
            'Password must be at least 8 characters.'
        );
        res.redirect(`/auth/reset/${id}`);
    }

    //------------ Checking password mismatch ------------//
    else if (password != password2) {
        req.flash(
            'error_msg',
            'Passwords do not match.'
        );
        res.redirect(`/auth/reset/${id}`);
    }

    else {
        bcryptjs.genSalt(10, (err, salt) => {
            bcryptjs.hash(password, salt, (err, hash) => {
                if (err) throw err;
                password = hash;

                User.findByIdAndUpdate(
                    { _id: id },
                    { password },
                    function (err, result) {
                        if (err) {
                            req.flash(
                                'error_msg',
                                'Error resetting password!'
                            );
                            res.redirect(`/auth/reset/${id}`);
                        } else {
                            req.flash(
                                'success_msg',
                                'Password reset successfully!'
                            );
                            res.redirect('/auth/login');
                        }
                    }
                );

            });
        });
    }
}

//------------ Login Handle ------------//
exports.loginHandle = (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/auth/login',
        failureFlash: true
    })(req, res, next);
}

//------------ Logout Handle ------------//
exports.logoutHandle = (req, res) => {
    req.logout();
    req.flash('success_msg', 'You are logged out');
    res.redirect('/auth/login');
}