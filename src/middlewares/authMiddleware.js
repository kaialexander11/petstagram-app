const jwt = require('../lib/jwt.js');

const { SECRET, TOKEN_KEY } = require('../config/config.js');

exports.auth = async (req, res, next) => {
    const token = req.cookies[TOKEN_KEY];

    if (token) {
        
        try {

            const decodedToken = await jwt.verify(token, SECRET);

            req.user = decodedToken;
            res.locals.user = decodedToken;
            res.locals.isAuthenticated = true;

            next();

        } catch (err) {

            res.clearCookie(TOKEN_KEY);

            res.redirect('/users/login');

        }
    } else {
        next();
    }
};

exports.isAuth = (req, res, next) => {

    if (!req.user) {
        res.redirect('/users/login');
    }

    next();
};