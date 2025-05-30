const router = require('express').Router();
const userManager = require('../managers/userManager.js');
const { SECRET, TOKEN_KEY } = require('../config/config.js'); 
const { getErrorMessage } = require('../utils/errorHelpers.js');

router.get('/login', (req, res) => {
    res.render('users/login');
});

router.post('/login', async (req, res, next) => {

    const { username, password } = req.body;

    try {

        const token = await userManager.login(username, password);
        res.cookie(TOKEN_KEY, token);
        //res.send('Logged in');
        res.redirect('/');

    } catch (err) {
        //res.render('users/login', { error: getErrorMessage(err) });

        next(err);
    }

});

router.get('/register', (req, res) => {
    res.render('users/register');
});

router.post('/register', async (req, res, next) => {

    const { username, email, password, repeatPassword } = req.body;

    try {
        
        const token = await userManager.register({ username, email, password, repeatPassword });

        res.cookie(TOKEN_KEY, token);
        //res.redirect('/users/login');
        res.redirect('/');

    } catch (err) {
        res.render('users/register', { error: getErrorMessage(err), username, email });
        //next(err);
    }

    //res.send('Registered');

});

router.get('/logout', (req, res) => {
    res.clearCookie('token');

    res.redirect('/');
});

module.exports = router;