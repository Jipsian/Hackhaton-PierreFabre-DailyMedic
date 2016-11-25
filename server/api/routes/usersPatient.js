import express from 'express';
import UserPatient from '../models/userPatient.js';
import Auth from '../middlewares/authorization.js';

let router = express.Router();

module.exports = (app) => {

    var userPatient = new userPatient();

    app.get('/loggedin', Auth.hasAuthorization, (req, res, next) => {
        res.sendStatus(200);
    });

    app.post('/login', userPatient.connect);

    router.get('/', Auth.isAdministrator, userPatient.findAll);

    router.get('/:id', Auth.isAdministrator, userPatient.findById);

    router.post('/', userPatient.create);

    router.put('/:id', Auth.isAdministrator, userPatient.update);

    router.delete('/:id', Auth.isAdministrator, userPatient.delete);

    app.use('/usersPatient', router);

};
