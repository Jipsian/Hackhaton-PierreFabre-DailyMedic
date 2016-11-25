import jsonwebtoken from 'jsonwebtoken';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import tokenPatient from '../../token.js';

const hashCode = (s) => s.split("").reduce((a, b) => {
    a = ((a << 5) - a) + b.charCodeAt(0);
    a & a
}, 0);

const userPatientSchema = new mongoose.Schema({
    email: {
        type: String,
        required: true,
        required: 'Email address is required',
        validate: [function(email) {
            return /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(email);
        }, 'Please fill a valid email address'],
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address'],
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    isAdmin: {
        type: Boolean,
        default: false
    },
    nom: String,
    prenom: String,
    age: String,
    genre: String,
    poids: String,
    taille: String,
    allergies: String,
    grpSang: String,
    autrepato: String,
    medecinTrait: String,
    adresse: String,
    tel: String,
    mail: String
});

userPatientSchema.methods.comparePassword = function(pwd, cb) {
    bcrypt.compare(pwd, this.password, function(err, isMatch) {
        if (err) cb(err);
        cb(null, isMatch);
    });
};

let model = mongoose.model('userPatient', userPatientSchema);

export default class userPatient {

    connect(req, res) {
        if (!req.body.email) {
            res.status(400).send('Please enter an email');
        } else if (!req.body.password) {
            res.status(400).send('Please enter a password');
        } else {
            model.findOne({
                email: req.body.email
            }, (err, userPatient) => {
                if (err || !userPatient) {
                    res.sendStatus(403);
                } else {
                    userPatient.comparePassword(req.body.password, (err, isMatch) => {
                        if (err) {
                            res.status(400).send(err);
                        } else {
                            if (isMatch) {
                                userPatient.password = null;
                                let tk = jsonwebtoken.sign(userPatient, tokenPatient, {
                                    expiresIn: "24h"
                                });
                                res.json({
                                    success: true,
                                    userPatient: userPatient,
                                    tokenPatient: tk
                                });
                            } else {
                                res.status(400).send('Incorrect password');
                            }
                        }
                    });
                }
            });
        }
    }

    findAll(req, res) {
        model.find({}, {
            password: 0
        }, (err, usersPatient) => {
            if (err || !usersPatient) {
                res.sendStatus(403);
            } else {
                res.json(usersPatient);
            }
        });
    }

    findById(req, res) {
        model.findById(req.params.id, {
            password: 0
        }, (err, userPatient) => {
            if (err || !userPatient) {
                res.sendStatus(403);
            } else {
                res.json(userPatient);
            }
        });
    }

    create(req, res) {
        if (req.body.password) {
            var salt = bcrypt.genSaltSync(10);
            req.body.password = bcrypt.hashSync(req.body.password, salt);
        }
        model.create(req.body,
            (err, userPatient) => {
                if (err || !userPatient) {
                    if (err.code === 11000 || err.code === 11001) {
                        err.message = "Email " + req.body.email + " already exist";
                    }
                    res.status(500).send(err.message);
                } else {
                    let tk = jsonwebtoken.sign(userPatient, tokenPatient, {
                        expiresIn: "24h"
                    });
                    res.json({
                        success: true,
                        userPatient: userPatient,
                        tokenPatient: tk
                    });
                }
            });
    }

    update(req, res) {
        model.update({
            _id: req.params.id
        }, req.body, (err, userPatient) => {
            if (err || !userPatient) {
                res.status(500).send(err.message);
            } else {
                let tk = jsonwebtoken.sign(userPatient, tokenPatient, {
                    expiresIn: "24h"
                });
                res.json({
                    success: true,
                    userPatient: userPatient,
                    tokenPatient: tk
                });
            }
        });
    }

    delete(req, res) {
        model.findByIdAndRemove(req.params.id, (err) => {
            if (err) {
                res.status(500).send(err.message);
            } else {
                res.sendStatus(200);
            }
        });
    }
}
