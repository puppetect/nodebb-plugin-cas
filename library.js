"use strict";

var User = require.main.require('./src/user');
var Utils = require.main.require('./src/utils')
var Groups = require.main.require('./src/groups');
var pluginJson = require('./plugin.json');
var xml2js = module.parent.require('xml2js');
var _ = module.parent.require('lodash');
var nconf = module.parent.require('nconf');
var request = module.parent.require('request');
var async = module.parent.require('async');
var winston = module.parent.require('winston');
var db = require.main.require('./src/database');
var	passport = module.parent.require('passport');
var	passportLocal = module.parent.require('passport-local').Strategy;
var pluginJson = require('./plugin.json');
var nodeBBUrl = pluginJson.nodeBBUrl;
var CASServerPrefix = pluginJson.CASServerPrefix;
var userCenterPrefix = pluginJson.userCenterPrefix;
var plugin = {};
var sessionStore = {};

plugin.init = function(params, callback){
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;
    var router = params.router,
        hostMiddleware = params.middleware,
        hostControllers = params.controllers;

    router.get('/*', function(req, res, next){
        if(req.query.ticket){
            sessionStore[req.query.ticket] = req.session;
        };
        next();
    });


    router.get('(/api)?/register', function (req, res, next) {
        var url = `${userCenterPrefix}`;
        if (res.locals.isAPI) {
            res.set('X-Redirect', encodeURI(url)).status(200).json({
                external: url
            });
        } else {
            res.redirect(url)
        }
    })

    router.get('(/api)?/login', function(req, res, next){
        var returnTo = (req.headers['x-return-to'] || '').replace(nconf.get('base_url') + nconf.get('relative_path'), '');
        if (returnTo) {
            req.session.returnTo = returnTo;
        }
        var url = `${CASServerPrefix}/login?service=${nodeBBUrl}`;
        if (res.locals.isAPI) {
            res.set('X-Redirect', encodeURI(url)).status(200).json({
                external: url
            });
        } else {
            res.redirect(url);
        }
    });

    router.get('/cas/login', hostMiddleware.buildHeader, function(req, res, next){
        res.render('casLogin', {nextUrl: req.session.returnTo});
    });

    router.post('/cas/logout', function(req, res, next){
        async.waterfall([function(callback){
            xml2js.parseString(req.body.logoutRequest, callback);
        },function(json, callback){
            var ticket = _.get(json, 'samlp:LogoutRequest.samlp:SessionIndex.0');
            if(ticket == null){
                callback("Failed to get session ticket.");
            }
            callback(null, ticket);
        }], function(err, ticket){
            if(err){
            }
            var session = sessionStore[ticket];
            var sessionID = session.meta.uuid;
            var uid = session.passport.user;
            delete sessionStore[ticket];
            session.destroy(function(){
                User.auth.revokeSession(sessionID, uid);
                // res.redirect(nconf.get('relative_path') + '/');
            })
        });
    });

    router.get('/api/cas/login', function(req, res, next){
        req.body.username = req.query.ticket;
        req.body.password = "test";
        next();
        }, 
        hostControllers.authentication.login
    );
    callback();
};

plugin.login = function() {
	passport.use(new passportLocal({passReqToCallback: true}, plugin.continueLogin));
};

plugin.continueLogin = function(req, username, password, next) {
    var ST = username;
    async.waterfall([
        function(callback){
            request({
                uri: `${CASServerPrefix}/p3/serviceValidate?ticket=${ST}&service=${nodeBBUrl}`,
                method: "GET"
            }, function(err, response, body){
                xml2js.parseString(body, callback);
            })
        },
        function(json, callback){
            var attributes = _.get(json, 'cas:serviceResponse.cas:authenticationSuccess.0.cas:attributes.0');
            if (!attributes) {
                return callback(new Error("[[auth failed]]"));
            }
            var keys = Object.keys(attributes);
            var userInfo = {};
            keys.forEach(key => {
                userInfo[key] = attributes[key][0]
            });
            var payload = {};
            payload.username = userInfo['cas:username'];
            payload.realname = userInfo['cas:realname'];
            payload.usertype = userInfo['cas:usertype'];
            if(Utils.isEmailValid(userInfo['cas:email'])){
                payload.email = userInfo['cas:email'];
            }
            callback(null, payload);
        },
        function(payload, callback){
            db.getObjectField('cas_username:uid', payload.username, function (err, uid) {
                if (err) {
                    return callback(err);
                }
                if (uid !== null) {
                    return callback(null, uid);
                } else {

                    var success = function (uid) {
                        // Save provider-specific information to the user
                        User.setUserField(uid, 'cas_username', payload.username);
                        db.setObjectField('cas_username:uid', payload.username, uid);
                        
                        if (payload.usertype && payload.usertype == 1) {
                            Groups.join('administrators', uid, function (err) {
                                callback(err, uid);
                            });
                        } else {
                            callback(null, uid);
                        }
                    };
    
                    User.getUidByUsername(payload.realname, function (err, uid) {
                        if (err) {
                            return callback(err);
                        }
    
                        if (!uid) {
                            User.create({
                                username: payload.realname,
                                email: payload.email,
                            }, function (err, uid) {
                                if (err) {
                                    return callback(err);
                                }
                                success(uid);
                            });
                        } else {
                            success(uid); // Existing account -- merge
                        }
                    });
                }
            });
        }
    ], function(err, uid){
        if (err) {
            next(new Error('[[error:invalid-username-or-password]]'));
        } else {
            next(null, {uid: uid}, '[[success:authentication-successful]]');
        }
    })
};

plugin.appendConfig = function (config, callback) {
    config['CASServerPrefix'] = CASServerPrefix;
	setImmediate(callback, null, config);
};



module.exports = plugin;