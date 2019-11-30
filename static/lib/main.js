"use strict";

$(document).ready(function () {

    $(window).on('action:app.loggedOut', function(event, data) {
        var service = window.location.href;
        var url = `${config.CASServerPrefix}/logout?service=${service}`;
        console.log(`[action:app.loggedOut] data.next=${url}`);
        data.next = url;
    });

    if ('/cas/login' == location.pathname) {
        app.flags = app.flags || {};
        app.flags._sessionRefresh = true;
        $.get('/api/cas/login?ticket=' + getParameterByName('ticket'))
            .done(function (data) {
                app.flags._sessionRefresh = false;
                app.updateHeader(data, function () {
                    ajaxify.go(data.next);
                });
            })
            .fail(function (err) {
                console.log(err);
            });
    }
    
    function getParameterByName(name, url) {
        if (!url) url = window.location.href;
        name = name.replace(/[\[\]]/g, "\\$&");
        var regex = new RegExp("[?&]" + name + "(=([^&#]*)|&|#|$)"),
            results = regex.exec(url);
        if (!results) return null;
        if (!results[2]) return '';
        return decodeURIComponent(results[2].replace(/\+/g, " "));
    }
}); 